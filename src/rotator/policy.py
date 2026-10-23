"""The rotation decision, as a pure function of what IAM and the state table say.

Nothing here calls AWS. Every run asks, per user, "what is the one next step?"
and the handler carries out at most that step. One step per user per run keeps
each change small, and the minimum waits between steps guarantee a rollback
window even when a key is already overdue on the first enforcing run.

The safety rules this module enforces:
  - Two keys with no rotation record: alert and touch neither.
  - Deactivate the old key only once the replacement is verified and published,
    the thresholds are met, and the old key has been idle for a while.
  - Delete only a key this tool deactivated itself, after a second wait.
  - A key re-enabled by a human is a rollback: never delete it.
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta

ACTIVE = "Active"
INACTIVE = "Inactive"

TAG_ENABLED = "enabled"
TAG_SKIP = "skip"

# SSM parameter names allow only these characters. IAM user names also allow
# "+=,@", so such users need an explicit parameter path tag.
_SSM_PATH = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")


class Phase(enum.StrEnum):
    CREATING = "creating"  # state written; replacement may not exist or be published yet
    CREATED = "created"  # replacement verified and published; old key still active
    DEACTIVATED = "deactivated"  # old key deactivated by this tool


class Action(enum.StrEnum):
    NONE = "none"
    CREATE = "create"  # create, verify and publish a replacement
    RECREATE = "recreate"  # replace a key an interrupted run created but never published
    DEACTIVATE = "deactivate"  # deactivate the old key
    DELETE = "delete"  # delete the old key this tool deactivated
    REOPEN = "reopen"  # old key was re-enabled: go back to waiting for it to go idle
    FORGET = "forget"  # drop the rotation record; never touches a key


# Actions that change IAM or SSM. These are skipped in report mode and count
# towards max_actions_per_run. REOPEN and FORGET only change the state table.
MUTATING = frozenset({Action.CREATE, Action.RECREATE, Action.DEACTIVATE, Action.DELETE})


class Level(enum.StrEnum):
    OK = "ok"
    INFO = "info"
    WARN = "warn"


@dataclass(frozen=True)
class AccessKey:
    key_id: str
    status: str
    created: datetime
    last_used: datetime | None = None


@dataclass(frozen=True)
class Rotation:
    phase: Phase
    old_key_id: str
    started_at: datetime
    parameter: str
    new_key_id: str | None = None
    deactivated_at: datetime | None = None


@dataclass(frozen=True)
class Thresholds:
    create_after_days: int = 65
    deactivate_after_days: int = 75
    delete_after_days: int = 85
    min_days_before_deactivate: int = 10
    min_days_before_delete: int = 10
    in_use_window_days: int = 7


@dataclass(frozen=True)
class Decision:
    action: Action
    level: Level
    message: str


def decide(
    keys: list[AccessKey],
    rotation: Rotation | None,
    t: Thresholds,
    now: datetime,
) -> Decision:
    if rotation is None:
        return _decide_idle(keys, t, now)

    by_id = {k.key_id: k for k in keys}
    old = by_id.get(rotation.old_key_id)
    new = by_id.get(rotation.new_key_id) if rotation.new_key_id else None

    unknown = [k.key_id for k in keys if k.key_id not in (rotation.old_key_id, rotation.new_key_id)]
    if unknown:
        return _warn(
            f"key {unknown[0]} is not part of the rotation of {rotation.old_key_id} in progress; "
            "holding. Remove the extra key, or delete this user's item in the state table to "
            "start over."
        )

    if rotation.phase == Phase.CREATING:
        if old is None:
            return Decision(
                Action.FORGET,
                Level.WARN,
                f"old key {rotation.old_key_id} was removed before its replacement was published; "
                "clearing the rotation record",
            )
        if rotation.new_key_id is None:
            return Decision(Action.CREATE, Level.INFO, "resuming an interrupted rotation: creating the replacement")
        if new is None:
            return Decision(
                Action.FORGET,
                Level.WARN,
                f"replacement key {rotation.new_key_id} disappeared before it was published; "
                "clearing the rotation record",
            )
        # IAM returns a secret only at creation, so an unpublished key is useless.
        # Nothing can depend on it, which makes discarding it safe.
        return Decision(
            Action.RECREATE,
            Level.INFO,
            f"resuming an interrupted rotation: {new.key_id} was never published; replacing it",
        )

    if new is None:
        return Decision(
            Action.FORGET,
            Level.WARN,
            f"replacement key {rotation.new_key_id} no longer exists; clearing the rotation record "
            f"without touching {rotation.old_key_id}. Consumers reading {rotation.parameter} now "
            "hold a dead key.",
        )
    if old is None:
        return Decision(Action.FORGET, Level.INFO, f"old key {rotation.old_key_id} is gone; rotation complete")
    if new.status != ACTIVE:
        return _warn(f"replacement key {new.key_id} is inactive; holding with {old.key_id} untouched")

    old_age = (now - old.created).days

    if rotation.phase == Phase.CREATED:
        if old.status != ACTIVE:
            return _warn(
                f"old key {old.key_id} was deactivated outside this tool. The tool only deletes keys it "
                "deactivated itself: reactivate it to let the rotation continue, or delete it yourself."
            )
        waited = (now - rotation.started_at).days
        if old_age < t.deactivate_after_days or waited < t.min_days_before_deactivate:
            due = max(t.deactivate_after_days - old_age, t.min_days_before_deactivate - waited)
            return Decision(
                Action.NONE,
                Level.OK,
                f"replacement {new.key_id} published {waited}d ago; {old.key_id} ({old_age}d) "
                f"is deactivated in {due}d",
            )
        if old.last_used and now - old.last_used < timedelta(days=t.in_use_window_days):
            return _warn(
                f"old key {old.key_id} ({old_age}d) was last used {old.last_used:%Y-%m-%d %H:%M} UTC; "
                f"holding deactivation until it has been idle for {t.in_use_window_days} days. "
                f"Point every consumer at {rotation.parameter}."
            )
        return Decision(
            Action.DEACTIVATE,
            Level.INFO,
            f"deactivating {old.key_id} ({old_age}d, last used {_when(old.last_used)}); "
            f"{new.key_id} replaces it",
        )

    # Phase.DEACTIVATED
    if old.status == ACTIVE:
        return Decision(
            Action.REOPEN,
            Level.WARN,
            f"old key {old.key_id} was re-enabled outside this tool; treating it as a rollback. It is "
            f"deactivated again once idle for {t.in_use_window_days} days and is never deleted while active.",
        )
    since = (now - rotation.deactivated_at).days if rotation.deactivated_at else 0
    if old_age < t.delete_after_days or since < t.min_days_before_delete:
        due = max(t.delete_after_days - old_age, t.min_days_before_delete - since)
        return Decision(
            Action.NONE,
            Level.OK,
            f"{old.key_id} ({old_age}d) deactivated {since}d ago; deleted in {due}d. "
            "Reactivate it to roll back.",
        )
    return Decision(Action.DELETE, Level.INFO, f"deleting {old.key_id} ({old_age}d), deactivated {since}d ago")


def _decide_idle(keys: list[AccessKey], t: Thresholds, now: datetime) -> Decision:
    if not keys:
        return Decision(Action.NONE, Level.OK, "no access keys")
    if len(keys) > 1:
        ages = ", ".join(f"{k.key_id} {k.status.lower()} {(now - k.created).days}d" for k in keys)
        return _warn(
            f"two access keys ({ages}) and no rotation in progress; the tool will not touch either. "
            "Delete the one you no longer need and the next run takes over."
        )
    key = keys[0]
    age = (now - key.created).days
    if key.status != ACTIVE:
        return _warn(f"the only key, {key.key_id} ({age}d), is inactive; delete it yourself if it is not needed")
    if age >= t.create_after_days:
        return Decision(Action.CREATE, Level.INFO, f"{key.key_id} is {age}d old; creating its replacement")
    return Decision(Action.NONE, Level.OK, f"{key.key_id} is {age}d old")


def review_exclusion(
    tags: Mapping[str, str],
    tag_key: str,
    keys: list[AccessKey],
    now: datetime,
) -> Decision:
    """A user tagged `skip`: never acted on, but always accounted for.

    Exclusions without a reason or an expiry tend to outlive the reason they
    were granted, so either missing is a warning.
    """
    active = [k for k in keys if k.status == ACTIVE]
    oldest = max(((now - k.created).days for k in active), default=None)
    summary = f"oldest active key {oldest}d" if oldest is not None else "no active keys"

    reason = tags.get(f"{tag_key}:reason", "").strip()
    until_raw = tags.get(f"{tag_key}:skip-until", "").strip()
    problems = []
    if not reason:
        problems.append(f"no {tag_key}:reason tag")
    if not until_raw:
        problems.append(f"no {tag_key}:skip-until tag")
    else:
        try:
            until = date.fromisoformat(until_raw)
        except ValueError:
            problems.append(f"{tag_key}:skip-until {until_raw!r} is not a YYYY-MM-DD date")
        else:
            if until < now.date():
                problems.append(f"exclusion expired {until_raw}")

    detail = f"excluded ({summary}); reason: {reason or 'none'}; until: {until_raw or 'none'}"
    if problems:
        return _warn(f"{detail}. " + "; ".join(problems).capitalize())
    return Decision(Action.NONE, Level.OK, detail)


def parameter_name(ssm_prefix: str, user_name: str, override: str | None) -> str | None:
    """Where a user's key is published. Always under ssm_prefix; None if invalid.

    The prefix is fixed so whoever can tag a user cannot redirect a fresh
    credential somewhere they can read. The IAM policy enforces the same.
    """
    relative = (override or user_name).strip().strip("/")
    if not _SSM_PATH.match(relative) or any(part == ".." for part in relative.split("/")):
        return None
    return f"{ssm_prefix}/{relative}"


def _warn(message: str) -> Decision:
    return Decision(Action.NONE, Level.WARN, message)


def _when(moment: datetime | None) -> str:
    return f"{moment:%Y-%m-%d}" if moment else "never"
