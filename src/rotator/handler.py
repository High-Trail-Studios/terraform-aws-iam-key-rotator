"""Lambda entry point: one pass over every opted-in IAM user.

For each user the policy picks at most one next step. In report mode nothing
is changed and the digest says what would happen. Per-user failures don't stop
the run: they are reported, and the invocation fails at the end so the Errors
alarm sees them. Secrets are never logged.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from rotator.aws import Iam, Notifier, Publisher, StateTable, utcnow, verify_key
from rotator.config import Config
from rotator.policy import (
    MUTATING,
    TAG_ENABLED,
    TAG_SKIP,
    Action,
    Decision,
    Level,
    Phase,
    Rotation,
    decide,
    parameter_name,
    review_exclusion,
)

log = logging.getLogger("rotator")
log.setLevel(logging.INFO)


class RunFailed(Exception):
    """At least one user could not be processed. Details are in the digest."""


@dataclass(frozen=True)
class Outcome:
    user: str
    decision: Decision
    status: str  # "done", "would", "deferred", "idle", "excluded", "error"


@dataclass
class Report:
    config: Config
    outcomes: list[Outcome] = field(default_factory=list)
    ignored: int = 0

    def add(self, user: str, decision: Decision, status: str) -> None:
        outcome = Outcome(user, decision, status)
        self.outcomes.append(outcome)
        log.info(json.dumps({
            "user": user,
            "action": str(decision.action),
            "level": str(decision.level),
            "status": status,
            "message": decision.message,
        }))

    def _select(self, *statuses: str, level: Level | None = None) -> list[Outcome]:
        return [o for o in self.outcomes if o.status in statuses and (level is None or o.decision.level == level)]

    @property
    def actions(self) -> list[Outcome]:
        return self._select("done", "would", "deferred")

    @property
    def warnings(self) -> list[Outcome]:
        return self._select("idle", "excluded", level=Level.WARN) + [
            o for o in self.actions if o.decision.level == Level.WARN
        ]

    @property
    def errors(self) -> list[Outcome]:
        return self._select("error")

    @property
    def notable(self) -> bool:
        return bool(self.actions or self.warnings or self.errors)

    def subject(self) -> str:
        c = self.config
        return (
            f"[{c.name}] {c.mode}: {len(self.actions)} action(s), "
            f"{len(self.warnings)} warning(s), {len(self.errors)} error(s)"
        )

    def body(self) -> str:
        c = self.config
        lines = []
        if not c.enforce:
            lines.append('REPORT MODE: nothing was changed. Set mode = "enforce" to act on this.')
        managed = len(self.outcomes)
        lines.append(
            f"Checked {managed} user(s) tagged {c.tag_key}; ignored {self.ignored} untagged user(s) "
            f"under path {c.user_path_prefix}."
        )
        prefix = {"done": "", "would": "WOULD: ", "deferred": "DEFERRED (max_actions_per_run): "}
        sections = [
            ("Actions", [(o.user, prefix[o.status] + o.decision.message) for o in self.actions]),
            ("Warnings", [(o.user, o.decision.message) for o in self.warnings if o not in self.actions]),
            ("Errors", [(o.user, o.decision.message) for o in self.errors]),
            ("Excluded", [(o.user, o.decision.message) for o in self._select("excluded")]),
        ]
        for title, rows in sections:
            if rows:
                lines += ["", title] + [f"  {user}: {message}" for user, message in rows]
        return "\n".join(lines)


class Rotator:
    def __init__(
        self,
        config: Config,
        iam: Iam,
        state: StateTable,
        publisher: Publisher,
        sts_factory: Callable[[str, str], Any],
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.config = config
        self.iam = iam
        self.state = state
        self.publisher = publisher
        self.sts_factory = sts_factory
        self.clock = clock
        self.sleep = sleep

    def run(self) -> Report:
        report = Report(self.config)
        now = self.clock()
        budget = self.config.max_actions_per_run
        tag_key = self.config.tag_key

        for user in self.iam.users(self.config.user_path_prefix):
            try:
                tags = self.iam.tags(user)
                value = tags.get(tag_key)
                if value is None:
                    report.ignored += 1
                elif value == TAG_SKIP:
                    report.add(user, review_exclusion(tags, tag_key, self.iam.keys(user), now), "excluded")
                elif value == TAG_ENABLED:
                    decision = self._decide(user, tags, now)
                    if decision.action in MUTATING:
                        if not self.config.enforce:
                            report.add(user, decision, "would")
                        elif budget <= 0:
                            report.add(user, decision, "deferred")
                        else:
                            budget -= 1
                            self._apply(user, decision, now)
                            report.add(user, decision, "done")
                    elif decision.action != Action.NONE and self.config.enforce:
                        self._apply(user, decision, now)
                        report.add(user, decision, "done")
                    else:
                        report.add(user, decision, "idle")
                else:
                    report.add(
                        user,
                        Decision(Action.NONE, Level.WARN, f"unknown {tag_key} tag value {value!r}; "
                                 f"use {TAG_ENABLED!r} or {TAG_SKIP!r}"),
                        "idle",
                    )
            except Exception as e:
                log.exception("user %s failed", user)
                report.add(user, Decision(Action.NONE, Level.WARN, f"{type(e).__name__}: {e}"), "error")
        return report

    def _decide(self, user: str, tags: dict[str, str], now: datetime) -> Decision:
        rotation = self.state.get(user)
        decision = decide(self.iam.keys(user, last_used=True), rotation, self.config.thresholds, now)
        if decision.action == Action.CREATE and rotation is None and self._parameter(user, tags) is None:
            return Decision(
                Action.NONE,
                Level.WARN,
                f"{decision.message}, but the user name is not a valid SSM path. Set the "
                f"{self.config.tag_key}:ssm-path tag (letters, digits, _.-/).",
            )
        return decision

    def _parameter(self, user: str, tags: dict[str, str]) -> str | None:
        return parameter_name(self.config.ssm_prefix, user, tags.get(f"{self.config.tag_key}:ssm-path"))

    def _apply(self, user: str, decision: Decision, now: datetime) -> None:
        rotation = self.state.get(user)
        action = decision.action

        if action == Action.CREATE:
            if rotation is None:
                old = self.iam.keys(user)[0]
                rotation = Rotation(Phase.CREATING, old.key_id, now, self._parameter(user, self.iam.tags(user)))
                # Recorded before the key exists, so an interrupted run leaves a trace.
                self.state.put(user, rotation, new=True)
            self._create(user, rotation, now)
        elif action == Action.RECREATE:
            self._discard(user, rotation.new_key_id)
            rotation = replace(rotation, new_key_id=None)
            self.state.put(user, rotation)
            self._create(user, rotation, now)
        elif action == Action.DEACTIVATE:
            self.iam.deactivate(user, rotation.old_key_id)
            self.state.put(user, replace(rotation, phase=Phase.DEACTIVATED, deactivated_at=now))
        elif action == Action.DELETE:
            self.iam.delete(user, rotation.old_key_id)
            self.state.delete(user)
        elif action == Action.REOPEN:
            self.state.put(user, replace(rotation, phase=Phase.CREATED, deactivated_at=None))
        elif action == Action.FORGET:
            self.state.delete(user)

    def _create(self, user: str, rotation: Rotation, now: datetime) -> None:
        key_id, secret = self.iam.create_key(user)
        self.state.put(user, replace(rotation, new_key_id=key_id))
        try:
            verify_key(user, key_id, secret, self.sts_factory, sleep=self.sleep)
            self.publisher.put(rotation.parameter, user, key_id, secret)
        except Exception as e:
            # The key was never published, so nothing depends on it. Removing it
            # keeps the user at one key and the old key untouched.
            try:
                self._discard(user, key_id)
                self.state.delete(user)
            except Exception as cleanup:
                raise RuntimeError(
                    f"replacement {key_id} failed ({e}) and could not be removed ({cleanup}); "
                    f"delete it by hand, then delete this user's item in the state table"
                ) from e
            raise RuntimeError(f"replacement {key_id} failed and was removed; old key untouched: {e}") from e
        # The consumers' window to switch starts when the key is published.
        self.state.put(user, replace(rotation, phase=Phase.CREATED, new_key_id=key_id, started_at=now))

    def _discard(self, user: str, key_id: str) -> None:
        self.iam.deactivate(user, key_id)
        self.iam.delete(user, key_id)


# --- Lambda wiring ----------------------------------------------------------

_config: Config | None = None


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    import boto3  # provided by the Lambda runtime

    global _config
    if _config is None:
        _config = Config.from_env()
    config = _config
    region = os.environ.get("AWS_REGION")

    def sts_factory(key_id: str, secret: str) -> Any:
        # Explicit keys only: the Lambda's own session token must not be mixed in.
        return boto3.client(
            "sts", region_name=region, aws_access_key_id=key_id, aws_secret_access_key=secret
        )

    rotator = Rotator(
        config,
        Iam(boto3.client("iam")),
        StateTable(boto3.client("dynamodb"), config.state_table),
        Publisher(boto3.client("ssm"), config.ssm_kms_key_id),
        sts_factory,
    )
    report = rotator.run()
    publish(report, boto3.client("sns") if config.alert_topic_arn else None)
    log.info("%s", report.subject())

    if report.errors:
        raise RunFailed(f"{len(report.errors)} user(s) failed; see the digest or the logs above")
    return {
        "mode": config.mode,
        "actions": len(report.actions),
        "warnings": len(report.warnings),
        "errors": 0,
    }


def publish(report: Report, sns_client: Any) -> None:
    body = report.body()
    if sns_client is None or not report.notable:
        log.info("%s", body)
        return
    Notifier(sns_client, report.config.alert_topic_arn).publish(report.subject(), body)
