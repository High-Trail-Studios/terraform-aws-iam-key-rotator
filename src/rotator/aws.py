"""Thin wrappers over the AWS APIs the rotator calls.

Each takes its boto3 client as an argument so tests can pass a fake. Nothing
here decides anything; see policy.py for that.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from rotator.policy import AccessKey, Phase, Rotation


class KeyNotVerified(Exception):
    """A freshly created key could not authenticate as its user."""


class Iam:
    def __init__(self, client: Any) -> None:
        self._client = client

    def users(self, path_prefix: str) -> Iterator[str]:
        for page in self._client.get_paginator("list_users").paginate(PathPrefix=path_prefix):
            for user in page["Users"]:
                yield user["UserName"]

    def tags(self, user: str) -> dict[str, str]:
        tags: dict[str, str] = {}
        for page in self._client.get_paginator("list_user_tags").paginate(UserName=user):
            tags.update({t["Key"]: t["Value"] for t in page["Tags"]})
        return tags

    def keys(self, user: str, last_used: bool = False) -> list[AccessKey]:
        # IAM allows at most two keys per user, so one page is always enough.
        metadata = self._client.list_access_keys(UserName=user)["AccessKeyMetadata"]
        keys = []
        for k in sorted(metadata, key=lambda k: k["CreateDate"]):
            used = None
            if last_used:
                info = self._client.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])
                used = info.get("AccessKeyLastUsed", {}).get("LastUsedDate")
            keys.append(AccessKey(k["AccessKeyId"], k["Status"], k["CreateDate"], used))
        return keys

    def create_key(self, user: str) -> tuple[str, str]:
        key = self._client.create_access_key(UserName=user)["AccessKey"]
        return key["AccessKeyId"], key["SecretAccessKey"]

    def deactivate(self, user: str, key_id: str) -> None:
        self._client.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")

    def delete(self, user: str, key_id: str) -> None:
        self._client.delete_access_key(UserName=user, AccessKeyId=key_id)


class StateTable:
    """One item per user with a rotation in progress. Mutable, so not an audit
    log: CloudTrail records every IAM call this tool makes."""

    def __init__(self, client: Any, table: str) -> None:
        self._client = client
        self._table = table

    def get(self, user: str) -> Rotation | None:
        item = self._client.get_item(
            TableName=self._table, Key={"user_name": {"S": user}}, ConsistentRead=True
        ).get("Item")
        if not item:
            return None

        def s(name: str) -> str | None:
            return item[name]["S"] if name in item else None

        def ts(name: str) -> datetime | None:
            raw = s(name)
            return datetime.fromisoformat(raw) if raw else None

        return Rotation(
            phase=Phase(s("phase")),
            old_key_id=s("old_key_id"),
            started_at=ts("started_at"),
            parameter=s("parameter"),
            new_key_id=s("new_key_id"),
            deactivated_at=ts("deactivated_at"),
        )

    def put(self, user: str, rotation: Rotation, new: bool = False) -> None:
        """`new` refuses to overwrite an existing record, so two overlapping
        runs can never both start a rotation for the same user."""
        item = {
            "user_name": {"S": user},
            "phase": {"S": str(rotation.phase)},
            "old_key_id": {"S": rotation.old_key_id},
            "started_at": {"S": rotation.started_at.isoformat()},
            "parameter": {"S": rotation.parameter},
        }
        if rotation.new_key_id:
            item["new_key_id"] = {"S": rotation.new_key_id}
        if rotation.deactivated_at:
            item["deactivated_at"] = {"S": rotation.deactivated_at.isoformat()}
        condition = {"ConditionExpression": "attribute_not_exists(user_name)"} if new else {}
        self._client.put_item(TableName=self._table, Item=item, **condition)

    def delete(self, user: str) -> None:
        self._client.delete_item(TableName=self._table, Key={"user_name": {"S": user}})


class Publisher:
    """Writes a key pair to SSM as one SecureString, so consumers never read a
    mismatched ID and secret."""

    def __init__(self, client: Any, kms_key_id: str | None = None) -> None:
        self._client = client
        self._kms_key_id = kms_key_id

    def put(self, name: str, user: str, key_id: str, secret: str) -> None:
        args = {
            "Name": name,
            "Type": "SecureString",
            "Tier": "Standard",
            "Overwrite": True,
            "Description": f"Access key for IAM user {user}, managed by iam-key-rotator",
            "Value": json.dumps({"UserName": user, "AccessKeyId": key_id, "SecretAccessKey": secret}),
        }
        if self._kms_key_id:
            args["KeyId"] = self._kms_key_id
        self._client.put_parameter(**args)


def verify_key(
    user: str,
    key_id: str,
    secret: str,
    sts_factory: Callable[[str, str], Any],
    sleep: Callable[[float], None] = time.sleep,
    delays: tuple[float, ...] = (2, 4, 8, 16),
) -> None:
    """Prove the new key authenticates as `user`. New IAM keys take a few
    seconds to propagate, so early failures are retried."""
    last_error: Exception | None = None
    for delay in (0, *delays):
        if delay:
            sleep(delay)
        try:
            arn = sts_factory(key_id, secret).get_caller_identity()["Arn"]
        except Exception as e:  # propagation shows up as InvalidClientTokenId
            last_error = e
            continue
        if arn.endswith(f"/{user}") and ":user/" in arn:
            return
        raise KeyNotVerified(f"key {key_id} authenticated as {arn}, not user {user}")
    raise KeyNotVerified(f"key {key_id} did not authenticate: {type(last_error).__name__}")


class Notifier:
    # SNS rejects subjects over 100 characters and messages over 256 KB.
    MAX_SUBJECT = 100
    MAX_MESSAGE = 200_000

    def __init__(self, client: Any, topic_arn: str) -> None:
        self._client = client
        self._topic_arn = topic_arn

    def publish(self, subject: str, message: str) -> None:
        if len(message) > self.MAX_MESSAGE:
            message = message[: self.MAX_MESSAGE] + "\n... truncated; see the Lambda logs for the full report"
        self._client.publish(TopicArn=self._topic_arn, Subject=subject[: self.MAX_SUBJECT], Message=message)


def utcnow() -> datetime:
    return datetime.now(UTC)
