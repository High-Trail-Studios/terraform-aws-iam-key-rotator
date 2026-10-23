"""Non-secret configuration, read once from the Lambda environment."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from rotator.policy import Thresholds

MODES = ("report", "enforce")


@dataclass(frozen=True)
class Config:
    name: str
    mode: str
    tag_key: str
    user_path_prefix: str
    thresholds: Thresholds
    max_actions_per_run: int
    ssm_prefix: str
    state_table: str
    ssm_kms_key_id: str | None = None
    alert_topic_arn: str | None = None

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> Config:
        mode = env.get("ROTATOR_MODE", "report")
        if mode not in MODES:
            raise ValueError(f"ROTATOR_MODE must be one of {MODES}, got {mode!r}")

        return cls(
            name=env.get("ROTATOR_NAME", "iam-key-rotator"),
            mode=mode,
            tag_key=env["ROTATOR_TAG_KEY"],
            user_path_prefix=env.get("ROTATOR_USER_PATH_PREFIX", "/"),
            thresholds=Thresholds(
                create_after_days=int(env["ROTATOR_CREATE_AFTER_DAYS"]),
                deactivate_after_days=int(env["ROTATOR_DEACTIVATE_AFTER_DAYS"]),
                delete_after_days=int(env["ROTATOR_DELETE_AFTER_DAYS"]),
                min_days_before_deactivate=int(env["ROTATOR_MIN_DAYS_BEFORE_DEACTIVATE"]),
                min_days_before_delete=int(env["ROTATOR_MIN_DAYS_BEFORE_DELETE"]),
                in_use_window_days=int(env["ROTATOR_IN_USE_WINDOW_DAYS"]),
            ),
            max_actions_per_run=int(env["ROTATOR_MAX_ACTIONS_PER_RUN"]),
            ssm_prefix=env["ROTATOR_SSM_PREFIX"].rstrip("/"),
            state_table=env["ROTATOR_STATE_TABLE"],
            ssm_kms_key_id=env.get("ROTATOR_SSM_KMS_KEY_ID") or None,
            alert_topic_arn=env.get("ROTATOR_ALERT_TOPIC_ARN") or None,
        )
