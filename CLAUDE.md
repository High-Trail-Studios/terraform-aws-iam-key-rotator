# iam-key-rotator

Rotates AWS IAM access keys on a schedule.

<!-- Scaffold. Org philosophy loads automatically from the parent directory and
     is not repeated here. Fill in Stack and Commands once code exists. -->

## Design constraints

- **IAM allows a maximum of 2 access keys per user.** This is the hard limit the
  whole design turns on: rotation means create-second → verify → deactivate-old
  → delete-old. There is no room for a third key, so a failed rotation that
  leaves two keys behind blocks the next run. Handle that case explicitly.
- **Deactivate before delete, always.** Deactivation is reversible and gives a
  rollback window; deletion is not. Never collapse the two steps.
- **Never delete a key this tool did not verify a replacement for.** Deleting
  the working key before the new one is confirmed good is the failure mode that
  locks someone out of their own account.
- The tool needs `iam:ListUsers`, `iam:ListUserTags`, `iam:ListAccessKeys`,
  `iam:GetAccessKeyLastUsed`, `iam:CreateAccessKey`, `iam:UpdateAccessKey`,
  `iam:DeleteAccessKey`. Mutations are limited by IAM condition to users tagged
  `<tag_key> = enabled`. State the policy in the README.

## Decisions (2026-09-30)

- **Opt-in only, via IAM user tags.** `key-rotator = enabled | skip`, plus
  `key-rotator:reason`, `key-rotator:skip-until`, `key-rotator:ssm-path`. No
  config table. Untagged users are never touched, and IAM enforces it.
- **Old key still in use at deactivation time: hold and alert.** Never deactivate
  a key used within `in_use_window_days`. No per-user "strict" override in v1.
- **`mode = "report"` by default**, not first-run detection.
- **Alerts go to an SNS topic ARN** (compose with sns-relay); no Slack URL in
  Terraform.
- Thresholds 65/75/85 are earliest triggers; minimum waits (10d/10d) between
  steps keep a rollback window for overdue keys.
- DynamoDB is working state, not an audit log; CloudTrail is the audit trail.

## Out of scope (v1)

- Distributing the new key to whatever consumes it. That is the hard,
  environment-specific half of rotation and belongs behind a clean seam, not
  baked in. Document the seam; don't build every destination.

## Stack

Mirrors terraform-aws-sns-alert: Terraform module at the repo root (AWS provider
6.x), Lambda in Python 3.14 on arm64, standard library only. `src/rotator/policy.py`
is the pure decision function; `handler.py` carries out at most one step per user
per run.

## Commands

- Tests: `python3 -m unittest discover -s tests`
- Format: `terraform fmt -check -recursive`
- Validate: `terraform init -backend=false && terraform validate`
- Locally `terraform` may be OpenTofu.

## Not done yet

README, `examples/basic` (wired to sns-relay), `tests/module.tftest.hcl`, CI
workflows, `docs/ci.md`. Not yet applied against real AWS.
