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
- The tool needs `iam:ListAccessKeys`, `iam:CreateAccessKey`,
  `iam:UpdateAccessKey`, `iam:DeleteAccessKey`. Scope to the target users, not
  `iam:*`. State the policy in the README.

## Out of scope (v1)

- Distributing the new key to whatever consumes it. That is the hard,
  environment-specific half of rotation and belongs behind a clean seam, not
  baked in. Document the seam; don't build every destination.

## Stack

TBD — no code yet.

## Commands

TBD — no build, test, or deploy commands yet.
