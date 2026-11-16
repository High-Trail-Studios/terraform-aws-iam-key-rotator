# iam-key-rotator

A small Terraform module that rotates IAM user access keys on a schedule. It
uses one Lambda and works safely within IAM's two-key limit: it creates the
replacement, verifies it, publishes it, deactivates the old key and only then
deletes it. Every step waits long enough that you can still roll back.

```
EventBridge (daily) ─► rotator Lambda ─► for each IAM user tagged key-rotator=enabled:
                             │              one next step: create │ deactivate │ delete │ wait
                             │
                             ├─► new key ─► SSM SecureString <ssm_prefix>/<user>  ◄── your consumers read it here
                             ├─► rotations in progress ─► DynamoDB (working state only)
                             └─► per-run digest ─► SNS topic (optional, e.g. sns-relay)
```

Users opt in with a tag, so untagged users are never touched. **IAM enforces
this too:** the Lambda's role cannot create, change or delete keys for any user
without the tag. The module starts in **report mode**, which shows what it
would do and changes nothing until you switch it to enforce.

## Before you adopt this: do you need access keys at all?

Long-lived access keys are the legacy pattern. If a workload can use something
else, use that instead. It's better than rotating keys well:

- **Workloads on AWS** (EC2, ECS, Lambda, EKS): IAM roles.
- **CI/CD** (GitHub Actions, GitLab, CircleCI and others): OIDC federation to an
  IAM role.
- **On-premises servers:** IAM Roles Anywhere.
- **People:** IAM Identity Center with short-lived credentials.

This tool is for the keys you can't remove yet, such as a vendor appliance or a
third-party SaaS integration that only takes a key pair. It makes those keys
less dangerous. It does not make them good.

## Quick start

```hcl
module "iam_key_rotator" {
  source = "git::https://github.com/<org>/terraform-aws-iam-key-rotator.git?ref=v0.1.0"

  # Optional: where the per-run digest goes. Without it, the digest is only logged.
  alert_topic_arn = module.sns_relay.topic_arns["security"]

  # Optional: who is told when the rotator itself fails or stops running.
  alarm_actions = [module.sns_relay.topic_arns["ops"]]
}
```

```sh
terraform init
terraform plan      # review what will be created
terraform apply

# Opt a user in:
aws iam tag-user --user-name ci-deploy --tags Key=key-rotator,Value=enabled

# Get a report now instead of waiting for the 06:00 UTC run:
aws lambda invoke --function-name iam-key-rotator response.json && cat response.json
aws logs tail /aws/lambda/iam-key-rotator --since 10m
```

Read the report. When it says what you expect, **set up your consumers (see
[Consumers: the SSM seam](#consumers-the-ssm-seam)) and then** set
`mode = "enforce"`.

Requirements: Terraform ≥ 1.7 or OpenTofu, AWS provider 6.x, and a region where
the Lambda `python3.14` runtime is available on arm64. The Lambda uses only the
Python standard library plus the boto3 that the Lambda runtime provides, so
there is nothing to package.

## How a rotation works

Each run, the rotator works out the one next step for each opted-in user and
takes at most that step. One step per user per run keeps every change small. It
also means a rotation takes several runs, and that spacing is the safety margin.

With the default thresholds and a key created on day 0:

| Key age | Step | Conditions |
|---------|------|------------|
| day 65 | **Create** key B, prove it authenticates as the user (`sts:GetCallerIdentity`), write it to SSM | The user has exactly one key, and it is active |
| day 75+ | **Deactivate** key A | A is at least 75 days old, B was published at least 10 days ago, **and A has not been used for 7 days** |
| day 85+ | **Delete** key A | A is at least 85 days old and was deactivated at least 10 days ago |

A key that is **already overdue** when you first enforce isn't rushed. The
minimum waits still apply: the new key is created on day 0, the old key is
deactivated on day 10 at the earliest and deleted on day 20 at the earliest.

The rules the rotator never breaks:

- **Two keys and no rotation in progress: hands off.** It can't tell which key
  matters, so it reports and touches neither. Delete the one you don't need,
  and the next run takes over.
- **It never deactivates a key that is still in use.** If IAM's last-used date
  falls inside `in_use_window_days`, the rotator holds and warns every run until
  the key goes quiet. It holds indefinitely, even past 90 days.
- **It deactivates before it deletes, every time.** Between the two steps there
  are at least `min_days_before_delete` days in which **reactivating the old
  key rolls back the rotation.** The rotator treats a re-enabled key as a
  rollback. It never deletes a key while that key is active, and it deactivates
  it again only once it has been idle for `in_use_window_days`.
- **It deletes only keys it deactivated itself,** plus replacement keys it
  created that failed verification or publishing. Those were never handed to
  anyone. If someone deactivates the old key by hand, the rotator stops and
  asks you to finish the job.
- **A failed creation leaves the user as it was.** If the new key doesn't
  verify or can't be written to SSM, it is deleted again and the old key is
  untouched.
- **An interrupted run is resumed.** The state record is written before the
  key is created. If a run dies between creating a key and publishing it, the
  next run replaces that key. IAM returns a secret only once, so an unpublished
  key is useless to everyone and safe to discard.

### What "in use" can and can't see

The in-use check relies on IAM's `LastUsedDate` for the key, and that has
limits:

- **IAM updates it with a delay.** A key used in the last few hours may still
  look idle.
- **A consumer that runs less often than `in_use_window_days` looks idle.** For
  example, a monthly report job won't show up in a 7-day window, so its key is
  deactivated and the job fails on its next run. The rollback window catches
  this: reactivate the key and the rotation goes back to waiting. Better still,
  set `in_use_window_days` longer than your slowest consumer's interval before
  you enforce.

## Opting users in

Everything is controlled by tags on the IAM user. There is no config table.

| Tag | Value | Effect |
|-----|-------|--------|
| `key-rotator` | `enabled` | Rotated |
| `key-rotator` | `skip` | Never touched, but listed in every digest with its oldest key's age |
| `key-rotator:reason` | free text | Why the user is skipped. A skip without one is reported as a warning |
| `key-rotator:skip-until` | `YYYY-MM-DD` | When the skip should end. A missing or past date is reported as a warning |
| `key-rotator:ssm-path` | path | Publish under `<ssm_prefix>/<this>` instead of `<ssm_prefix>/<user name>` |
| *(no `key-rotator` tag)* | | Ignored. Only the count of such users appears in the digest |

The tag key is `tag_key` (default `key-rotator`).

`skip` is meant to be temporary and visible: a skipped user with no reason or
no expiry keeps showing up as a warning until someone fixes it. Users whose
names contain `+ = , @` aren't valid SSM paths, so they need the
`key-rotator:ssm-path` tag. The rotator warns and does nothing until it is set.

**Anyone who can tag IAM users can opt users in.** Granting `iam:TagUser` and
`iam:UntagUser` now also decides which users the rotator may rotate. Restrict
them as tightly as you restrict key management.

**Don't change the tag in the middle of a rotation.** Removing the tag drops
the user from the digest with both keys still in place. Switching it to `skip`
leaves both keys and the state record as they are. Let the rotation finish
first, or clean up by hand. See [Recovering by hand](#recovering-by-hand).

## Consumers: the SSM seam

Getting the new key to whatever uses it is the environment-specific half of
rotation, and **this module doesn't do it.** It publishes each new key in one
place, in one format, and stops there:

```
Parameter:  <ssm_prefix>/<user name>          e.g. /iam-key-rotator/ci-deploy
Type:       SecureString (Standard tier), in the module's region
Value:      {"UserName": "ci-deploy", "AccessKeyId": "AKIA...", "SecretAccessKey": "..."}
```

The key ID and the secret are stored in one value, so a consumer can never read
a mismatched pair.

**The simplest consumer is the user itself.** The old key keeps working for at
least `min_days_before_deactivate` days after the new one is published (10 by
default). That means a consumer can fetch its own replacement with the key it
already holds. Attach this to the user, or to a group of rotated users:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "ssm:GetParameter",
    "Resource": "arn:aws:ssm:<region>:<account-id>:parameter/iam-key-rotator/${aws:username}"
  }]
}
```

```sh
aws ssm get-parameter --with-decryption --name /iam-key-rotator/ci-deploy \
  --query Parameter.Value --output text
```

The consumer has to re-read the parameter well within that 10-day window: on
startup, on a timer, or when it gets an authentication error. If it doesn't,
the in-use check holds the rotation and warns you, which is safe but means the
key never rotates.

**For destinations that can't read SSM** (a SaaS integration's settings page, a
CI system's secret store), the seam is still the parameter. Parameter Store
sends an EventBridge event (`source: aws.ssm`,
`detail-type: Parameter Store Change`) whenever a parameter is created or
updated. Trigger your own small distributor from that event. It's the right
place for destination-specific code, and that code doesn't belong in the
rotator.

Caveats:

- **The parameter doesn't exist before the first rotation.** Consumers can
  start reading it once it appears. The in-use hold keeps the old key alive
  until they have switched. If you have the current secret, you can create the
  parameter yourself in the same JSON format beforehand, and the rotator will
  overwrite it.
- **Don't manage these parameters with Terraform** (`aws_ssm_parameter`). The
  rotator overwrites the value, and the next `terraform apply` would put the
  old key back.
- **Read access to a parameter is read access to that user's credentials.**
  Grant `ssm:GetParameter` per parameter, not on the whole prefix.

## Running more than one

IAM is global, so **run one rotator per account,** whatever region you deploy
it in. Two rotators with the same `tag_key` would both act on the same users.
Their state tables are separate, so neither knows about the other's rotations
in progress. That can't lock anyone out, because every safety rule still
applies, but you get stuck rotations and errors in both digests.

If you really need two, for example with different thresholds for different
teams, give them different `name_prefix`, `ssm_prefix` and `tag_key` values,
plus non-overlapping `user_path_prefix` values if you can.

## Alerts and the digest

After each run the rotator publishes one digest to `alert_topic_arn`, but
**only if something happened:** an action, a warning or an error. Quiet runs
are logged and not sent, so no message means nothing to do. Two CloudWatch
alarms make sure silence never hides a dead rotator:

| Alarm | Fires when |
|-------|-----------|
| `<name_prefix>-errors` | A run failed for at least one user in the last 24 hours. A failure for one user doesn't stop the others. The run finishes, then reports the failure, so the alarm can see it |
| `<name_prefix>-missed-run` | No run for `missed_run_alarm_hours` (default 26) |

Both notify `alarm_actions`. With no actions they still appear in the console,
but nobody is told. A failed run is **not retried.** The next scheduled run
picks up where it left off.

A digest in report mode looks like this:

```
Subject: [iam-key-rotator] report: 1 action(s), 1 warning(s), 0 error(s)

REPORT MODE: nothing was changed. Set mode = "enforce" to act on this.
Checked 4 user(s) tagged key-rotator; ignored 12 untagged user(s) under path /.

Actions
  ci-deploy: WOULD: AKIAIOSFODNN7EXAMPLE is 71d old; creating its replacement

Warnings
  backup-agent: two access keys (AKIAI44QH8DHBEXAMPLE active 400d, AKIAJ3EXAMPLE2EXAMPLE inactive 380d) and no rotation in progress; the tool will not touch either. Delete the one you no longer need and the next run takes over.

Excluded
  sftp-vendor: excluded (oldest active key 512d); reason: vendor appliance, rotated manually; until: 2027-03-31
```

Secrets never appear in the digest or the logs.

## IAM

The Lambda role can do exactly this:

| Permission | Resource | Why |
|------------|----------|-----|
| `iam:ListUsers` | `*` | Find users. This action doesn't support resource-level permissions |
| `iam:ListUserTags`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed` | users under `user_path_prefix` | Read the opt-in tags, the keys and their last use |
| `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:DeleteAccessKey` | users under `user_path_prefix`, **only if tagged `<tag_key> = enabled`** | Rotate |
| `ssm:PutParameter` | `<ssm_prefix>/*` | Publish new keys |
| `dynamodb:GetItem`, `PutItem`, `DeleteItem` | its own state table | Track rotations in progress |
| `logs:CreateLogStream`, `logs:PutLogEvents` | its own log group | Logging |
| `sns:Publish` (only if `alert_topic_arn` is set) | that topic | Send the digest |
| `kms:Encrypt`, `kms:GenerateDataKey` (only if `ssm_kms_key_arn` is set) | that key, via SSM only | Encrypt published keys |

Notes:

- **The opt-in is enforced by IAM, not just by the code.** The mutating
  statement has an `aws:ResourceTag/<tag_key> = enabled` condition. A bug in
  the rotator still can't touch an untagged user.
- **The rotator can't read SSM.** It writes new keys and never reads them back.
- **A tag can't redirect a key outside `ssm_prefix`.** The `ssm-path` tag is
  validated in code, and the IAM policy only allows writes under the prefix.
- **It can't touch root keys, roles or anything outside IAM users.**
- With a customer-managed KMS key, the key policy must allow the rotator's role
  (the `lambda_role_arn` output) to use it, and consumers need `kms:Decrypt`.

CloudTrail is the audit log. Every key the rotator creates, deactivates or
deletes is an IAM API call made by the `<name_prefix>-lambda` role. The
DynamoDB table holds only working state and is changed as rotations proceed.

## Cost

Nothing here bills by the hour. With daily runs and a handful of users, this
costs about $0.20 a month:

- **CloudWatch alarms:** 2 × about $0.10/month, the only fixed cost. Turn them
  off with `create_alarms = false` if you already monitor Lambda.
- **Lambda:** one invocation a day at 128 MB, well within the free tier. A run
  that creates keys lasts longer (see below), but it's still small.
- **DynamoDB:** on-demand, with one small item per user while a rotation is in
  progress. No provisioned capacity and no standing charge.
- **SSM Parameter Store:** Standard-tier SecureStrings and standard throughput
  are free. The default `aws/ssm` key is free. A customer-managed KMS key
  (`ssm_kms_key_arn`) costs about $1/month plus requests.
- **EventBridge schedule, STS:** free.
- **CloudWatch Logs:** a few lines per user per run, kept for
  `log_retention_days` (30 by default).
- **Code bucket:** one small object. Pass `code_bucket_name` to reuse a bucket
  you already have.

**Timeout to watch:** a new key can take up to about 30 seconds to verify while
IAM propagates it. With the defaults (`max_actions_per_run = 10`,
`lambda_timeout_seconds = 300`), a run that creates ten keys and hits slow
propagation every time could reach the timeout. That isn't dangerous, because
the next run resumes, but it costs a day and raises the errors alarm. If you
raise `max_actions_per_run`, allow about 30 seconds of timeout per creation.

## Teardown

`terraform destroy` removes everything the module created: the Lambda, its
role, the log group, the schedule, the alarms, the state table, and the code
bucket if the module created it.

It does **not** remove:

- **The SSM parameters the rotator wrote.** Terraform never created them, so it
  can't see them. **They contain live credentials.** Delete them yourself:

  ```sh
  aws ssm get-parameters-by-path --path /iam-key-rotator --recursive \
    --query 'Parameters[].Name' --output text \
    | xargs -n 10 aws ssm delete-parameters --names
  ```

- **Access keys.** They belong to your users, and the module leaves them alone.
- **The `key-rotator` tags** on your users.

**Check for rotations in progress first.** If you destroy while a user is
partway through a rotation, that user is left with two keys and no state
record. If you reapply later, the rotator reports that user and won't touch
them until you delete one of the keys yourself.

## Recovering by hand

| Situation | What to do |
|-----------|------------|
| A consumer broke after deactivation | Reactivate the old key (`aws iam update-access-key --status Active`). The rotation goes back to waiting, and the key won't be deleted while it is active. |
| Two keys, no rotation in progress | Decide which key is live and delete the other. The next run takes over. |
| A rotation is stuck or you want to start over | Get the user back to one key, then delete the user's item from `<name_prefix>-state` (keyed by `user_name`). |
| "Could not be removed" in an error | A replacement failed and its cleanup failed too. Delete the key the message names, then the user's state item. |

## What this does not do

- **It doesn't deliver keys to consumers.** See
  [Consumers: the SSM seam](#consumers-the-ssm-seam).
- **It only rotates opted-in users.** Untagged users, including ones with very
  old keys, appear in the digest only as a count. Finding stale keys across the
  account is the job of IAM credential reports, IAM Access Analyzer or Security
  Hub.
- **It doesn't remove unused keys or users,** and it doesn't issue a first key
  to a user that has none.
- **It doesn't handle root keys, console passwords, SSH keys,
  service-specific credentials or roles.**
- **It doesn't work across accounts.** Deploy it once in each account. Members
  of an AWS Organization each need their own deployment.
- **It doesn't keep keys in sync across regions.** Keys are published to SSM in
  the module's region only.
- **It doesn't pin boto3.** The Lambda uses the runtime's bundled boto3, which
  AWS updates on its own schedule. The rotator only calls stable IAM, STS, SSM,
  DynamoDB and SNS APIs, so this trades exact pinning for having no
  dependencies to package.

## Compliance

This module is **control-mapped, not "compliant."** It implements one technical
control, and compliance is a property of your organization, not of a tool.

| Control | How it maps | Out of scope |
|---------|-------------|--------------|
| CIS AWS Foundations Benchmark: access keys rotated every 90 days or less | Opted-in keys are replaced from day 65 and deleted from day 85 by default | Untagged and skipped users. Keys the in-use check holds past 90 days, which the digest warns about every day |
| AWS Security Hub `IAM.3`: access keys rotated every 90 days or less | Same | Same. Security Hub evaluates every user, so the ones this module doesn't rotate will still fail the check |

Evidence is in CloudTrail (the rotator's IAM calls) and in the digests.

## Inputs

| Variable | Default | Description |
|----------|---------|-------------|
| `mode` | `"report"` | `report` decides and reports. `enforce` creates, deactivates and deletes keys |
| `name_prefix` | `"iam-key-rotator"` | Names of the Lambda, role, table, rule, alarms and code bucket |
| `tag_key` | `"key-rotator"` | IAM user tag that opts users in |
| `user_path_prefix` | `"/"` | Only users under this IAM path are considered. It narrows both the listing and the IAM policy |
| `create_after_days` | `65` | Create the replacement at this key age |
| `deactivate_after_days` | `75` | Earliest key age at which the old key is deactivated |
| `delete_after_days` | `85` | Earliest key age at which the deactivated key is deleted |
| `min_days_before_deactivate` | `10` | Minimum days between publishing and deactivating, even for overdue keys |
| `min_days_before_delete` | `10` | Minimum days between deactivating and deleting: the rollback window |
| `in_use_window_days` | `7` | Deactivate only once the old key has been unused this long |
| `max_actions_per_run` | `10` | Cap on key changes per run. Users beyond it wait until the next run |
| `schedule` | `"cron(0 6 * * ? *)"` | EventBridge schedule. The thresholds assume roughly daily runs |
| `ssm_prefix` | `"/iam-key-rotator"` | Where new keys are published |
| `ssm_kms_key_arn` | `null` | Customer-managed KMS key for the parameters. `null` uses the free `aws/ssm` key |
| `alert_topic_arn` | `null` | SNS topic for the digest. `null` logs it only |
| `create_alarms` | `true` | Create the errors and missed-run alarms |
| `alarm_actions` | `[]` | ARNs notified when an alarm fires or recovers |
| `missed_run_alarm_hours` | `26` | Hours without a run before the missed-run alarm fires. Keep this longer than the schedule interval |
| `code_bucket_name` | `null` | Existing S3 bucket for the Lambda package. `null` creates a small one that is destroyed with the module |
| `code_key_prefix` | `""` | Key prefix inside the code bucket |
| `lambda_memory_mb` | `128` | Lambda memory |
| `lambda_timeout_seconds` | `300` | Lambda timeout. Allow about 30 seconds per key creation |
| `log_retention_days` | `30` | CloudWatch Logs retention |
| `tags` | `{}` | Tags for every taggable resource |

## Outputs

| Output | Description |
|--------|-------------|
| `lambda_function_name` | Invoke it by hand to get a report now |
| `lambda_role_arn` | For a KMS key policy |
| `state_table_name` | DynamoDB table holding rotations in progress |
| `ssm_prefix` | Where keys are published. Grant consumers access to their own parameter under it |
| `tag_key` | The opt-in tag |

## Development

```sh
python3 -m unittest discover -s tests     # unit tests, stdlib only, no AWS
terraform fmt -check -recursive
terraform init -backend=false && terraform validate
```

[examples/basic](examples/basic) wires the module to sns-relay for Slack
delivery. [tests/e2e](tests/e2e) is a three-day runbook and configuration for
testing against real AWS in a sandbox account with one throwaway user.

`src/rotator/policy.py` makes every decision as a pure function of the keys,
the state record and the clock. `handler.py` carries out the decisions, and
`aws.py` is a thin wrapper over the AWS APIs. Most behavior changes belong in
`policy.py`, and most tests target it.

## License

MIT. See [LICENSE](LICENSE).
