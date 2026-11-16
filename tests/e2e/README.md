# End-to-end test

This test runs the rotator against real AWS with one throwaway IAM user, from
creating the new key through deactivating and deleting the old one, including a
rollback. **Use a sandbox account.**

The configuration is isolated from anything else in the account. It has its
own name (`iam-key-rotator-e2e`), its own tag key (`key-rotator-e2e`), its own
SSM prefix and its own IAM path. The rotator's role can only change keys for
users under `/iam-key-rotator-e2e/` that carry that tag, and the only such user
is `rotation-test`.

The thresholds are as short as the code allows. It counts in whole days, so
each step needs **at least 24 hours** after the one before it. A full run takes
three days, plus one more if you test the rollback.

You need the AWS CLI, `jq`, and Terraform ≥ 1.7 or OpenTofu. Your credentials
must be able to manage IAM, Lambda, DynamoDB, SSM, SNS, EventBridge,
CloudWatch and S3 in the sandbox.

Cost: about $0.20 a month for the two alarms, prorated over a few days.
Everything else stays within the free tier.

## Setup

```sh
cd tests/e2e
terraform init
terraform apply -var alert_email=you@example.com   # leave alert_email out to read the logs instead
```

Confirm the subscription email if you set an address. Then give the test user
its first key, **key A**, and store it as a CLI profile:

```sh
KEY=$(aws iam create-access-key --user-name rotation-test --query AccessKey --output json)
aws configure set aws_access_key_id     "$(jq -r .AccessKeyId     <<<"$KEY")" --profile rotation-test
aws configure set aws_secret_access_key "$(jq -r .SecretAccessKey <<<"$KEY")" --profile rotation-test
unset KEY
```

Helpers used below. Set these in each new shell:

```sh
FN=iam-key-rotator-e2e
run()  { aws lambda invoke --function-name "$FN" /dev/stdout >/dev/null; aws logs tail "/aws/lambda/$FN" --since 5m --format short | grep -v -e START -e END -e REPORT; }
keys() { aws iam list-access-keys --user-name rotation-test --query 'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]' --output table; }
state(){ aws dynamodb scan --table-name "$FN-state" --query Items --output json; }
```

## Day 0: report mode, key too new

```sh
run
```

Expect: `rotation-test`, `AKIA... is 0d old`, and `Checked 1 user(s)`. No email,
because quiet runs aren't sent.

**Optional checks before day 1:**
- **Two keys:** run `aws iam create-access-key --user-name rotation-test`
  again, then `run`. Expect the warning `two access keys ... the tool will not
  touch either`. Delete that second key (`aws iam delete-access-key`) before
  you go on.
- **Bad tag value:** run `aws iam tag-user --user-name rotation-test --tags Key=key-rotator-e2e,Value=yes`,
  then `run`. Expect `unknown key-rotator-e2e tag value 'yes'`. Set the value
  back to `enabled`.

## Day 1: create key B

At least 24 hours after creating key A:

```sh
run                                  # report mode: "WOULD: AKIA... is 1d old; creating its replacement"
terraform apply -var mode=enforce    # keep -var alert_email=... if you set it
run                                  # "AKIA... is 1d old; creating its replacement"
keys                                 # two keys, both Active
state                                # one item, phase "created"
```

Check that the user can fetch its own new key **with key A**, which tests the
consumer pattern from the module README:

```sh
aws ssm get-parameter --with-decryption --profile rotation-test \
  --name /iam-key-rotator-e2e/rotation-test --query Parameter.Value --output text | jq .
```

Expect the user name and **key B's** ID. Using key A here counts as use, so
deactivation waits until key A has been idle for 24 hours. Now switch the
profile to key B:

```sh
NEW=$(aws ssm get-parameter --with-decryption --profile rotation-test \
  --name /iam-key-rotator-e2e/rotation-test --query Parameter.Value --output text)
aws configure set aws_access_key_id     "$(jq -r .AccessKeyId     <<<"$NEW")" --profile rotation-test
aws configure set aws_secret_access_key "$(jq -r .SecretAccessKey <<<"$NEW")" --profile rotation-test
unset NEW
aws sts get-caller-identity --profile rotation-test    # .../iam-key-rotator-e2e/rotation-test
```

**Optional in-use check:** within 24 hours before the day-2 run, make one call
with key A. Then `run` should warn `old key ... was last used ...; holding
deactivation`. IAM records last use with a delay, so this check may not trigger
straight away.

## Day 2: deactivate key A, then roll back

At least 24 hours after day 1, with key A unused since the fetch above:

```sh
run      # "deactivating AKIA...A (2d, last used ...); AKIA...B replaces it"
keys     # A Inactive, B Active
state    # phase "deactivated"
```

Roll back by reactivating key A, the same way you would if a consumer broke:

```sh
aws iam update-access-key --user-name rotation-test --access-key-id <key A> --status Active
run      # "was re-enabled outside this tool; treating it as a rollback"
state    # phase back to "created"
run      # key A is still idle, so: "deactivating AKIA...A"
```

Re-deactivation restarts the rollback window, so key A is deleted no earlier
than 24 hours after this.

## Day 3: delete key A

At least 24 hours after the last deactivation:

```sh
run      # "deleting AKIA...A (3d), deactivated 1d ago"
keys     # only B, Active
state    # []  (rotation complete, no state left)
```

That completes the test. Key B is already old enough under these thresholds,
so the next run in enforce mode starts a new rotation. Re-apply with
`-var mode=report` or tear down now.

The daily 06:00 UTC run also fires in enforce mode. If it runs before you do,
it takes the step for you. That is fine: check the digest or the logs.

## Alarms

`iam-key-rotator-e2e-missed-run` should stay `OK` while the schedule runs, and
`iam-key-rotator-e2e-errors` should stay `OK` throughout.

If you set `alert_email`, check that alarm notifications reach you by forcing
each alarm into the alarm state. It goes back to `OK` at the next evaluation:

```sh
for a in errors missed-run; do
  aws cloudwatch set-alarm-state --alarm-name "iam-key-rotator-e2e-$a" \
    --state-value ALARM --state-reason "e2e notification test"
done
```

This tests delivery, not detection. Detection uses the standard Lambda
`Errors` and `Invocations` metrics. A real run that fails is hard to set up
safely in a sandbox, and the unit tests cover the failure paths, such as a new
key that doesn't verify being removed again.

## Teardown

```sh
terraform destroy    # pass the same -var flags you applied with
aws ssm delete-parameter --name /iam-key-rotator-e2e/rotation-test
```

`force_destroy` on the test user deletes whatever keys it still has. After
destroy, confirm that nothing is left:

```sh
aws ssm get-parameters-by-path --path /iam-key-rotator-e2e --recursive --query 'Parameters[].Name'   # []
aws iam list-users --path-prefix /iam-key-rotator-e2e/ --query 'Users[].UserName'                   # []
aws logs describe-log-groups --log-group-name-prefix /aws/lambda/iam-key-rotator-e2e --query 'logGroups[].logGroupName'   # []
```

Also remove the `[rotation-test]` section from `~/.aws/credentials`.

## What to record

Note anything that surprised you: wrong or unclear digest wording, a step that
didn't happen when expected, a permission error, or anything left behind after
destroy. Those become fixes before `v0.1.0` is tagged.
