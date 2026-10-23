# One item per user with a rotation in progress; the item is removed when the
# rotation completes. It is working state, not an audit log: CloudTrail records
# every IAM call the rotator makes.
#
# Destroying the module deletes this table. A rotation in flight at that moment
# is then seen as "two keys, no rotation in progress" if the module is applied
# again, which the rotator reports and refuses to touch.

resource "aws_dynamodb_table" "state" {
  name         = "${var.name_prefix}-state"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "user_name"

  attribute {
    name = "user_name"
    type = "S"
  }

  # Encrypted at rest with the AWS-owned key (the default): no KMS charge. The
  # table holds key IDs and timestamps, never secrets.

  tags = var.tags
}
