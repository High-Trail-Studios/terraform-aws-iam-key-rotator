# End-to-end test against real AWS. Use a sandbox account. See README.md here.
#
# Everything is isolated from any real rotator in the same account: its own
# name, tag key, SSM prefix and IAM path, so its role can only ever touch the
# one throwaway user below. Thresholds are cut to the minimum the code allows
# (whole days), so a full create -> deactivate -> delete takes three days.

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "region" {
  description = "Region to test in."
  type        = string
  default     = "us-east-1"
}

variable "mode" {
  description = "Start with report; re-apply with -var mode=enforce on day 1."
  type        = string
  default     = "report"
}

variable "alert_email" {
  description = "Optional address for digests and alarms. Confirm the subscription email AWS sends."
  type        = string
  default     = null
}

provider "aws" {
  region = var.region

  default_tags {
    tags = { purpose = "iam-key-rotator-e2e" }
  }
}

locals {
  name    = "iam-key-rotator-e2e"
  path    = "/iam-key-rotator-e2e/"
  tag_key = "key-rotator-e2e"
}

module "rotator" {
  source = "../.."

  name_prefix      = local.name
  mode             = var.mode
  tag_key          = local.tag_key
  user_path_prefix = local.path
  ssm_prefix       = "/${local.name}"

  create_after_days          = 1
  deactivate_after_days      = 2
  delete_after_days          = 3
  min_days_before_deactivate = 1
  min_days_before_delete     = 1
  in_use_window_days         = 1
  max_actions_per_run        = 1

  alert_topic_arn = one(aws_sns_topic.alerts[*].arn)
  alarm_actions   = aws_sns_topic.alerts[*].arn

  log_retention_days = 7
}

# --- The throwaway user being rotated ---------------------------------------

resource "aws_iam_user" "test" {
  name = "rotation-test"
  path = local.path

  # Deletes whatever access keys the test leaves behind, so destroy is clean.
  force_destroy = true

  tags = { (local.tag_key) = "enabled" }
}

# The self-fetch pattern from the module README: the user can read its own
# parameter and nothing else.
data "aws_iam_policy_document" "read_own_key" {
  statement {
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/${local.name}/$${aws:username}"]
  }
}

data "aws_caller_identity" "current" {}

resource "aws_iam_user_policy" "read_own_key" {
  name   = "read-own-rotated-key"
  user   = aws_iam_user.test.name
  policy = data.aws_iam_policy_document.read_own_key.json
}

# --- Optional email delivery ------------------------------------------------

resource "aws_sns_topic" "alerts" {
  count = var.alert_email == null ? 0 : 1
  name  = "${local.name}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == null ? 0 : 1
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- Outputs used by the runbook ---------------------------------------------

output "function_name" {
  value = module.rotator.lambda_function_name
}

output "test_user" {
  value = aws_iam_user.test.name
}

output "parameter_name" {
  value = "/${local.name}/${aws_iam_user.test.name}"
}

output "state_table" {
  value = module.rotator.state_table_name
}
