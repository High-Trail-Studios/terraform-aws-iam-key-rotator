# The common case: one rotator per account, starting in report mode, with the
# digest and the rotator's own alarms delivered to Slack through sns-relay.
#
# After apply, store the two webhook URLs that sns-relay needs (see its
# required_ssm_parameters output), tag a user with key-rotator = enabled, and
# invoke the function by hand to see the first report.

terraform {
  required_version = ">= 1.7.0"
}

provider "aws" {
  region = "us-east-1"
}

module "sns_relay" {
  source = "git::https://github.com/High-Trail-Studios/terraform-aws-sns-relay.git?ref=v0.1.0"

  routes = {
    security = { adapter = "slack" } # rotation digests: actions, warnings, errors
    ops      = { adapter = "slack" } # the rotator's own alarms: failed or missed runs
  }
}

module "iam_key_rotator" {
  source = "../.."

  # Defaults: mode = "report", tag_key = "key-rotator", keys published under
  # /iam-key-rotator/<user name>. Switch to "enforce" once the report looks
  # right and your consumers read their key from SSM.

  alert_topic_arn = module.sns_relay.topic_arns["security"]
  alarm_actions   = [module.sns_relay.topic_arns["ops"]]
}

output "rotator_function_name" {
  description = "Invoke this to get a report now."
  value       = module.iam_key_rotator.lambda_function_name
}

output "ssm_prefix" {
  value = module.iam_key_rotator.ssm_prefix
}

output "required_ssm_parameters" {
  description = "Webhook URLs to store before alerts flow."
  value       = module.sns_relay.required_ssm_parameters
}
