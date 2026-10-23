data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  account_arn_prefix = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}"
  ssm_arn_prefix     = "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_prefix}"

  # Every IAM user the rotator may look at. Mutations are further limited to
  # users tagged "<tag_key> = enabled"; see iam.tf.
  user_arn_pattern = "${local.account_arn_prefix}:user${var.user_path_prefix}*"
}
