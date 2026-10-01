data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "rotator" {
  name               = "${var.name_prefix}-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = var.tags
}

# Everything the rotator can do, and nothing more. See README "IAM".
data "aws_iam_policy_document" "rotator" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.rotator.arn}:*"]
  }

  # ListUsers does not support resource-level permissions.
  statement {
    sid       = "ListUsers"
    actions   = ["iam:ListUsers"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadUsersAndKeys"
    actions   = ["iam:ListUserTags", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"]
    resources = [local.user_arn_pattern]
  }

  # The opt-in is enforced here, not only in code: IAM refuses to let the
  # rotator change keys of any user not tagged "<tag_key> = enabled".
  statement {
    sid       = "RotateOptedInUsersOnly"
    actions   = ["iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:DeleteAccessKey"]
    resources = [local.user_arn_pattern]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.tag_key}"
      values   = ["enabled"]
    }
  }

  statement {
    sid       = "TrackRotations"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.state.arn]
  }

  # Writes are confined to ssm_prefix whatever a user's ssm-path tag says, so
  # tagging a user can never redirect a new key outside it.
  statement {
    sid       = "PublishKeys"
    actions   = ["ssm:PutParameter"]
    resources = ["${local.ssm_arn_prefix}/*"]
  }

  dynamic "statement" {
    for_each = var.ssm_kms_key_arn == null ? [] : [var.ssm_kms_key_arn]

    content {
      sid       = "EncryptPublishedKeys"
      actions   = ["kms:Encrypt", "kms:GenerateDataKey"]
      resources = [statement.value]

      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["ssm.${data.aws_region.current.region}.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.alert_topic_arn == null ? [] : [var.alert_topic_arn]

    content {
      sid       = "SendDigest"
      actions   = ["sns:Publish"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "rotator" {
  name   = "rotator"
  role   = aws_iam_role.rotator.id
  policy = data.aws_iam_policy_document.rotator.json
}
