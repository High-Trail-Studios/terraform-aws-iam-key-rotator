locals {
  create_code_bucket = var.code_bucket_name == null
  code_bucket        = local.create_code_bucket ? aws_s3_bucket.code[0].id : var.code_bucket_name
  code_key           = "${var.code_key_prefix}${var.name_prefix}/rotator.zip"
  function_name      = var.name_prefix
}

data "archive_file" "rotator" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/.build/rotator.zip"
  excludes    = ["**/__pycache__/**", "**/*.pyc"]
}

# --- Code bucket (only when the caller did not supply one) ------------------

resource "aws_s3_bucket" "code" {
  count = local.create_code_bucket ? 1 : 0

  bucket_prefix = "${var.name_prefix}-code-"

  # The bucket only ever holds this module's build artifact, which is rebuilt
  # from source on every apply, so emptying it on destroy is safe.
  force_destroy = true

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "code" {
  count = local.create_code_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.code[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "rotator" {
  bucket      = local.code_bucket
  key         = local.code_key
  source      = data.archive_file.rotator.output_path
  source_hash = data.archive_file.rotator.output_base64sha256

  tags = var.tags
}

# --- Function ---------------------------------------------------------------

resource "aws_cloudwatch_log_group" "rotator" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days

  tags = var.tags
}

resource "aws_lambda_function" "rotator" {
  function_name = local.function_name
  role          = aws_iam_role.rotator.arn
  runtime       = "python3.14"
  architectures = ["arm64"]
  handler       = "rotator.handler.handler"
  memory_size   = var.lambda_memory_mb
  timeout       = var.lambda_timeout_seconds

  s3_bucket        = aws_s3_object.rotator.bucket
  s3_key           = aws_s3_object.rotator.key
  source_code_hash = data.archive_file.rotator.output_base64sha256

  environment {
    variables = {
      ROTATOR_NAME                       = var.name_prefix
      ROTATOR_MODE                       = var.mode
      ROTATOR_TAG_KEY                    = var.tag_key
      ROTATOR_USER_PATH_PREFIX           = var.user_path_prefix
      ROTATOR_CREATE_AFTER_DAYS          = tostring(var.create_after_days)
      ROTATOR_DEACTIVATE_AFTER_DAYS      = tostring(var.deactivate_after_days)
      ROTATOR_DELETE_AFTER_DAYS          = tostring(var.delete_after_days)
      ROTATOR_MIN_DAYS_BEFORE_DEACTIVATE = tostring(var.min_days_before_deactivate)
      ROTATOR_MIN_DAYS_BEFORE_DELETE     = tostring(var.min_days_before_delete)
      ROTATOR_IN_USE_WINDOW_DAYS         = tostring(var.in_use_window_days)
      ROTATOR_MAX_ACTIONS_PER_RUN        = tostring(var.max_actions_per_run)
      ROTATOR_SSM_PREFIX                 = var.ssm_prefix
      ROTATOR_SSM_KMS_KEY_ID             = var.ssm_kms_key_arn == null ? "" : var.ssm_kms_key_arn
      ROTATOR_STATE_TABLE                = aws_dynamodb_table.state.name
      ROTATOR_ALERT_TOPIC_ARN            = var.alert_topic_arn == null ? "" : var.alert_topic_arn
    }
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.rotator.name
  }

  tags = var.tags

  depends_on = [aws_iam_role_policy.rotator]
}

# A failed run is not retried: the next scheduled run picks up where it left
# off, and a retry would only send a second digest for the same day.
resource "aws_lambda_function_event_invoke_config" "rotator" {
  function_name          = aws_lambda_function.rotator.function_name
  maximum_retry_attempts = 0
}
