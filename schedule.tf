resource "aws_cloudwatch_event_rule" "schedule" {
  name                = var.name_prefix
  description         = "Runs ${local.function_name} to check and rotate IAM access keys."
  schedule_expression = var.schedule

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "schedule" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.rotator.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "eventbridge-schedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
