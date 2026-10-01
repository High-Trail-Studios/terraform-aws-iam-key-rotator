# A rotator that fails quietly is worse than none: keys drift past their limit
# while everything looks calm. One alarm for failed runs, one for missing runs.

resource "aws_cloudwatch_metric_alarm" "errors" {
  count = var.create_alarms ? 1 : 0

  alarm_name        = "${var.name_prefix}-errors"
  alarm_description = "A ${local.function_name} run failed for at least one user in the last 24 hours. The digest and the Lambda logs name the user and the error."

  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.rotator.function_name }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = var.alarm_actions
  ok_actions    = var.alarm_actions

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "missed_run" {
  count = var.create_alarms ? 1 : 0

  alarm_name        = "${var.name_prefix}-missed-run"
  alarm_description = "${local.function_name} has not run for ${var.missed_run_alarm_hours} hours. Check the ${aws_cloudwatch_event_rule.schedule.name} schedule rule."

  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = aws_lambda_function.rotator.function_name }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = var.missed_run_alarm_hours
  datapoints_to_alarm = var.missed_run_alarm_hours
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = var.alarm_actions
  ok_actions    = var.alarm_actions

  tags = var.tags
}
