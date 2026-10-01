output "lambda_function_name" {
  description = "Name of the rotator function. Invoke it by hand to get a report now."
  value       = aws_lambda_function.rotator.function_name
}

output "lambda_role_arn" {
  description = "Execution role of the rotator, e.g. for a KMS key policy."
  value       = aws_iam_role.rotator.arn
}

output "state_table_name" {
  description = "DynamoDB table holding rotations in progress."
  value       = aws_dynamodb_table.state.name
}

output "ssm_prefix" {
  description = "SSM path new keys are published under. Grant consumers ssm:GetParameter on their own parameter beneath it."
  value       = var.ssm_prefix
}

output "tag_key" {
  description = "IAM user tag that opts users in."
  value       = var.tag_key
}
