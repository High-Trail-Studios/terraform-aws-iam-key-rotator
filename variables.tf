variable "name_prefix" {
  description = "Prefix for every resource this module creates."
  type        = string
  default     = "iam-key-rotator"

  validation {
    condition     = can(regex("^[a-zA-Z0-9-]{1,40}$", var.name_prefix))
    error_message = "name_prefix must be 1-40 characters of letters, digits, and hyphens."
  }
}

variable "mode" {
  description = "\"report\" decides and reports but changes nothing. \"enforce\" creates, deactivates and deletes keys. Start with report and switch once the digest looks right."
  type        = string
  default     = "report"

  validation {
    condition     = contains(["report", "enforce"], var.mode)
    error_message = "mode must be \"report\" or \"enforce\"."
  }
}

variable "tag_key" {
  description = "IAM user tag that opts a user in. \"<tag_key> = enabled\" rotates; \"skip\" excludes with reporting. Users without it are never touched, and IAM enforces that."
  type        = string
  default     = "key-rotator"

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.:/=+@-]{1,100}$", var.tag_key))
    error_message = "tag_key must be 1-100 characters valid in an IAM tag key."
  }
}

variable "user_path_prefix" {
  description = "Only IAM users under this path are considered. Narrows both the listing and the IAM policy."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([a-zA-Z0-9+=,.@_-]+/)*$", var.user_path_prefix))
    error_message = "user_path_prefix must start and end with /."
  }
}

# --- Schedule thresholds ------------------------------------------------------

variable "create_after_days" {
  description = "Create the replacement once the active key is this many days old."
  type        = number
  default     = 65
}

variable "deactivate_after_days" {
  description = "Earliest key age at which the old key is deactivated."
  type        = number
  default     = 75
}

variable "delete_after_days" {
  description = "Earliest key age at which a deactivated old key is deleted."
  type        = number
  default     = 85

  validation {
    condition     = var.create_after_days > 0 && var.create_after_days < var.deactivate_after_days && var.deactivate_after_days < var.delete_after_days
    error_message = "Need 0 < create_after_days < deactivate_after_days < delete_after_days."
  }
}

variable "min_days_before_deactivate" {
  description = "Minimum days between publishing the replacement and deactivating the old key, even for overdue keys."
  type        = number
  default     = 10

  validation {
    condition     = var.min_days_before_deactivate >= 1
    error_message = "min_days_before_deactivate must be at least 1."
  }
}

variable "min_days_before_delete" {
  description = "Minimum days between deactivating the old key and deleting it: the rollback window."
  type        = number
  default     = 10

  validation {
    condition     = var.min_days_before_delete >= 1
    error_message = "min_days_before_delete must be at least 1."
  }
}

variable "in_use_window_days" {
  description = "The old key is deactivated only after it has been unused for this many days. While in use, the rotator holds and warns."
  type        = number
  default     = 7

  validation {
    condition     = var.in_use_window_days >= 1
    error_message = "in_use_window_days must be at least 1."
  }
}

variable "max_actions_per_run" {
  description = "Cap on key changes per run. Users beyond it are deferred to the next run. Limits the blast radius of a bad configuration."
  type        = number
  default     = 10

  validation {
    condition     = var.max_actions_per_run >= 1
    error_message = "max_actions_per_run must be at least 1."
  }
}

variable "schedule" {
  description = "EventBridge schedule. The thresholds assume roughly daily runs."
  type        = string
  default     = "cron(0 6 * * ? *)"
}

# --- Output -------------------------------------------------------------------

variable "ssm_prefix" {
  description = "New keys are written as SecureString to \"<ssm_prefix>/<user name>\" (or \"<ssm_prefix>/<tag_key>:ssm-path tag>\"). The Lambda can write nowhere else."
  type        = string
  default     = "/iam-key-rotator"

  validation {
    condition     = can(regex("^/[a-zA-Z0-9_.-]+(/[a-zA-Z0-9_.-]+)*$", var.ssm_prefix))
    error_message = "ssm_prefix must start with / and must not end with /."
  }
}

variable "ssm_kms_key_arn" {
  description = "Customer-managed KMS key for the SecureString parameters. Null uses the free aws/ssm key."
  type        = string
  default     = null
}

# --- Alerting -----------------------------------------------------------------

variable "alert_topic_arn" {
  description = "SNS topic for the per-run digest, e.g. a route from the sns-relay module. Null logs the digest only."
  type        = string
  default     = null

  validation {
    condition     = var.alert_topic_arn == null || can(regex("^arn:aws[a-zA-Z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]{1,256}$", var.alert_topic_arn))
    error_message = "alert_topic_arn must be a standard SNS topic ARN."
  }
}

variable "create_alarms" {
  description = "Create CloudWatch alarms for failed runs and missed runs."
  type        = bool
  default     = true
}

variable "alarm_actions" {
  description = "ARNs notified when an alarm fires or recovers."
  type        = list(string)
  default     = []
}

variable "missed_run_alarm_hours" {
  description = "Alarm when the rotator has not run for this many hours. Keep it above the schedule interval."
  type        = number
  default     = 26

  validation {
    condition     = var.missed_run_alarm_hours >= 2 && var.missed_run_alarm_hours <= 168
    error_message = "missed_run_alarm_hours must be between 2 and 168."
  }
}

# --- Code storage and Lambda -------------------------------------------------

variable "code_bucket_name" {
  description = "Existing S3 bucket for the Lambda package. Null creates a small dedicated bucket that is destroyed with the module."
  type        = string
  default     = null
}

variable "code_key_prefix" {
  description = "Key prefix inside the code bucket, e.g. \"lambda/\"."
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = "Lambda memory. The rotator is I/O bound; 128 MB is enough."
  type        = number
  default     = 128
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout. Each key creation can take up to ~30s while the new key propagates."
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the rotator's log group."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags applied to every taggable resource."
  type        = map(string)
  default     = {}
}
