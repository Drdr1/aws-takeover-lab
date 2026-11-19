# Owner-applied guardrails: the SSN key and the audit trail.
#
# Applied with the owner-break-glass role, never with terraform-deploy. The
# deploy role's boundary blocks it from changing anything here, so the people
# who run the servers day to day cannot read SSNs or switch off the record of
# what they did.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.20"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "s3_use_path_style" {
  type    = bool
  default = false
}

variable "trail_bucket" {
  type = string
}

variable "trail_retention_days" {
  type    = number
  default = 365
}

provider "aws" {
  region            = var.region
  s3_use_path_style = var.s3_use_path_style

  default_tags {
    tags = {
      ManagedBy = "terraform"
      Stack     = "guardrails"
    }
  }
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  policy_vars = {
    account_id  = local.account_id
    owner_role  = "owner-break-glass"
    deploy_role = "terraform-deploy"
    app_role    = "los-app"
  }
}

# ---------------------------------------------------------------------------
# Borrower SSNs. The LOS encrypts each SSN with a data key from this KMS key
# before it reaches the database (envelope encryption, see src/takeover/ssn.py),
# so RDS, its snapshots and its backups only ever hold ciphertext.
#
# The key policy has no "account root gets kms:*" statement on purpose: that
# statement would let any IAM admin grant themselves Decrypt. Only the owner
# role can manage the key; admins can see it exists; only the LOS app role can
# use it, and only with the borrower-ssn encryption context.
# ---------------------------------------------------------------------------

resource "aws_kms_key" "ssn" {
  description             = "Borrower SSN envelope encryption (owner-only)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = templatefile("${path.module}/../../policies/ssn-key.json.tftpl", local.policy_vars)

  tags = {
    Protection = "owner-only"
  }
}

resource "aws_kms_alias" "ssn" {
  name          = "alias/los-borrower-ssn"
  target_key_id = aws_kms_key.ssn.key_id
}

# ---------------------------------------------------------------------------
# Audit trail: every API call in every region, written to a bucket where
# Object Lock keeps each log file for a year even from an administrator, with
# log file validation so tampering is detectable.
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "trail" {
  bucket              = var.trail_bucket
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.trail_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.trail]
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

resource "aws_cloudtrail" "main" {
  name                          = "account-audit"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.trail]
}

output "ssn_key_arn" {
  value = aws_kms_key.ssn.arn
}

output "trail_name" {
  value = aws_cloudtrail.main.name
}
