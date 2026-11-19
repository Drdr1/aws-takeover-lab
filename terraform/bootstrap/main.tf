# Remote state for everything else. Applied once with local state, by the
# account owner, then never touched by day-to-day pipelines.
#
# State can contain secrets (RDS endpoints, generated passwords, anything a
# provider stores), so access to this bucket is treated like database access.

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

variable "state_bucket" {
  type        = string
  description = "Globally unique name for the state bucket."
}

variable "attach_bucket_policy" {
  type        = bool
  default     = true
  description = "Always true in a real account. The moto lab sets false: moto evaluates aws:SecureTransport and aws:PrincipalArn differently from AWS, so the policy is verified by tests/test_policies.py instead."
}


provider "aws" {
  region            = var.region
  s3_use_path_style = var.s3_use_path_style

  default_tags {
    tags = {
      ManagedBy = "terraform"
      Stack     = "bootstrap"
    }
  }
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "state" {
  description             = "Terraform state encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootManagesKey"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "StateAdminsUseKey"
        Effect    = "Allow"
        Principal = { AWS = [aws_iam_role.deploy.arn, aws_iam_role.owner.arn] }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "state" {
  name          = "alias/terraform-state"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket = var.state_bucket

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# Old state versions are the rollback path, so they are kept for 90 days.
resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  count  = var.attach_bucket_policy ? 1 : 0
  bucket = aws_s3_bucket.state.id
  policy = templatefile("${path.module}/../../policies/state-bucket.json.tftpl", local.policy_vars)

  depends_on = [aws_s3_bucket_public_access_block.state]
}

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}
