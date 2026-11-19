# Who can do what, decided by the owner and enforced by AWS rather than by trust.
#
#   owner-break-glass  The business owner. Full access, MFA required, used
#                      rarely. Owns the guardrails stack and the SSN key.
#   terraform-deploy   What I (or any sysadmin, or CI) use. Broad access, but
#                      capped by the admin-boundary policy: it cannot touch the
#                      owner's principals, stop CloudTrail, use or re-policy the
#                      SSN key, change the state bucket's policy, or create a
#                      role or user without the same boundary attached.

variable "owner_principal_arn" {
  type        = string
  description = "The owner's own IAM user or SSO principal, the only one who can assume owner-break-glass."
}

variable "deploy_trusted_arns" {
  type        = list(string)
  description = "Who can assume terraform-deploy (sysadmin users or SSO roles; a GitHub OIDC role in CI)."
}

variable "owner_user_name" {
  type    = string
  default = "owner"
}

locals {
  boundary_name = "admin-boundary"
  policy_vars = {
    account_id    = data.aws_caller_identity.current.account_id
    boundary_name = local.boundary_name
    owner_role    = "owner-break-glass"
    owner_user    = var.owner_user_name
    deploy_role   = "terraform-deploy"
    state_bucket  = var.state_bucket
  }
}

resource "aws_iam_policy" "admin_boundary" {
  name        = local.boundary_name
  description = "Ceiling for every admin and deploy role. Owner-only."
  policy      = templatefile("${path.module}/../../policies/admin-boundary.json.tftpl", local.policy_vars)
}

resource "aws_iam_role" "owner" {
  name = "owner-break-glass"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.owner_principal_arn }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "owner_admin" {
  role       = aws_iam_role.owner.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_role" "deploy" {
  name                 = "terraform-deploy"
  permissions_boundary = aws_iam_policy.admin_boundary.arn

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = var.deploy_trusted_arns }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "deploy_admin" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

output "deploy_role_arn" {
  value = aws_iam_role.deploy.arn
}

output "owner_role_arn" {
  value = aws_iam_role.owner.arn
}
