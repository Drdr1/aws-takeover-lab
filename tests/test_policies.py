"""The access rules that protect the owner and the SSNs, as executable checks.

These render the exact policy files Terraform applies (policies/*.tftpl) and
evaluate requests against them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from takeover.policy_eval import POLICIES, Request, allowed_by_all, decide, not_denied, render

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role"
OWNER = f"{ROLE}/owner-break-glass"
DEPLOY = f"{ROLE}/terraform-deploy"
APP = f"{ROLE}/los-app"
OUTSIDER = f"{ROLE}/someone-else"
BOUNDARY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/admin-boundary"
VARS = {
    "account_id": ACCOUNT,
    "boundary_name": "admin-boundary",
    "owner_role": "owner-break-glass",
    "owner_user": "owner",
    "deploy_role": "terraform-deploy",
    "app_role": "los-app",
    "state_bucket": "acme-tfstate",
}
ADMIN = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


@pytest.fixture(scope="module")
def boundary() -> dict:
    return render("admin-boundary.json.tftpl", **VARS)


@pytest.fixture(scope="module")
def key_policy() -> dict:
    return render("ssn-key.json.tftpl", **VARS)


@pytest.fixture(scope="module")
def bucket_policy() -> dict:
    return render("state-bucket.json.tftpl", **VARS)


def deploy_can(boundary: dict, action: str, resource: str = "*", **ctx: str) -> bool:
    """terraform-deploy has AdministratorAccess, capped by the boundary."""
    return allowed_by_all([ADMIN, boundary], Request(DEPLOY, action, resource, dict(ctx)))


# --- the sysadmin can do the job -------------------------------------------


@pytest.mark.parametrize(
    "action,resource",
    [
        ("ec2:RunInstances", "*"),
        ("ec2:AuthorizeSecurityGroupIngress", "*"),
        ("rds:ModifyDBInstance", f"arn:aws:rds:us-east-1:{ACCOUNT}:db:los-db"),
        ("s3:PutObject", "arn:aws:s3:::acme-tfstate/los-prod/terraform.tfstate"),
        ("ssm:StartSession", "*"),
        ("iam:PassRole", APP),
        ("kms:Decrypt", f"arn:aws:kms:us-east-1:{ACCOUNT}:key/state-key"),
    ],
)
def test_deploy_role_can_run_the_environment(boundary: dict, action: str, resource: str) -> None:
    assert deploy_can(boundary, action, resource)


def test_deploy_role_can_create_roles_only_with_the_same_boundary(boundary: dict) -> None:
    assert deploy_can(boundary, "iam:CreateRole", f"{ROLE}/new", **{"iam:PermissionsBoundary": BOUNDARY_ARN})
    assert not deploy_can(boundary, "iam:CreateRole", f"{ROLE}/new")
    assert not deploy_can(
        boundary, "iam:CreateRole", f"{ROLE}/new", **{"iam:PermissionsBoundary": f"arn:aws:iam::{ACCOUNT}:policy/mine"}
    )
    assert not deploy_can(boundary, "iam:CreateUser", f"arn:aws:iam::{ACCOUNT}:user/backdoor")


# --- ...but cannot lock the owner out or cover their tracks -----------------


@pytest.mark.parametrize(
    "action,resource",
    [
        ("iam:UpdateAssumeRolePolicy", OWNER),
        ("iam:DetachRolePolicy", OWNER),
        ("iam:DeleteRole", OWNER),
        ("iam:DeleteLoginProfile", f"arn:aws:iam::{ACCOUNT}:user/owner"),
        ("iam:DeactivateMFADevice", f"arn:aws:iam::{ACCOUNT}:user/owner"),
        ("iam:DeleteRolePermissionsBoundary", DEPLOY),
        ("iam:CreatePolicyVersion", BOUNDARY_ARN),
        ("iam:SetDefaultPolicyVersion", BOUNDARY_ARN),
        ("cloudtrail:StopLogging", "*"),
        ("cloudtrail:DeleteTrail", "*"),
        ("s3:PutBucketPolicy", "arn:aws:s3:::acme-tfstate"),
        ("account:PutAlternateContact", "*"),
        ("organizations:LeaveOrganization", "*"),
    ],
)
def test_deploy_role_cannot_lock_out_the_owner(boundary: dict, action: str, resource: str) -> None:
    assert not deploy_can(boundary, action, resource)


@pytest.mark.parametrize(
    "action", ["kms:Decrypt", "kms:PutKeyPolicy", "kms:CreateGrant", "kms:ScheduleKeyDeletion", "kms:UntagResource"]
)
def test_deploy_role_cannot_use_or_repolicy_owner_only_keys(boundary: dict, action: str) -> None:
    key = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/ssn"
    assert not deploy_can(boundary, action, key, **{"aws:ResourceTag/Protection": "owner-only"})


# --- the SSN key: admins see it, only the app uses it -----------------------


def test_only_the_app_decrypts_ssns_and_only_with_ssn_context(key_policy: dict) -> None:
    ctx = {"kms:EncryptionContext:purpose": "borrower-ssn"}
    assert decide(key_policy, Request(APP, "kms:Decrypt", context=ctx)) == "Allow"
    assert decide(key_policy, Request(APP, "kms:GenerateDataKey", context=ctx)) == "Allow"
    assert decide(key_policy, Request(APP, "kms:Decrypt")) == "ImplicitDeny"
    assert (
        decide(key_policy, Request(APP, "kms:Decrypt", context={"kms:EncryptionContext:purpose": "x"}))
        == "ImplicitDeny"
    )
    assert decide(key_policy, Request(APP, "kms:PutKeyPolicy", context=ctx)) == "ImplicitDeny"


@pytest.mark.parametrize("action", ["kms:Decrypt", "kms:GenerateDataKey", "kms:PutKeyPolicy", "kms:CreateGrant"])
def test_admins_cannot_use_or_change_the_ssn_key(key_policy: dict, action: str) -> None:
    ctx = {"kms:EncryptionContext:purpose": "borrower-ssn"}
    assert decide(key_policy, Request(DEPLOY, action, context=ctx)) != "Allow"


def test_admins_can_see_the_ssn_key(key_policy: dict) -> None:
    assert decide(key_policy, Request(DEPLOY, "kms:DescribeKey")) == "Allow"
    assert decide(key_policy, Request(DEPLOY, "kms:GetKeyRotationStatus")) == "Allow"


def test_owner_keeps_control_of_the_ssn_key(key_policy: dict) -> None:
    assert decide(key_policy, Request(OWNER, "kms:PutKeyPolicy")) == "Allow"


def test_ssn_key_policy_has_no_account_root_grant(key_policy: dict) -> None:
    """A root kms:* statement would let any IAM admin grant themselves Decrypt."""
    root = f"arn:aws:iam::{ACCOUNT}:root"
    assert decide(key_policy, Request(root, "kms:Decrypt")) == "ImplicitDeny"
    assert decide(key_policy, Request(root, "kms:PutKeyPolicy")) == "ImplicitDeny"


# --- the state bucket -------------------------------------------------------


def test_state_bucket_refuses_plain_http(bucket_policy: dict) -> None:
    req = Request(DEPLOY, "s3:GetObject", "arn:aws:s3:::acme-tfstate/los-prod/terraform.tfstate")
    req.context = {"aws:SecureTransport": "false", "aws:PrincipalArn": DEPLOY}
    assert not not_denied(bucket_policy, req)


def test_state_bucket_allows_only_state_admins(bucket_policy: dict) -> None:
    obj = "arn:aws:s3:::acme-tfstate/los-prod/terraform.tfstate"
    for who, expected in ((DEPLOY, True), (OWNER, True), (OUTSIDER, False), (APP, False)):
        req = Request(who, "s3:GetObject", obj, {"aws:SecureTransport": "true", "aws:PrincipalArn": who})
        assert not_denied(bucket_policy, req) is expected, who


# --- the organization SCP ---------------------------------------------------


def test_scp_protects_guardrails_from_everyone_but_the_owner() -> None:
    scp = json.loads((POLICIES / "scp-protect-owner.json").read_text())
    for action in ("cloudtrail:StopLogging", "kms:PutKeyPolicy", "account:CloseAccount"):
        assert not not_denied(
            scp, Request(DEPLOY, action, context={"aws:PrincipalArn": DEPLOY, "aws:RequestedRegion": "us-east-1"})
        )
        assert not_denied(
            scp, Request(OWNER, action, context={"aws:PrincipalArn": OWNER, "aws:RequestedRegion": "us-east-1"})
        )


def test_scp_keeps_workloads_in_approved_regions() -> None:
    scp = json.loads((POLICIES / "scp-protect-owner.json").read_text())
    ctx = {"aws:PrincipalArn": DEPLOY}
    assert not_denied(scp, Request(DEPLOY, "ec2:RunInstances", context={**ctx, "aws:RequestedRegion": "us-east-1"}))
    assert not not_denied(
        scp, Request(DEPLOY, "ec2:RunInstances", context={**ctx, "aws:RequestedRegion": "ap-south-1"})
    )
    assert not_denied(scp, Request(DEPLOY, "iam:ListRoles", context={**ctx, "aws:RequestedRegion": "ap-south-1"}))


def test_every_policy_file_is_covered() -> None:
    files = {p.name for p in Path(POLICIES).iterdir()}
    assert files == {
        "admin-boundary.json.tftpl",
        "ssn-key.json.tftpl",
        "state-bucket.json.tftpl",
        "scp-protect-owner.json",
        "inventory-readonly.json",
    }
