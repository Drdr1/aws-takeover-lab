"""Read-only discovery of an inherited AWS account.

Only Describe/List/Get calls are made (see iam/inventory-readonly.json for the
exact policy this needs). The result is a plain data model that the report,
the findings and the Terraform generator all read from, so the three can
never disagree about what exists.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from botocore.exceptions import ClientError

from takeover.aws import client

MANAGED_TAG = "ManagedBy"


@dataclass
class Resource:
    tf_type: str
    import_id: str
    name: str
    attrs: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    tf_name: str = ""
    in_state: bool = False

    @property
    def address(self) -> str:
        return f"{self.tf_type}.{self.tf_name}"

    @property
    def managed(self) -> bool:
        return self.in_state or self.tags.get(MANAGED_TAG, "").lower() == "terraform"


@dataclass
class Inventory:
    account_id: str
    region: str
    resources: list[Resource] = field(default_factory=list)
    account: dict[str, Any] = field(default_factory=dict)

    def of_type(self, tf_type: str) -> list[Resource]:
        return [r for r in self.resources if r.tf_type == tf_type]

    def by_id(self, import_id: str) -> Resource | None:
        return next((r for r in self.resources if r.import_id == import_id), None)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True, default=str)

    @classmethod
    def from_json(cls, text: str) -> Inventory:
        raw = json.loads(text)
        inv = cls(raw["account_id"], raw["region"], account=raw.get("account", {}))
        inv.resources = [Resource(**r) for r in raw["resources"]]
        return inv


def state_ids(state: dict[str, Any]) -> set[str]:
    """Every id/arn/name in a `terraform show -json` state, for coverage."""
    ids: set[str] = set()

    def walk(module: dict[str, Any]) -> None:
        for r in module.get("resources", []):
            values = r.get("values") or {}
            ids.update(str(values[k]) for k in ("id", "arn", "name", "bucket", "identifier") if values.get(k))
        for child in module.get("child_modules", []):
            walk(child)

    walk((state.get("values") or {}).get("root_module") or {})
    return ids


def mark_managed(inv: Inventory, states: list[dict[str, Any]]) -> None:
    ids: set[str] = set().union(*(state_ids(s) for s in states)) if states else set()
    for r in inv.resources:
        r.in_state = r.import_id in ids


def slug(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()
    if not s or s[0].isdigit():
        s = f"r_{s}"
    return s


def _tags(raw: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in raw or []}


def _assign_names(resources: list[Resource]) -> None:
    seen: dict[tuple[str, str], int] = {}
    for r in resources:
        base = slug(r.name)
        key = (r.tf_type, base)
        seen[key] = seen.get(key, 0) + 1
        r.tf_name = base if seen[key] == 1 else f"{base}_{seen[key]}"


def _network(inv: Inventory) -> set[str]:
    ec2 = client("ec2")
    vpcs = [v for v in ec2.describe_vpcs()["Vpcs"] if not v.get("IsDefault")]
    vpc_ids = {v["VpcId"] for v in vpcs}
    for v in vpcs:
        tags = _tags(v.get("Tags"))
        dns_hostnames = ec2.describe_vpc_attribute(VpcId=v["VpcId"], Attribute="enableDnsHostnames")
        inv.resources.append(
            Resource(
                "aws_vpc",
                v["VpcId"],
                tags.get("Name", v["VpcId"]),
                {
                    "cidr_block": v["CidrBlock"],
                    "enable_dns_hostnames": dns_hostnames["EnableDnsHostnames"]["Value"],
                },
                tags,
            )
        )
    for g in ec2.describe_internet_gateways()["InternetGateways"]:
        att = [a["VpcId"] for a in g.get("Attachments", []) if a["VpcId"] in vpc_ids]
        if not att:
            continue
        tags = _tags(g.get("Tags"))
        inv.resources.append(
            Resource(
                "aws_internet_gateway",
                g["InternetGatewayId"],
                tags.get("Name", g["InternetGatewayId"]),
                {"vpc_id": att[0]},
                tags,
            )
        )
    for s in ec2.describe_subnets()["Subnets"]:
        if s["VpcId"] not in vpc_ids:
            continue
        tags = _tags(s.get("Tags"))
        inv.resources.append(
            Resource(
                "aws_subnet",
                s["SubnetId"],
                tags.get("Name", s["SubnetId"]),
                {
                    "vpc_id": s["VpcId"],
                    "cidr_block": s["CidrBlock"],
                    "availability_zone": s["AvailabilityZone"],
                    "map_public_ip_on_launch": s.get("MapPublicIpOnLaunch", False),
                },
                tags,
            )
        )
    for g in ec2.describe_security_groups()["SecurityGroups"]:
        if g["VpcId"] not in vpc_ids or g["GroupName"] == "default":
            continue
        tags = _tags(g.get("Tags"))
        inv.resources.append(
            Resource(
                "aws_security_group",
                g["GroupId"],
                tags.get("Name", g["GroupName"]),
                {
                    "group_name": g["GroupName"],
                    "description": g["Description"],
                    "vpc_id": g["VpcId"],
                    "ingress": [_perm(p) for p in g.get("IpPermissions", [])],
                    "egress": [_perm(p) for p in g.get("IpPermissionsEgress", [])],
                },
                tags,
            )
        )
    return vpc_ids


def _perm(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol": p["IpProtocol"],
        "from_port": p.get("FromPort", 0),
        "to_port": p.get("ToPort", 0),
        "cidr_blocks": sorted(r["CidrIp"] for r in p.get("IpRanges", [])),
        "security_groups": sorted(g["GroupId"] for g in p.get("UserIdGroupPairs", [])),
    }


def _instances(inv: Inventory, vpc_ids: set[str]) -> None:
    ec2 = client("ec2")
    for res in ec2.describe_instances()["Reservations"]:
        for i in res["Instances"]:
            if i.get("VpcId") not in vpc_ids or i["State"]["Name"] == "terminated":
                continue
            tags = _tags(i.get("Tags"))
            inv.resources.append(
                Resource(
                    "aws_instance",
                    i["InstanceId"],
                    tags.get("Name", i["InstanceId"]),
                    {
                        "ami": i["ImageId"],
                        "instance_type": i["InstanceType"],
                        "subnet_id": i["SubnetId"],
                        "vpc_security_group_ids": sorted(g["GroupId"] for g in i.get("SecurityGroups", [])),
                        "public_ip": i.get("PublicIpAddress"),
                        "platform": tags.get("Platform", i.get("Platform", "linux")),
                        "iam_instance_profile": (i.get("IamInstanceProfile") or {}).get("Arn"),
                        "metadata_http_tokens": (i.get("MetadataOptions") or {}).get("HttpTokens", "optional"),
                    },
                    tags,
                )
            )


def _databases(inv: Inventory) -> None:
    rds = client("rds")
    for g in rds.describe_db_subnet_groups()["DBSubnetGroups"]:
        inv.resources.append(
            Resource(
                "aws_db_subnet_group",
                g["DBSubnetGroupName"],
                g["DBSubnetGroupName"],
                {
                    "description": g["DBSubnetGroupDescription"],
                    "subnet_ids": sorted(s["SubnetIdentifier"] for s in g["Subnets"]),
                },
            )
        )
    for d in rds.describe_db_instances()["DBInstances"]:
        tags = _tags(rds.list_tags_for_resource(ResourceName=d["DBInstanceArn"])["TagList"])
        inv.resources.append(
            Resource(
                "aws_db_instance",
                d["DBInstanceIdentifier"],
                d["DBInstanceIdentifier"],
                {
                    "engine": d["Engine"],
                    "engine_version": d["EngineVersion"],
                    "instance_class": d["DBInstanceClass"],
                    "allocated_storage": d["AllocatedStorage"],
                    "username": d["MasterUsername"],
                    "db_subnet_group_name": d["DBSubnetGroup"]["DBSubnetGroupName"],
                    "vpc_security_group_ids": sorted(g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups", [])),
                    "publicly_accessible": d.get("PubliclyAccessible", False),
                    "storage_encrypted": d.get("StorageEncrypted", False),
                    "backup_retention_period": d.get("BackupRetentionPeriod", 0),
                    "deletion_protection": d.get("DeletionProtection", False),
                    "multi_az": d.get("MultiAZ", False),
                },
                tags,
            )
        )


def _buckets(inv: Inventory) -> None:
    s3 = client("s3")
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        try:
            tags = _tags(s3.get_bucket_tagging(Bucket=name)["TagSet"])
        except ClientError:
            tags = {}
        versioning = s3.get_bucket_versioning(Bucket=name).get("Status", "Disabled")
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError:
            pab = None
        try:
            rules = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
            sse = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except (ClientError, KeyError, IndexError):
            sse = None
        inv.resources.append(
            Resource(
                "aws_s3_bucket",
                name,
                name,
                {"versioning": versioning, "public_access_block": pab, "sse": sse},
                tags,
            )
        )


def _identity(inv: Inventory) -> None:
    iam = client("iam")
    for u in iam.list_users()["Users"]:
        name = u["UserName"]
        tags = _tags(iam.list_user_tags(UserName=name)["Tags"])
        policies = sorted(p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"])
        keys = [
            k["AccessKeyId"]
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
            if k["Status"] == "Active"
        ]
        mfa = iam.list_mfa_devices(UserName=name)["MFADevices"]
        inv.resources.append(
            Resource(
                "aws_iam_user",
                name,
                name,
                {"path": u["Path"], "policies": policies, "active_keys": len(keys), "mfa": bool(mfa)},
                tags,
            )
        )
    for r in iam.list_roles()["Roles"]:
        if r["Path"].startswith("/aws-service-role/"):
            continue
        name = r["RoleName"]
        tags = _tags(iam.list_role_tags(RoleName=name)["Tags"])
        doc = r["AssumeRolePolicyDocument"]
        if isinstance(doc, str):
            doc = json.loads(doc)
        boundary = (iam.get_role(RoleName=name)["Role"].get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
        inv.resources.append(
            Resource(
                "aws_iam_role",
                name,
                name,
                {"path": r["Path"], "assume_role_policy": doc, "permissions_boundary": boundary},
                tags,
            )
        )


def _secrets(inv: Inventory) -> None:
    sm = client("secretsmanager")
    for s in sm.list_secrets()["SecretList"]:
        # Metadata only. GetSecretValue is never called and is denied in the
        # read-only policy: an inventory has no business reading secrets.
        inv.resources.append(
            Resource(
                "aws_secretsmanager_secret",
                s["ARN"],
                s["Name"],
                {
                    "secret_name": s["Name"],
                    "kms_key_id": s.get("KmsKeyId"),
                    "rotation_enabled": s.get("RotationEnabled", False),
                },
                _tags(s.get("Tags")),
            )
        )


def _account(inv: Inventory) -> None:
    trails = client("cloudtrail").describe_trails()["trailList"]
    inv.account["cloudtrail_trails"] = [t["Name"] for t in trails]
    inv.account["multi_region_trail"] = any(t.get("IsMultiRegionTrail") for t in trails)


def discover() -> Inventory:
    account_id = client("sts").get_caller_identity()["Account"]
    inv = Inventory(account_id=account_id, region=client("ec2").meta.region_name)
    vpc_ids = _network(inv)
    _instances(inv, vpc_ids)
    _databases(inv)
    _buckets(inv)
    _identity(inv)
    _secrets(inv)
    _account(inv)
    _assign_names(inv.resources)
    return inv
