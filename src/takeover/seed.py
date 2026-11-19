"""Seed the "inherited" environment: what a previous engineer left behind.

Built by hand through API calls (the moto equivalent of console clicks), with
no Terraform, so the rest of the lab has something undocumented to take over.
It deliberately contains the problems a takeover usually finds: SSH and RDP
open to the internet, a publicly reachable database with one day of backups,
a bucket with no versioning or public-access block, an IAM user with full
admin and a live access key, and no CloudTrail.
"""

from __future__ import annotations

import json

from takeover.aws import client

TAGS = [{"Key": "Owner", "Value": "previous-engineer"}]


def _tag(name: str) -> list[dict[str, str]]:
    return [{"Key": "Name", "Value": name}, *TAGS]


def seed() -> dict[str, str]:
    ec2 = client("ec2")
    ids: dict[str, str] = {}

    vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc], Tags=_tag("los-prod"))
    ec2.modify_vpc_attribute(VpcId=vpc, EnableDnsHostnames={"Value": True})
    ids["vpc"] = vpc

    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    ec2.create_tags(Resources=[igw], Tags=_tag("los-prod-igw"))
    ids["igw"] = igw

    subnets = {
        "public-a": ("10.20.1.0/24", "us-east-1a"),
        "public-b": ("10.20.2.0/24", "us-east-1b"),
        "private-a": ("10.20.11.0/24", "us-east-1a"),
        "private-b": ("10.20.12.0/24", "us-east-1b"),
    }
    for name, (cidr, az) in subnets.items():
        sid = ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az)["Subnet"]["SubnetId"]
        ec2.create_tags(Resources=[sid], Tags=_tag(f"los-{name}"))
        ids[f"subnet-{name}"] = sid

    def sg(name: str, desc: str, rules: list[dict[str, object]]) -> str:
        gid: str = ec2.create_security_group(GroupName=name, Description=desc, VpcId=vpc)["GroupId"]
        ec2.create_tags(Resources=[gid], Tags=_tag(name))
        if rules:
            ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=rules)
        return gid

    world = [{"CidrIp": "0.0.0.0/0"}]
    ids["sg-web"] = sg(
        "los-web",
        "LOS web tier",
        [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": world},
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": world},
        ],
    )
    ids["sg-bridge"] = sg(
        "mismo-bridge",
        "MISMO bridge Windows host",
        [{"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": world}],
    )
    ids["sg-db"] = sg(
        "los-db",
        "LOS database",
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "UserIdGroupPairs": [{"GroupId": ids["sg-web"]}, {"GroupId": ids["sg-bridge"]}],
            }
        ],
    )

    def instance(name: str, subnet: str, group: str, platform: str) -> str:
        iid = ec2.run_instances(
            ImageId="ami-12c6146b",
            InstanceType="t3.medium",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet,
            SecurityGroupIds=[group],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [*_tag(name), {"Key": "Platform", "Value": platform}],
                }
            ],
        )["Instances"][0]["InstanceId"]
        return str(iid)

    ids["ec2-web"] = instance("los-web-01", ids["subnet-public-a"], ids["sg-web"], "linux")
    ids["ec2-bridge"] = instance("mismo-bridge-01", ids["subnet-public-b"], ids["sg-bridge"], "windows")

    rds = client("rds")
    rds.create_db_subnet_group(
        DBSubnetGroupName="los-db-subnets",
        DBSubnetGroupDescription="LOS database subnets",
        SubnetIds=[ids["subnet-private-a"], ids["subnet-private-b"]],
    )
    rds.create_db_instance(
        DBInstanceIdentifier="los-db",
        DBInstanceClass="db.t3.medium",
        Engine="postgres",
        EngineVersion="16.3",
        AllocatedStorage=100,
        MasterUsername="losadmin",
        MasterUserPassword="change-me-not-a-real-secret",
        DBSubnetGroupName="los-db-subnets",
        VpcSecurityGroupIds=[ids["sg-db"]],
        PubliclyAccessible=True,
        StorageEncrypted=False,
        BackupRetentionPeriod=1,
        Tags=TAGS,
    )
    ids["rds"] = "los-db"

    s3 = client("s3")
    for bucket in ("acme-los-documents", "acme-los-backups"):
        s3.create_bucket(Bucket=bucket)
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": TAGS})
    s3.put_bucket_versioning(Bucket="acme-los-backups", VersioningConfiguration={"Status": "Enabled"})
    s3.put_public_access_block(
        Bucket="acme-los-backups",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    ids["s3-docs"] = "acme-los-documents"
    ids["s3-backups"] = "acme-los-backups"

    iam = client("iam")
    iam.create_user(UserName="prev-admin", Tags=TAGS)
    iam.attach_user_policy(UserName="prev-admin", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="prev-admin")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName="los-app", AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS)
    ids["iam-user"] = "prev-admin"
    ids["iam-role"] = "los-app"

    sm = client("secretsmanager")
    ids["secret"] = sm.create_secret(
        Name="los/db-master",
        SecretString=json.dumps({"username": "losadmin", "password": "change-me-not-a-real-secret"}),
        Tags=TAGS,
    )["ARN"]
    return ids


if __name__ == "__main__":
    print(json.dumps(seed(), indent=2))
