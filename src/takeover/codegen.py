"""Turn an inventory into Terraform code plus import blocks.

The output is meant to read like code a person wrote: IDs of resources that are
themselves imported become references (vpc_id = aws_vpc.los_prod.id), only the
arguments that matter are set, and resources are split into files by layer.
`terraform plan` returning zero changes is the proof that the code describes
the account exactly as it is, before anyone changes anything.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from takeover.findings import Finding, evaluate
from takeover.hcl import Block, Raw, import_block, resource
from takeover.inventory import Inventory, Resource, slug

FILES = {
    "aws_vpc": "network.tf",
    "aws_internet_gateway": "network.tf",
    "aws_subnet": "network.tf",
    "aws_security_group": "security_groups.tf",
    "aws_instance": "compute.tf",
    "aws_db_subnet_group": "database.tf",
    "aws_db_instance": "database.tf",
    "aws_s3_bucket": "storage.tf",
    "aws_iam_user": "identity.tf",
    "aws_iam_role": "identity.tf",
    "aws_secretsmanager_secret": "secrets.tf",
}


class Generator:
    def __init__(self, inv: Inventory, findings: list[Finding] | None = None) -> None:
        self.inv = inv
        self.findings: dict[str, list[Finding]] = defaultdict(list)
        for f in evaluate(inv) if findings is None else findings:
            self.findings[f.resource_id].append(f)
        self.refs = {r.import_id: r.address for r in inv.resources}
        self.files: dict[str, list[str]] = defaultdict(list)
        self.imports: list[str] = []

    def ref(self, import_id: str, attr: str = "id") -> Any:
        addr = self.refs.get(import_id)
        return Raw(f"{addr}.{attr}") if addr else import_id

    def refs_list(self, ids: list[str]) -> Any:
        items = [self.ref(i) for i in ids]
        if all(isinstance(i, Raw) for i in items):
            # Every list rendered here is a set in the provider, so sorting
            # by address gives stable, diff-friendly code without a plan diff.
            return Raw("[" + ", ".join(sorted(i.expr for i in items if isinstance(i, Raw))) + "]")
        return items

    def emit(self, r: Resource, items: dict[str, Any], tf_type: str = "", name: str = "", import_id: str = "") -> None:
        tf_type = tf_type or r.tf_type
        name = name or r.tf_name
        if r.tags and "tags" not in items and tf_type == r.tf_type:
            items["tags"] = dict(r.tags)
        notes = ""
        if tf_type == r.tf_type and self.findings.get(r.import_id):
            notes = "".join(f"# {f.rule} ({f.severity}): {f.title}\n" for f in self.findings[r.import_id])
            notes += "# Reproduced exactly as found. The fix is a separate, approved change.\n"
        self.files[FILES[r.tf_type]].append(notes + resource(tf_type, name, items))
        self.imports.append(import_block(f"{tf_type}.{name}", import_id or r.import_id))

    def run(self) -> dict[str, str]:
        for r in self.inv.resources:
            if r.managed:
                continue  # already in someone's Terraform; importing twice breaks both
            getattr(self, f"_{r.tf_type}")(r)
        out = {name: "\n".join(blocks) for name, blocks in sorted(self.files.items())}
        out["imports.tf"] = "\n".join(self.imports)
        return out

    def _aws_vpc(self, r: Resource) -> None:
        self.emit(r, {"cidr_block": r.attrs["cidr_block"], "enable_dns_hostnames": r.attrs["enable_dns_hostnames"]})

    def _aws_internet_gateway(self, r: Resource) -> None:
        self.emit(r, {"vpc_id": self.ref(r.attrs["vpc_id"])})

    def _aws_subnet(self, r: Resource) -> None:
        a = r.attrs
        self.emit(
            r,
            {
                "vpc_id": self.ref(a["vpc_id"]),
                "cidr_block": a["cidr_block"],
                "availability_zone": a["availability_zone"],
                "map_public_ip_on_launch": a["map_public_ip_on_launch"],
            },
        )

    def _rule(self, kind: str, p: dict[str, Any], own_id: str) -> Block:
        b: dict[str, Any] = {"protocol": p["protocol"], "from_port": p["from_port"], "to_port": p["to_port"]}
        if p["cidr_blocks"]:
            b["cidr_blocks"] = p["cidr_blocks"]
        groups = [g for g in p["security_groups"] if g != own_id]
        if groups:
            b["security_groups"] = self.refs_list(groups)
        if own_id in p["security_groups"]:
            b["self"] = True
        return Block(kind, b)

    def _aws_security_group(self, r: Resource) -> None:
        a = r.attrs
        self.emit(
            r,
            {
                "name": a["group_name"],
                "description": a["description"],
                "vpc_id": self.ref(a["vpc_id"]),
                "ingress": [self._rule("ingress", p, r.import_id) for p in a["ingress"]],
                "egress": [self._rule("egress", p, r.import_id) for p in a["egress"]],
            },
        )

    def _aws_instance(self, r: Resource) -> None:
        a = r.attrs
        self.emit(
            r,
            {
                "ami": a["ami"],
                "instance_type": a["instance_type"],
                "subnet_id": self.ref(a["subnet_id"]),
                "vpc_security_group_ids": self.refs_list(a["vpc_security_group_ids"]),
            },
        )

    def _aws_db_subnet_group(self, r: Resource) -> None:
        self.emit(
            r,
            {
                "name": r.import_id,
                "description": r.attrs["description"],
                "subnet_ids": self.refs_list(r.attrs["subnet_ids"]),
            },
        )

    def _aws_db_instance(self, r: Resource) -> None:
        a = r.attrs
        group = self.ref(a["db_subnet_group_name"], "name")
        self.emit(
            r,
            {
                "identifier": r.import_id,
                "engine": a["engine"],
                "engine_version": a["engine_version"],
                "instance_class": a["instance_class"],
                "allocated_storage": a["allocated_storage"],
                "username": a["username"],
                "db_subnet_group_name": group,
                "vpc_security_group_ids": self.refs_list(a["vpc_security_group_ids"]),
                "publicly_accessible": a["publicly_accessible"],
                "storage_encrypted": a["storage_encrypted"],
                "backup_retention_period": a["backup_retention_period"],
                "deletion_protection": a["deletion_protection"],
                "multi_az": a["multi_az"],
                # Terraform-only safety net: if this resource is ever destroyed,
                # AWS takes a final snapshot first.
                "skip_final_snapshot": False,
                "final_snapshot_identifier": f"{r.import_id}-final",
                # The master password is not in Terraform and never will be: it
                # lives in Secrets Manager and is rotated there.
                "lifecycle": Block("lifecycle", {"ignore_changes": Raw("[password]")}),
            },
        )

    def _aws_s3_bucket(self, r: Resource) -> None:
        a = r.attrs
        self.emit(r, {"bucket": r.import_id})
        bucket = Raw(f"{r.address}.id")
        if a["versioning"] in ("Enabled", "Suspended"):
            self.emit(
                r,
                {
                    "bucket": bucket,
                    "versioning_configuration": Block("versioning_configuration", {"status": a["versioning"]}),
                },
                "aws_s3_bucket_versioning",
            )
        if a["public_access_block"]:
            p = a["public_access_block"]
            self.emit(
                r,
                {
                    "bucket": bucket,
                    "block_public_acls": p["BlockPublicAcls"],
                    "ignore_public_acls": p["IgnorePublicAcls"],
                    "block_public_policy": p["BlockPublicPolicy"],
                    "restrict_public_buckets": p["RestrictPublicBuckets"],
                },
                "aws_s3_bucket_public_access_block",
            )

    def _aws_iam_user(self, r: Resource) -> None:
        self.emit(r, {"name": r.import_id, "path": r.attrs["path"]})
        for arn in r.attrs["policies"]:
            name = f"{r.tf_name}_{slug(arn.rsplit('/', 1)[-1])}"
            self.emit(
                r,
                {"user": Raw(f"{r.address}.name"), "policy_arn": arn},
                "aws_iam_user_policy_attachment",
                name,
                f"{r.import_id}/{arn}",
            )

    def _aws_iam_role(self, r: Resource) -> None:
        doc = json.dumps(r.attrs["assume_role_policy"], sort_keys=True)
        items: dict[str, Any] = {"name": r.import_id, "path": r.attrs["path"]}
        items["assume_role_policy"] = Raw(f"jsonencode({_hcl_object(json.loads(doc))})")
        if r.attrs.get("permissions_boundary"):
            items["permissions_boundary"] = r.attrs["permissions_boundary"]
        self.emit(r, items)

    def _aws_secretsmanager_secret(self, r: Resource) -> None:
        items: dict[str, Any] = {"name": r.attrs["secret_name"], "recovery_window_in_days": 30}
        if r.attrs.get("kms_key_id"):
            items["kms_key_id"] = r.attrs["kms_key_id"]
        self.emit(r, items)


def _hcl_object(v: Any) -> str:
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {_hcl_object(x)}" for k, x in v.items()) + " }"
    if isinstance(v, list):
        return "[" + ", ".join(_hcl_object(x) for x in v) + "]"
    return json.dumps(v)


def write(inv: Inventory, outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    for stale in outdir.glob("*.tf"):
        if stale.name not in ("providers.tf", "backend.tf", "versions.tf"):
            stale.unlink()
    paths = []
    for name, text in Generator(inv).run().items():
        p = outdir / name
        p.write_text("# Generated by takeover codegen from a read-only inventory. Review, then own it.\n\n" + text)
        paths.append(p)
    return paths
