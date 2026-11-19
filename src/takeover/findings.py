"""Security and resilience findings, computed only from the inventory."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from takeover.inventory import Inventory, Resource

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
REMOTE_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}


@dataclass
class Finding:
    rule: str
    severity: str
    resource: str
    title: str
    fix: str
    resource_id: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _world_open(r: Resource, port: int) -> bool:
    for p in r.attrs["ingress"]:
        covers = p["protocol"] == "-1" or p["from_port"] <= port <= p["to_port"]
        if covers and "0.0.0.0/0" in p["cidr_blocks"]:
            return True
    return False


def evaluate(inv: Inventory) -> list[Finding]:
    out: list[Finding] = []

    def add(rule: str, sev: str, r: Resource | str, title: str, fix: str) -> None:
        name = r if isinstance(r, str) else f"{r.name} ({r.import_id})"
        rid = r if isinstance(r, str) else r.import_id
        out.append(Finding(rule, sev, name, title, fix, rid))

    for sg in inv.of_type("aws_security_group"):
        for port, proto in REMOTE_ADMIN_PORTS.items():
            if _world_open(sg, port):
                add(
                    "TKO-001" if port == 22 else "TKO-002",
                    "critical",
                    sg,
                    f"{proto} ({port}) open to the whole internet",
                    "Remove the rule; reach hosts through SSM Session Manager (IAM-authenticated, logged in CloudTrail).",
                )

    for db in inv.of_type("aws_db_instance"):
        a = db.attrs
        if a["publicly_accessible"]:
            add(
                "TKO-003",
                "high",
                db,
                "Database has a public endpoint",
                "Set publicly_accessible = false; only the app and bridge security groups reach it.",
            )
        if not a["storage_encrypted"]:
            add(
                "TKO-004",
                "high",
                db,
                "Database storage and snapshots are not encrypted",
                "Encryption can't be switched on in place: snapshot, copy the snapshot with a KMS key, restore, cut over in a maintenance window.",
            )
        if a["backup_retention_period"] < 7:
            add(
                "TKO-005",
                "medium",
                db,
                f"Only {a['backup_retention_period']} day(s) of automated backups",
                "Raise retention to at least 14 days and prove it with a quarterly restore test.",
            )
        if not a["deletion_protection"]:
            add(
                "TKO-006",
                "medium",
                db,
                "Deletion protection is off",
                "Turn on deletion_protection; one wrong apply should not be able to drop the system of record.",
            )

    for b in inv.of_type("aws_s3_bucket"):
        a = b.attrs
        pab = a["public_access_block"]
        if not pab or not all(pab.values()):
            add(
                "TKO-007",
                "high",
                b,
                "No S3 public access block",
                "Add aws_s3_bucket_public_access_block with all four settings on.",
            )
        if a["versioning"] != "Enabled":
            add(
                "TKO-008",
                "medium",
                b,
                "Versioning is off, so overwrites and deletes are permanent",
                "Enable versioning with a lifecycle rule for old versions.",
            )

    for u in inv.of_type("aws_iam_user"):
        a = u.attrs
        if ADMIN_POLICY in a["policies"] and a["active_keys"]:
            add(
                "TKO-009",
                "critical",
                u,
                "IAM user with full admin and a long-lived access key",
                "Find where the key is used (CloudTrail, last-used date), move that use to a role, then deactivate and delete the key.",
            )
        if not a["mfa"]:
            add("TKO-010", "high", u, "IAM user without MFA", "Require MFA or replace the user with SSO access.")

    if not inv.account.get("multi_region_trail"):
        add(
            "TKO-011",
            "high",
            "account",
            "No multi-region CloudTrail: there is no record of who changed what",
            "Owner-applied trail to an Object Lock bucket (terraform/guardrails).",
        )

    for i in inv.of_type("aws_instance"):
        if i.attrs.get("metadata_http_tokens") != "required":
            add(
                "TKO-012",
                "medium",
                i,
                "IMDSv1 allowed on the instance",
                "Require IMDSv2 tokens (metadata_options.http_tokens = required) after checking the app's SDK versions.",
            )

    for s in inv.of_type("aws_secretsmanager_secret"):
        if not s.attrs["rotation_enabled"]:
            add(
                "TKO-013",
                "medium",
                s,
                "Secret is never rotated",
                "Enable rotation; for the RDS master password, use RDS-managed rotation.",
            )

    return sorted(out, key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.resource))
