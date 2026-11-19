"""Inventory, findings, code generation and plan gates, against in-process moto."""

from __future__ import annotations

import json

import pytest

from takeover import codegen, plans, report
from takeover.findings import evaluate
from takeover.hcl import Block, Raw, resource
from takeover.inventory import Inventory, discover, mark_managed
from takeover.policy_eval import Request, decide


@pytest.fixture
def inv(seeded: dict[str, str]) -> Inventory:
    return discover()


def test_inventory_finds_everything_and_skips_aws_defaults(inv: Inventory, seeded: dict[str, str]) -> None:
    ids = {r.import_id for r in inv.resources}
    expected = {v for k, v in seeded.items()}
    assert expected <= ids
    assert not [r for r in inv.of_type("aws_vpc") if r.attrs["cidr_block"] == "172.31.0.0/16"]
    assert not [r for r in inv.of_type("aws_security_group") if r.attrs["group_name"] == "default"]
    assert len(inv.resources) == 18


def test_inventory_never_reads_secret_values(inv: Inventory) -> None:
    text = inv.to_json()
    assert "change-me-not-a-real-secret" not in text


def test_inventory_round_trips_through_json(inv: Inventory) -> None:
    again = Inventory.from_json(inv.to_json())
    assert [r.address for r in again.resources] == [r.address for r in inv.resources]


def test_findings(inv: Inventory) -> None:
    rules = [f.rule for f in evaluate(inv)]
    assert rules[:3] == ["TKO-001", "TKO-002", "TKO-009"]  # criticals first
    for rule in ("TKO-003", "TKO-004", "TKO-005", "TKO-006", "TKO-007", "TKO-008", "TKO-010", "TKO-011", "TKO-013"):
        assert rule in rules
    assert rules.count("TKO-012") == 2
    # the backups bucket was set up properly and must not be flagged
    assert not [f for f in evaluate(inv) if f.resource_id == "acme-los-backups"]


def test_generated_code_uses_references_not_ids(inv: Inventory) -> None:
    files = codegen.Generator(inv).run()
    sg = files["security_groups.tf"]
    assert "vpc_id      = aws_vpc.los_prod.id" in sg
    assert "security_groups = [aws_security_group.los_web.id, aws_security_group.mismo_bridge.id]" in sg
    assert "sg-" not in sg
    db = files["database.tf"]
    assert "db_subnet_group_name      = aws_db_subnet_group.los_db_subnets.name" in db
    assert "ignore_changes = [password]" in db
    assert "change-me" not in "".join(files.values())


def test_generated_code_flags_findings_inline(inv: Inventory) -> None:
    sg = codegen.Generator(inv).run()["security_groups.tf"]
    assert "# TKO-001 (critical): SSH (22) open to the whole internet" in sg
    assert "# Reproduced exactly as found." in sg


def test_one_import_block_per_resource(inv: Inventory) -> None:
    files = codegen.Generator(inv).run()
    imports = files["imports.tf"].count("import {")
    resources = sum(t.count('resource "') for n, t in files.items() if n != "imports.tf")
    assert imports == resources == 21  # 18 found + versioning, public access block, policy attachment


def test_resources_already_in_terraform_are_not_imported_twice(inv: Inventory) -> None:
    state = {"values": {"root_module": {"resources": [{"values": {"id": "acme-los-backups"}}]}}}
    mark_managed(inv, [state])
    files = codegen.Generator(inv).run()
    assert "acme-los-backups" not in files["imports.tf"]
    assert "acme-los-documents" in files["imports.tf"]


def test_diagram_shows_exposure(inv: Inventory) -> None:
    d = report.diagram(inv)
    assert d.startswith("flowchart LR")
    assert "internet -. 22 .->" in d
    assert "internet -. 3389 .->" in d
    assert "internet -- 443 -->" in d
    assert "-- 5432 -->" in d


def test_hcl_rendering() -> None:
    text = resource(
        "aws_x", "y", {"a": "s", "n": 1, "b": True, "r": Raw("aws_z.w.id"), "blk": Block("lifecycle", {"l": []})}
    )
    assert text.splitlines()[0] == 'resource "aws_x" "y" {'
    assert '  a = "s"' in text and "  r = aws_z.w.id" in text and "  lifecycle {" in text


# --- plan gates --------------------------------------------------------------


def _change(
    address: str, actions: list[str], importing: bool, before: dict, after: dict, rtype: str = "aws_db_instance"
) -> dict:
    change = {"actions": actions, "before": before, "after": after}
    if importing:
        change["importing"] = {"id": "x"}
    return {"address": address, "type": rtype, "change": change}


def test_import_gate_accepts_clean_imports() -> None:
    plan = {"resource_changes": [_change("aws_vpc.a", ["no-op"], True, {}, {}, "aws_vpc")]}
    assert plans.check_import(plan) == {"aws_vpc.a": []}


def test_import_gate_accepts_terraform_only_arguments() -> None:
    plan = {
        "resource_changes": [
            _change(
                "aws_db_instance.db", ["update"], True, {"skip_final_snapshot": True}, {"skip_final_snapshot": False}
            )
        ]
    }
    assert plans.check_import(plan) == {"aws_db_instance.db": ["skip_final_snapshot"]}


@pytest.mark.parametrize(
    "change",
    [
        _change("aws_db_instance.db", ["update"], True, {"publicly_accessible": True}, {"publicly_accessible": False}),
        _change("aws_db_instance.db", ["delete", "create"], True, {}, {"engine": "mysql"}),
        _change("aws_s3_bucket.new", ["create"], False, {}, {"bucket": "x"}, "aws_s3_bucket"),
        _change("aws_instance.gone", ["delete"], False, {"ami": "a"}, {}, "aws_instance"),
    ],
)
def test_import_gate_rejects_anything_that_changes_aws(change: dict) -> None:
    with pytest.raises(plans.UnsafeImport):
        plans.check_import({"resource_changes": [change]})


def test_drift_report_ignores_aws_housekeeping_and_shows_rule_changes() -> None:
    rule = {"protocol": "tcp", "from_port": 5432, "to_port": 5432, "cidr_blocks": [], "security_groups": ["sg-web"]}
    leak = {**rule, "cidr_blocks": ["203.0.113.7/32"], "security_groups": []}
    plan = {
        "resource_drift": [
            {
                "address": "aws_db_instance.db",
                "change": {
                    "actions": ["update"],
                    "before": {"latest_restorable_time": "1"},
                    "after": {"latest_restorable_time": "2"},
                },
            },
            {
                "address": "aws_security_group.db",
                "change": {"actions": ["update"], "before": {"ingress": [rule]}, "after": {"ingress": [leak, rule]}},
            },
        ]
    }
    items = plans.drift(plan)
    assert [i["address"] for i in items] == ["aws_security_group.db"]
    md = plans.drift_markdown(items)
    assert "added: `tcp 5432 from 203.0.113.7/32`" in md
    assert plans.drift_markdown([]).startswith("No drift")


def test_evaluator_refuses_features_it_does_not_implement() -> None:
    policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": "1.2.3.4"}}}
        ]
    }
    with pytest.raises(NotImplementedError):
        decide(policy, Request("p", "s3:GetObject"))


def test_inventory_json_is_stable(inv: Inventory) -> None:
    assert json.loads(inv.to_json())["account_id"] == "123456789012"


# --- the inventory really is read-only ----------------------------------------

# botocore operation names whose IAM action is spelled differently
IAM_ACTION = {
    "s3:ListBuckets": "s3:ListAllMyBuckets",
    "s3:GetPublicAccessBlock": "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketEncryption": "s3:GetEncryptionConfiguration",
}


def test_inventory_calls_only_what_the_readonly_policy_allows(
    seeded: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from takeover import aws, inventory
    from takeover.policy_eval import POLICIES

    calls: set[str] = set()
    real = aws.client

    def recording(service: str):  # type: ignore[no-untyped-def]
        c = real(service)
        c.meta.events.register("before-call.*.*", lambda model, **_: calls.add(f"{service}:{model.name}"))
        return c

    monkeypatch.setattr(inventory, "client", recording)
    inventory.discover()

    policy = json.loads((POLICIES / "inventory-readonly.json").read_text())
    assert calls, "no API calls recorded"
    for call in sorted(calls):
        op = call.split(":")[1]
        assert op.startswith(("Describe", "List", "Get")), f"{call} is not a read"
        action = IAM_ACTION.get(call, call)
        assert decide(policy, Request("inventory", action)) == "Allow", f"{action} not in inventory-readonly.json"
    assert "secretsmanager:GetSecretValue" not in calls
    assert decide(policy, Request("inventory", "secretsmanager:GetSecretValue")) == "Deny"
