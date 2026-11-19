"""Read `terraform show -json` plans: import safety gate and drift report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# Arguments that exist only in Terraform: they steer what the provider does on
# a later destroy or apply, but are not stored in AWS, so an import can't read
# them back. Setting them during an import changes Terraform state only and
# makes no AWS API call. Anything outside this list blocks the import.
STATE_ONLY = {
    "aws_db_instance": {
        "apply_immediately",
        "skip_final_snapshot",
        "final_snapshot_identifier",
        "delete_automated_backups",
    },
    "aws_secretsmanager_secret": {"recovery_window_in_days", "force_overwrite_replica_secret"},
    "aws_s3_bucket": {"force_destroy"},
}


class UnsafeImport(Exception):
    pass


def load(path: str | Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(Path(path).read_text())
    return data


def check_import(plan: dict[str, Any]) -> dict[str, list[str]]:
    """Fail unless every planned change is a pure import with no diff.

    An import plan that also creates, updates, replaces or destroys anything
    means the generated code does not match reality, and applying it would
    change production during what is supposed to be a read-only step.
    """
    imported: dict[str, list[str]] = {}
    problems: list[str] = []
    for rc in plan.get("resource_changes", []):
        change = rc["change"]
        actions = change["actions"]
        if change.get("importing") is not None:
            diff = _diff(change.get("before") or {}, change.get("after") or {})
            harmless = STATE_ONLY.get(rc["type"], set())
            if actions == ["no-op"] or (actions == ["update"] and diff and set(diff) <= harmless):
                imported[rc["address"]] = diff if actions == ["update"] else []
                continue
            problems.append(f"{rc['address']}: import would also {'/'.join(actions)} ({', '.join(diff) or 'unknown'})")
        elif actions != ["no-op"]:
            problems.append(f"{rc['address']}: {'/'.join(actions)} outside an import")
    if problems:
        raise UnsafeImport("\n".join(problems))
    return imported


def _diff(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    keys = sorted(set(before) | set(after))
    return [k for k in keys if before.get(k) != after.get(k) and k not in ("tags_all",)]


# Attributes AWS changes on its own; a difference here is not someone's edit.
VOLATILE = {"latest_restorable_time", "last_modified", "status", "tags_all"}


def drift(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Resources whose real state no longer matches the last applied state."""
    out = []
    for rd in plan.get("resource_drift", []):
        change = rd["change"]
        before, after = change.get("before") or {}, change.get("after") or {}
        attrs: dict[str, Any] = {}
        for k in _diff(before, after):
            if k in VOLATILE:
                continue
            was, now = before.get(k), after.get(k)
            if isinstance(was, list) and isinstance(now, list):
                attrs[k] = {"added": [x for x in now if x not in was], "removed": [x for x in was if x not in now]}
            else:
                attrs[k] = {"was": was, "now": now}
        if attrs:
            out.append({"address": rd["address"], "actions": change["actions"], "attributes": attrs})
    return out


def _describe(item: Any) -> str:
    """Render a security group rule the way a person reads one."""
    if isinstance(item, dict) and "from_port" in item:
        port = (
            str(item["from_port"]) if item["from_port"] == item["to_port"] else f"{item['from_port']}-{item['to_port']}"
        )
        sources = item.get("cidr_blocks", []) + item.get("security_groups", [])
        proto = "all" if item.get("protocol") == "-1" else item.get("protocol")
        return f"{proto} {port} from {', '.join(sources) or 'self'}"
    return json.dumps(item, sort_keys=True)


def drift_markdown(items: list[dict[str, Any]]) -> str:
    if not items:
        return "No drift: the account matches the Terraform state.\n"
    lines = [
        f"# Drift detected: {len(items)} resource(s) changed outside Terraform",
        "",
        "Someone changed these in the console or CLI. Either bring the change into code",
        "through a pull request, or revert it with `terraform apply`. CloudTrail shows who.",
        "",
    ]
    for item in items:
        lines.append(f"## `{item['address']}` ({'/'.join(item['actions'])})")
        lines.append("")
        for attr, d in item["attributes"].items():
            lines.append(f"- **{attr}**")
            if "added" in d:
                lines += [f"  - added: `{_describe(x)}`" for x in d["added"]]
                lines += [f"  - removed: `{_describe(x)}`" for x in d["removed"]]
            else:
                lines.append(f"  - was: `{json.dumps(d['was'], sort_keys=True)}`")
                lines.append(f"  - now: `{json.dumps(d['now'], sort_keys=True)}`")
        lines.append("")
    return "\n".join(lines)
