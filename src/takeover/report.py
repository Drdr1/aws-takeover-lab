"""Human-readable outputs: the takeover report and an architecture diagram."""

from __future__ import annotations

from collections import Counter

from takeover.findings import Finding
from takeover.inventory import Inventory, Resource


def _label(r: Resource) -> str:
    return f"{r.name}" if r.name == r.import_id else f"{r.name}<br/>{r.import_id}"


def diagram(inv: Inventory) -> str:
    lines = ["flowchart LR", '  internet(("Internet"))']
    node = {r.import_id: f"n{i}" for i, r in enumerate(inv.resources)}
    instances_by_subnet: dict[str, list[Resource]] = {}
    for i in inv.of_type("aws_instance"):
        instances_by_subnet.setdefault(i.attrs["subnet_id"], []).append(i)
    db_by_group = {g.import_id: g for g in inv.of_type("aws_db_subnet_group")}
    dbs = inv.of_type("aws_db_instance")

    for vpc in inv.of_type("aws_vpc"):
        lines.append(f'  subgraph {node[vpc.import_id]}["VPC {vpc.name} {vpc.attrs["cidr_block"]}"]')
        for s in inv.of_type("aws_subnet"):
            if s.attrs["vpc_id"] != vpc.import_id:
                continue
            lines.append(f'    subgraph {node[s.import_id]}["{s.name} {s.attrs["cidr_block"]}"]')
            for inst in instances_by_subnet.get(s.import_id, []):
                lines.append(
                    f'      {node[inst.import_id]}["{_label(inst)}<br/>{inst.attrs["platform"]} {inst.attrs["instance_type"]}"]'
                )
            lines.append("    end")
        for db in dbs:
            group = db_by_group.get(db.attrs["db_subnet_group_name"])
            if group and any(sid in node for sid in group.attrs["subnet_ids"]):
                lines.append(
                    f'    {node[db.import_id]}[("{db.name}<br/>{db.attrs["engine"]} {db.attrs["engine_version"]}")]'
                )
        lines.append("  end")

    groups = {g.import_id: g for g in inv.of_type("aws_security_group")}
    members: dict[str, list[str]] = {}
    for i in inv.of_type("aws_instance"):
        for g in i.attrs["vpc_security_group_ids"]:
            members.setdefault(g, []).append(node[i.import_id])
    for db in dbs:
        for g in db.attrs["vpc_security_group_ids"]:
            members.setdefault(g, []).append(node[db.import_id])

    for gid, g in groups.items():
        for rule in g.attrs["ingress"]:
            port = (
                str(rule["from_port"])
                if rule["from_port"] == rule["to_port"]
                else f"{rule['from_port']}-{rule['to_port']}"
            )
            for target in members.get(gid, []):
                if "0.0.0.0/0" in rule["cidr_blocks"]:
                    style = "-. " if rule["from_port"] in (22, 3389) else "-- "
                    lines.append(f"  internet {style}{port} {'.->' if style == '-. ' else '-->'} {target}")
                for src_group in rule["security_groups"]:
                    for src in members.get(src_group, []):
                        lines.append(f"  {src} -- {port} --> {target}")
    for u in inv.of_type("aws_s3_bucket"):
        lines.append(f'  {node[u.import_id]}[/"s3: {u.name}"/]')
    return "\n".join(lines) + "\n"


def markdown(inv: Inventory, findings: list[Finding], title: str) -> str:
    counts = Counter(f.severity for f in findings)
    managed = [r for r in inv.resources if r.managed]
    unmanaged = [r for r in inv.resources if not r.managed]
    out = [
        f"# {title}",
        "",
        f"Account `{inv.account_id}`, region `{inv.region}`. Collected with read-only calls only.",
        "",
        "| | |",
        "|---|---|",
        f"| Resources found | {len(inv.resources)} |",
        f"| Already in Terraform | {len(managed)} |",
        f"| Not in Terraform | {len(unmanaged)} |",
        f"| Findings | {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium |",
        f"| CloudTrail | {', '.join(inv.account.get('cloudtrail_trails') or []) or 'none'} |",
        "",
        "## Findings",
        "",
        "Nothing here is changed without a written change request and the owner's approval.",
        "",
        "| Rule | Severity | Resource | Finding | Proposed fix |",
        "|---|---|---|---|---|",
    ]
    out += [f"| {f.rule} | {f.severity} | {f.resource} | {f.title} | {f.fix} |" for f in findings]
    out += ["", "## Inventory", "", "| Type | Name | ID | Terraform |", "|---|---|---|---|"]
    for r in sorted(inv.resources, key=lambda r: (r.tf_type, r.name)):
        out.append(f"| `{r.tf_type}` | {r.name} | `{r.import_id}` | {'managed' if r.managed else 'not managed'} |")
    out += ["", "## Diagram", "", "```mermaid", diagram(inv).rstrip(), "```", ""]
    return "\n".join(out)
