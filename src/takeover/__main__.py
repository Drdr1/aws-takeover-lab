"""Command line: python -m takeover <command>."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from takeover import codegen, plans, report
from takeover.aws import client
from takeover.findings import evaluate
from takeover.inventory import Inventory, discover, mark_managed


def cmd_seed(_: argparse.Namespace) -> None:
    from takeover.seed import seed

    print(json.dumps(seed(), indent=2))


def cmd_assume(a: argparse.Namespace) -> None:
    creds = client("sts").assume_role(RoleArn=a.role_arn, RoleSessionName=a.session)["Credentials"]
    print(
        "export "
        + " ".join(
            f"{k}={shlex.quote(v)}"
            for k, v in (
                ("AWS_ACCESS_KEY_ID", creds["AccessKeyId"]),
                ("AWS_SECRET_ACCESS_KEY", creds["SecretAccessKey"]),
                ("AWS_SESSION_TOKEN", creds["SessionToken"]),
            )
        )
    )


def cmd_inventory(a: argparse.Namespace) -> None:
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    inv = discover()
    if a.tf_state:
        mark_managed(inv, [json.loads(Path(p).read_text()) for p in a.tf_state])
    found = evaluate(inv)
    prefix = f"{a.name}-" if a.name else ""
    (out / f"{prefix}inventory.json").write_text(inv.to_json())
    (out / f"{prefix}findings.json").write_text(json.dumps([f.as_dict() for f in found], indent=2))
    (out / f"{prefix}report.md").write_text(report.markdown(inv, found, a.title))
    (out / f"{prefix}diagram.mmd").write_text(report.diagram(inv))
    print(f"{len(inv.resources)} resources, {len(found)} findings -> {out}")


def cmd_codegen(a: argparse.Namespace) -> None:
    inv = Inventory.from_json(Path(a.inventory).read_text())
    for p in codegen.write(inv, Path(a.outdir)):
        print(p)


def cmd_check_import(a: argparse.Namespace) -> None:
    try:
        imported = plans.check_import(plans.load(a.plan))
    except plans.UnsafeImport as e:
        print(f"UNSAFE IMPORT PLAN:\n{e}", file=sys.stderr)
        raise SystemExit(1) from e
    print(f"import plan is safe: {len(imported)} resources imported; nothing in AWS is created, changed or destroyed")
    for address, attrs in imported.items():
        if attrs:
            print(f"  {address}: Terraform-only arguments set in state ({', '.join(attrs)})")


def cmd_simulate_drift(_: argparse.Namespace) -> None:
    """A colleague 'temporarily' opens Postgres to their home IP in the console."""
    ec2 = client("ec2")
    group = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["los-db"]}])["SecurityGroups"][0]
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"],
        IpPermissions=[
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "203.0.113.7/32"}]}
        ],
    )
    print(f"console change: opened 5432 on {group['GroupId']} to 203.0.113.7/32")


def cmd_drift_report(a: argparse.Namespace) -> None:
    print(plans.drift_markdown(plans.drift(plans.load(a.plan))))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="takeover")
    sub = p.add_subparsers(required=True)
    sub.add_parser("seed").set_defaults(fn=cmd_seed)
    s = sub.add_parser("assume")
    s.add_argument("role_arn")
    s.add_argument("--session", default="takeover-lab")
    s.set_defaults(fn=cmd_assume)
    s = sub.add_parser("inventory")
    s.add_argument("--out", default="out")
    s.add_argument("--name", default="")
    s.add_argument("--title", default="AWS takeover report")
    s.add_argument("--tf-state", action="append", default=[], help="terraform show -json output, for coverage")
    s.set_defaults(fn=cmd_inventory)
    s = sub.add_parser("codegen")
    s.add_argument("inventory")
    s.add_argument("outdir")
    s.set_defaults(fn=cmd_codegen)
    s = sub.add_parser("check-import")
    s.add_argument("plan")
    s.set_defaults(fn=cmd_check_import)
    sub.add_parser("simulate-drift").set_defaults(fn=cmd_simulate_drift)
    s = sub.add_parser("drift-report")
    s.add_argument("plan")
    s.set_defaults(fn=cmd_drift_report)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
