"""A small IAM policy evaluator for testing this repo's own policies.

moto stores IAM, KMS and bucket policies but does not evaluate permissions
boundaries, KMS key policies or SCPs the way AWS does, so the access rules
that protect the owner and the SSNs are checked here instead: explicit Deny
beats Allow, and anything not allowed is denied.

It implements only what the policies in policies/ use (Action/NotAction,
Resource, Principal, and the String/Arn/Bool condition operators) and fails
loudly on anything else, so a policy can't silently pass a test by using a
feature the evaluator ignores. It is a test aid, not a replacement for the
IAM policy simulator or Access Analyzer in a real account.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

POLICIES = Path(__file__).resolve().parents[2] / "policies"


@dataclass
class Request:
    principal: str
    action: str
    resource: str = "*"
    context: dict[str, Any] = field(default_factory=dict)


def render(name: str, **values: str) -> dict[str, Any]:
    """Render a policies/*.json.tftpl file the way Terraform's templatefile would."""
    text = (POLICIES / name).read_text()

    def sub(m: re.Match[str]) -> str:
        key = m.group(1)
        if key not in values:
            raise KeyError(f"{name} needs template value {key!r}")
        return values[key]

    return dict(json.loads(re.sub(r"\$\{(\w+)\}", sub, text)))


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def _glob(pattern: str, value: str, case: bool = False) -> bool:
    if not case:
        pattern, value = pattern.lower(), value.lower()
    return fnmatch.fnmatchcase(value, pattern.replace("[", "[[]"))


def _principal_matches(stmt: dict[str, Any], principal: str) -> bool:
    if "Principal" not in stmt:
        return True  # identity policy: applies to whoever it is attached to
    p = stmt["Principal"]
    if p == "*":
        return True
    if not isinstance(p, dict) or set(p) - {"AWS", "Service"}:
        raise NotImplementedError(f"principal form {p!r}")
    return any(x == "*" or x == principal for x in _list(p.get("AWS", [])) + _list(p.get("Service", [])))


def _condition_holds(cond: dict[str, Any], ctx: dict[str, Any]) -> bool:
    for op, tests in cond.items():
        for key, expected in tests.items():
            present = key in ctx
            actual = ctx.get(key)
            exp = [str(e) for e in _list(expected)]
            if op in ("StringEquals", "ArnEquals"):
                ok = present and str(actual) in exp
            elif op in ("StringLike", "ArnLike"):
                ok = present and any(_glob(e, str(actual), case=True) for e in exp)
            elif op == "StringNotEquals":
                ok = not present or str(actual) not in exp
            elif op in ("ArnNotLike", "StringNotLike"):
                ok = not present or not any(_glob(e, str(actual), case=True) for e in exp)
            elif op == "Bool":
                ok = present and str(actual).lower() in [e.lower() for e in exp]
            else:
                raise NotImplementedError(f"condition operator {op}")
            if not ok:
                return False
    return True


def _applies(stmt: dict[str, Any], req: Request) -> bool:
    if not _principal_matches(stmt, req.principal):
        return False
    if "Action" in stmt:
        if not any(_glob(a, req.action) for a in _list(stmt["Action"])):
            return False
    elif "NotAction" in stmt:
        if any(_glob(a, req.action) for a in _list(stmt["NotAction"])):
            return False
    else:
        raise NotImplementedError("statement without Action/NotAction")
    if "NotResource" in stmt or "NotPrincipal" in stmt:
        raise NotImplementedError("NotResource/NotPrincipal")
    if not any(_glob(r, req.resource, case=True) for r in _list(stmt.get("Resource", "*"))):
        return False
    return _condition_holds(stmt.get("Condition", {}), req.context)


def decide(policy: dict[str, Any], req: Request) -> str:
    """'Deny' (explicit), 'Allow', or 'ImplicitDeny' for one policy."""
    allowed = False
    for stmt in _list(policy["Statement"]):
        if _applies(stmt, req):
            if stmt["Effect"] == "Deny":
                return "Deny"
            allowed = True
    return "Allow" if allowed else "ImplicitDeny"


def allowed_by_all(policies: list[dict[str, Any]], req: Request) -> bool:
    """Every policy must allow (identity AND boundary AND SCP); any deny wins."""
    decisions = [decide(p, req) for p in policies]
    return "Deny" not in decisions and all(d == "Allow" for d in decisions)


def not_denied(policy: dict[str, Any], req: Request) -> bool:
    """For resource policies used only to deny (bucket policies, SCP deny lists)."""
    return decide(policy, req) != "Deny"
