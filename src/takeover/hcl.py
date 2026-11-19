"""A deliberately small HCL writer: enough for clean, reviewable resource code."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Raw:
    """An expression written as-is, e.g. a reference like aws_vpc.main.id."""

    expr: str


@dataclass(frozen=True)
class Block:
    """A nested block (ingress { ... }) rather than an attribute."""

    name: str
    body: dict[str, Any]


def value(v: Any, indent: int) -> str:
    pad = "  " * indent
    if isinstance(v, Raw):
        return v.expr
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, list):
        if not v:
            return "[]"
        return "[" + ", ".join(value(x, indent) for x in v) + "]"
    if isinstance(v, dict):
        if not v:
            return "{}"
        width = max(len(k) for k in v)
        lines = [f"{pad}  {k.ljust(width)} = {value(x, indent + 1)}" for k, x in sorted(v.items())]
        return "{\n" + "\n".join(lines) + f"\n{pad}}}"
    raise TypeError(f"cannot render {type(v).__name__}")


def body(items: dict[str, Any], indent: int = 1) -> str:
    pad = "  " * indent
    blocks: list[Block] = []
    simple: dict[str, Any] = {}
    for k, v in items.items():
        if isinstance(v, Block):
            blocks.append(v)
        elif isinstance(v, list) and _blocks(v):
            blocks.extend(v)
        else:
            simple[k] = v
    out: list[str] = []
    if simple:
        width = max(len(k) for k in simple)
        out += [f"{pad}{k.ljust(width)} = {value(v, indent)}" for k, v in simple.items()]
    for b in blocks:
        out.append("")
        out.append(f"{pad}{b.name} {{")
        out.append(body(b.body, indent + 1))
        out.append(f"{pad}}}")
    return "\n".join(out)


def _blocks(v: list[Any]) -> bool:
    return bool(v) and all(isinstance(x, Block) for x in v)


def resource(tf_type: str, name: str, items: dict[str, Any]) -> str:
    return f'resource "{tf_type}" "{name}" {{\n{body(items)}\n}}\n'


def import_block(address: str, import_id: str) -> str:
    return f"import {{\n  to = {address}\n  id = {json.dumps(import_id)}\n}}\n"
