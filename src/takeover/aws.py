"""boto3 session helpers.

Everything in this lab talks to whatever endpoint AWS_ENDPOINT_URL points at.
In CI and locally that is a moto server; against a real account you unset it.
"""

from __future__ import annotations

import os
from typing import Any

import boto3

REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


def client(service: str) -> Any:
    endpoint = os.environ.get("AWS_ENDPOINT_URL") or None
    # Typed as Any on purpose: one helper for every service keeps call sites short.
    factory: Any = boto3.client
    return factory(service, region_name=REGION, endpoint_url=endpoint)
