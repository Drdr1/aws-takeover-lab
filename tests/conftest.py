from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from moto import mock_aws


@pytest.fixture
def aws(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """In-process moto, isolated from any real credentials or endpoint."""
    for k in ("AWS_ENDPOINT_URL", "AWS_SESSION_TOKEN", "AWS_PROFILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    with mock_aws():
        yield


@pytest.fixture
def seeded(aws: None) -> dict[str, str]:
    from takeover.seed import seed

    return seed()


os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
