from __future__ import annotations

import json
import logging

import pytest
from cryptography.exceptions import InvalidTag

from takeover.aws import client
from takeover.ssn import InvalidSsn, RedactSsns, SealedSsn, SsnVault, mask, normalize

SSN = "123-45-6789"


@pytest.fixture
def vault(aws: None) -> SsnVault:
    kms = client("kms")
    key = kms.create_key(Description="ssn", Tags=[{"TagKey": "Protection", "TagValue": "owner-only"}])
    return SsnVault(kms, key["KeyMetadata"]["KeyId"])


def test_round_trip(vault: SsnVault) -> None:
    sealed = vault.seal("B-1001", SSN)
    assert vault.open("B-1001", sealed) == "123456789"
    assert sealed.last4 == "6789"


def test_database_row_never_contains_the_ssn(vault: SsnVault) -> None:
    row = json.dumps(vault.seal("B-1001", SSN).as_row())
    assert "123456789" not in row
    assert "123-45-6789" not in row


def test_each_seal_uses_a_fresh_data_key_and_nonce(vault: SsnVault) -> None:
    a, b = vault.seal("B-1001", SSN), vault.seal("B-1001", SSN)
    assert a.ciphertext != b.ciphertext
    assert a.data_key != b.data_key


def test_sealed_ssn_copied_to_another_borrower_does_not_decrypt(vault: SsnVault) -> None:
    sealed = vault.seal("B-1001", SSN)
    with pytest.raises(Exception):  # KMS rejects the wrong encryption context
        vault.open("B-2002", sealed)


def test_tampered_ciphertext_is_rejected(vault: SsnVault) -> None:
    sealed = vault.seal("B-1001", SSN)
    raw = bytearray(__import__("base64").b64decode(sealed.ciphertext))
    raw[0] ^= 1
    forged = SealedSsn(__import__("base64").b64encode(bytes(raw)).decode(), sealed.data_key, sealed.nonce, sealed.last4)
    with pytest.raises(InvalidTag):
        vault.open("B-1001", forged)


@pytest.mark.parametrize(
    "bad", ["000-12-3456", "666-12-3456", "900-12-3456", "123-00-4567", "123-45-0000", "12345678", "abc"]
)
def test_invalid_ssns_are_refused(bad: str) -> None:
    with pytest.raises(InvalidSsn):
        normalize(bad)


def test_mask() -> None:
    assert mask("borrower 123-45-6789 and 987654321 applied") == "borrower ***-**-6789 and ***-**-4321 applied"
    assert mask("loan 2026-11-20 amount 450000") == "loan 2026-11-20 amount 450000"


def test_log_filter_redacts(caplog: pytest.LogCaptureFixture) -> None:
    log = logging.getLogger("los.test")
    log.addFilter(RedactSsns())
    with caplog.at_level(logging.INFO, logger="los.test"):
        log.info("underwriting borrower %s", SSN)
    assert "123-45-6789" not in caplog.text
    assert "***-**-6789" in caplog.text
