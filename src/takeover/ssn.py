"""Application-layer envelope encryption for borrower SSNs.

Each SSN is encrypted with its own AES-256-GCM data key. The data key comes
from KMS (GenerateDataKey) and only its KMS-encrypted form is stored next to
the ciphertext. Decrypting therefore needs a KMS Decrypt call, which the key
policy (policies/ssn-key.json.tftpl) allows only for the LOS app role, and
which CloudTrail records every time.

Both the KMS encryption context and the AES-GCM associated data bind the
ciphertext to one borrower ID, so a sealed SSN copied onto another borrower's
row will not decrypt.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PURPOSE = "borrower-ssn"
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)(\d{4})\b")
# Masking is deliberately looser than validation: anything SSN-shaped,
# including ITINs (9xx) and typos, is hidden from logs.
_SSN_SHAPED = re.compile(r"\b\d{3}-?\d{2}-?(\d{4})\b")


class InvalidSsn(ValueError):
    pass


@dataclass(frozen=True)
class SealedSsn:
    """What the database stores. Safe to log, back up and replicate."""

    ciphertext: str
    data_key: str
    nonce: str
    last4: str

    def as_row(self) -> dict[str, str]:
        return {
            "ssn_ciphertext": self.ciphertext,
            "ssn_data_key": self.data_key,
            "ssn_nonce": self.nonce,
            "ssn_last4": self.last4,
        }


def normalize(ssn: str) -> str:
    m = _SSN.fullmatch(ssn.strip())
    if not m:
        raise InvalidSsn("not a valid SSN")
    return re.sub(r"\D", "", ssn)


class SsnVault:
    def __init__(self, kms: Any, key_id: str) -> None:
        self.kms = kms
        self.key_id = key_id

    @staticmethod
    def _context(borrower_id: str) -> dict[str, str]:
        return {"purpose": PURPOSE, "borrower_id": borrower_id}

    def seal(self, borrower_id: str, ssn: str) -> SealedSsn:
        digits = normalize(ssn)
        key = self.kms.generate_data_key(
            KeyId=self.key_id, KeySpec="AES_256", EncryptionContext=self._context(borrower_id)
        )
        nonce = os.urandom(12)
        ct = AESGCM(key["Plaintext"]).encrypt(nonce, digits.encode(), borrower_id.encode())
        return SealedSsn(
            ciphertext=base64.b64encode(ct).decode(),
            data_key=base64.b64encode(key["CiphertextBlob"]).decode(),
            nonce=base64.b64encode(nonce).decode(),
            last4=digits[-4:],
        )

    def open(self, borrower_id: str, sealed: SealedSsn) -> str:
        plain_key = self.kms.decrypt(
            CiphertextBlob=base64.b64decode(sealed.data_key),
            EncryptionContext=self._context(borrower_id),
            KeyId=self.key_id,
        )["Plaintext"]
        digits = AESGCM(plain_key).decrypt(
            base64.b64decode(sealed.nonce), base64.b64decode(sealed.ciphertext), borrower_id.encode()
        )
        return digits.decode()


def mask(text: str) -> str:
    """Replace anything that looks like an SSN with ***-**-NNNN."""
    return _SSN_SHAPED.sub(lambda m: f"***-**-{m.group(1)}", text)


class RedactSsns(logging.Filter):
    """Attach to every handler so an SSN can't reach a log file by accident."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = mask(record.getMessage())
        record.args = None
        return True
