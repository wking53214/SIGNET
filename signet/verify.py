"""verify: the checker a library is handed, built from the signed registry.

`verifier(registry, purpose)` returns a `verify(data, signature) -> bool` callable of the shape beta, CNS and delta
already take (`lock_result_verifier=`, `verify_receipt_signature=`). It answers True only when ALL of these hold:

  - the signature is the envelope `key_id:` + 64 bytes of Ed25519 signature;
  - the registry lists that key id, for THIS purpose, and not as `revoked`;
  - `data` starts with this purpose's label (so bytes meant for another purpose never check here);
  - the Ed25519 signature is over exactly `data` (OpenSSL, through the `cryptography` package).

It answers False, and never raises, for anything else, so a checker fails closed. It reads nothing at call time: the
registry is taken when the verifier is built, and a newer registry means building a new verifier.

`check_checkpoint` checks a signed log checkpoint (see `signet.log`) the same way, under the `signet-log` purpose.

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3).
"""

from __future__ import annotations

from typing import Any, Callable, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .names import CHECKPOINT_LABEL, LOG_PURPOSE, check_name
from .registry import Registry, split_signature
from .strict import FormatError, canonical, loads

CHECKPOINT_SCHEMA = "signet-log-checkpoint/1"


def verifier(registry: Registry, purpose: str) -> Callable[[bytes, bytes], bool]:
    """A fail-closed `verify(data, signature) -> bool` for one purpose. ValueError if the registry lacks the purpose."""
    if not isinstance(registry, Registry):
        raise TypeError(f"expected a signet Registry, got {type(registry).__name__}")
    check_name("purpose", purpose)
    if purpose not in registry.purposes:
        raise ValueError(f"the registry does not list the purpose {purpose!r}")
    label = registry.purposes[purpose]
    trusted = {e.key_id: Ed25519PublicKey.from_public_bytes(bytes.fromhex(e.public_key))
               for e in registry.keys.values() if e.purpose == purpose and e.status != "revoked"}

    def verify(data: bytes, signature: bytes) -> bool:
        try:
            if type(data) is not bytes or not data.startswith(label):
                return False
            key_id, raw = split_signature(signature)
            key = trusted.get(key_id)
            if key is None:
                return False
            key.verify(raw, data)
            return True
        except (InvalidSignature, ValueError, TypeError):
            return False

    return verify


def checkpoint_signing_input(length: int, head: str) -> bytes:
    if type(length) is not int or length < 0 or type(head) is not str or len(head) != 64:
        raise ValueError("a checkpoint is a length of at least 0 and a 64 hex character head")
    return CHECKPOINT_LABEL + canonical({"schema": CHECKPOINT_SCHEMA, "length": length, "head": head})


def check_checkpoint(text: "bytes | str", registry: Registry) -> Tuple[int, str]:
    """`(length, head)` from a checkpoint file whose signature checks under the registry's `signet-log` keys, or
    ValueError. A checkpoint says the log had this many entries ending in this head when signet signed it."""
    try:
        doc: Any = loads(text)
    except FormatError as exc:
        raise ValueError(f"the checkpoint is not strict JSON: {exc}") from None
    if set(doc) != {"schema", "length", "head", "signature"} or doc["schema"] != CHECKPOINT_SCHEMA \
            or type(doc["signature"]) is not str:
        raise ValueError("a checkpoint has exactly schema, length, head and signature")
    data = checkpoint_signing_input(doc["length"], doc["head"])
    try:
        signature = bytes.fromhex(doc["signature"])
    except ValueError:
        raise ValueError("the checkpoint signature is not hex") from None
    if not verifier(registry, LOG_PURPOSE)(data, signature):
        raise ValueError("the checkpoint signature does not check out under the registry's signet-log keys")
    return doc["length"], doc["head"]
