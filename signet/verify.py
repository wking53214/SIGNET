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
`read_checkpoint` does the same and returns every field. A checkpoint is one of two schemas:

  - `signet-log-checkpoint/1`: length and head.
  - `signet-log-checkpoint/2`: length, head, `at_ms` (signet's clock when it signed) and `previous`, the SHA-256 of
    the previous checkpoint file's exact bytes ("" for the first). Each checkpoint then names the one before it, so a
    published sequence with one removed, swapped or replaced shows, and an outside witness's time can be compared
    with `at_ms` (signet_anchor).

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .names import CHECKPOINT_LABEL, LOG_PURPOSE, check_name
from .registry import Registry, split_signature
from .strict import FormatError, canonical, loads

CHECKPOINT_SCHEMA = "signet-log-checkpoint/1"
CHECKPOINT_SCHEMA_2 = "signet-log-checkpoint/2"
_HEX = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Checkpoint:
    schema: str
    length: int
    head: str
    key_id: str
    at_ms: Optional[int] = None  # schema 2 only
    previous: Optional[str] = None  # schema 2 only: "" for the first, else 64 hex


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


def checkpoint_signing_input(length: int, head: str, *, at_ms: Optional[int] = None,
                             previous: Optional[str] = None) -> bytes:
    """The bytes the log key signs. With `at_ms` and `previous` (both or neither), a schema 2 checkpoint."""
    if type(length) is not int or length < 0 or type(head) is not str or len(head) != 64:
        raise ValueError("a checkpoint is a length of at least 0 and a 64 hex character head")
    if (at_ms is None) != (previous is None):
        raise ValueError("at_ms and previous go together (schema 2)")
    if at_ms is None:
        return CHECKPOINT_LABEL + canonical({"schema": CHECKPOINT_SCHEMA, "length": length, "head": head})
    if type(at_ms) is not int or at_ms < 0 or type(previous) is not str \
            or not (previous == "" or (len(previous) == 64 and set(previous) <= _HEX)):
        raise ValueError("a schema 2 checkpoint has a whole at_ms and previous that is empty or 64 lowercase hex")
    return CHECKPOINT_LABEL + canonical({"schema": CHECKPOINT_SCHEMA_2, "length": length, "head": head,
                                         "at_ms": at_ms, "previous": previous})


def read_checkpoint(text: "bytes | str", registry: Registry) -> Checkpoint:
    """Every field of a checkpoint whose signature checks under the registry's `signet-log` keys, or ValueError."""
    try:
        doc: Any = loads(text)
    except FormatError as exc:
        raise ValueError(f"the checkpoint is not strict JSON: {exc}") from None
    v1, v2 = {"schema", "length", "head", "signature"}, {"schema", "length", "head", "at_ms", "previous", "signature"}
    if not ((set(doc) == v1 and doc["schema"] == CHECKPOINT_SCHEMA)
            or (set(doc) == v2 and doc["schema"] == CHECKPOINT_SCHEMA_2)) or type(doc["signature"]) is not str:
        raise ValueError("a checkpoint has exactly the fields of signet-log-checkpoint/1 or /2")
    extra = {"at_ms": doc["at_ms"], "previous": doc["previous"]} if doc["schema"] == CHECKPOINT_SCHEMA_2 else {}
    data = checkpoint_signing_input(doc["length"], doc["head"], **extra)
    try:
        signature = bytes.fromhex(doc["signature"])
    except ValueError:
        raise ValueError("the checkpoint signature is not hex") from None
    if not verifier(registry, LOG_PURPOSE)(data, signature):
        raise ValueError("the checkpoint signature does not check out under the registry's signet-log keys")
    key_id, _raw = split_signature(signature)
    return Checkpoint(doc["schema"], doc["length"], doc["head"], key_id, extra.get("at_ms"), extra.get("previous"))


def check_checkpoint(text: "bytes | str", registry: Registry) -> Tuple[int, str]:
    """`(length, head)` from a checkpoint file whose signature checks under the registry's `signet-log` keys, or
    ValueError. A checkpoint says the log had this many entries ending in this head when signet signed it."""
    cp = read_checkpoint(text, registry)
    return cp.length, cp.head
