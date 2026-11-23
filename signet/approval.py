"""approval: a purpose that signet signs only when enough listed people have approved the exact bytes.

WHY IT EXISTS

A separate signer stops a caller from stealing a key. It does not stop a taken-over caller from asking for a
signature on bytes that look right (README, threat 13). For most purposes that is the ceiling, because signet does not
understand what it signs. One kind of purpose is different: one where the bytes may only be signed after people
approved them, and the approvals are themselves signatures. The HUMANITY issuer is that case: a capability (a signed
slip that lets the kernel run one action) must not exist unless enough assigned approvers signed for it.

For such a purpose signet checks the approvals itself, before it signs. A taken-over issuer then needs real
approvers' keys, not just the issuer's account, to get a capability.

THE RULE, per purpose (in the config, and published in the signed registry so a checker can see it):

    "approval": {"domain": "humanity-issuer/approval/1\\n",
                 "approvers": ["<64 hex Ed25519 public key>", ...],
                 "quorum": 2}

WHAT AN APPROVER SIGNS, and what signet checks each approval against:

    domain || SHA-256(the bytes signet is asked to sign) || summary_sha256

`summary_sha256` is the SHA-256 of the plain-language summary the approver was shown. The caller sends it with the
request; signet cannot check that the summary was honest, only that the approvers signed that summary for these bytes.

COUNTED: distinct listed approvers whose Ed25519 signature verifies.
An approval from a key that is not listed, or that does not verify, does not count, and does not by itself refuse the
request: the quorum decides. A key listed twice counts once.

THE FLOOR. `quorum` is at least `MIN_QUORUM` (2) whatever the config says, so no one approver, and no caller claiming
an action is minor, can get a signature on their own. A caller may demand more than signet does; signet's number is
only the minimum. Approvers listed are at most `MAX_APPROVERS` (16).

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .names import check_label

MIN_QUORUM = 2
MAX_APPROVERS = 16
_HEX = "0123456789abcdef"


@dataclass(frozen=True)
class Approval:
    domain: bytes
    approvers: Tuple[str, ...]
    quorum: int

    def as_json(self) -> Dict[str, Any]:
        return {"domain": self.domain.decode("ascii"), "approvers": list(self.approvers), "quorum": self.quorum}


def _hex(value: Any, length: int) -> bool:
    return type(value) is str and len(value) == length and all(c in _HEX for c in value)


def check_rule(spec: Any, label: bytes) -> Approval:
    """An approval rule read into an `Approval`, or ValueError naming why. `label` is the purpose's own label."""
    if type(spec) is not dict or set(spec) != {"domain", "approvers", "quorum"}:
        raise ValueError("an approval rule has exactly domain, approvers and quorum")
    domain = check_label(spec["domain"])
    if domain == label:
        raise ValueError("the approval domain must differ from the purpose's label, or an approval could pass for the "
                         "signed thing itself")
    approvers = spec["approvers"]
    if type(approvers) is not list or not 1 <= len(approvers) <= MAX_APPROVERS:
        raise ValueError(f"approvers is a list of 1 to {MAX_APPROVERS} public keys")
    for key in approvers:
        if not _hex(key, 64):
            raise ValueError("an approver is a public key in 64 lowercase hex characters")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
        except ValueError:
            raise ValueError(f"approver {key[:12]}... is not an Ed25519 public key") from None
    if len(set(approvers)) != len(approvers):
        raise ValueError("an approver is listed twice")
    if list(approvers) != sorted(approvers):
        raise ValueError("approvers are listed in sorted order, so one rule has one spelling")
    quorum = spec["quorum"]
    if type(quorum) is not int or quorum < MIN_QUORUM:
        raise ValueError(f"the quorum is a whole number of at least {MIN_QUORUM}")
    if quorum > len(approvers):
        raise ValueError(f"the quorum is {quorum} but only {len(approvers)} approvers are listed: nothing could pass")
    return Approval(domain, tuple(approvers), quorum)


def message(domain: bytes, data: bytes, summary_sha256: bytes) -> bytes:
    """The exact bytes an approver signs for `data`."""
    return domain + hashlib.sha256(data).digest() + summary_sha256


def counted(rule: Approval, data: bytes, summary_sha256: bytes, approvals: Sequence[str]) -> List[str]:
    """The listed approvers (sorted, distinct) whose `"<public key hex>:<signature hex>"` approval verifies."""
    signed = message(rule.domain, data, summary_sha256)
    good = set()
    for item in approvals:
        key, _, sig = item.partition(":")
        if key not in rule.approvers or not _hex(sig, 128) or key in good:
            continue
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(sig), signed)
        except InvalidSignature:
            continue
        good.add(key)
    return sorted(good)
