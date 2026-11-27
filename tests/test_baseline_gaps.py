"""Baseline gaps found by the RACE 9.5 investigation (docs/SIGNET_BASELINE_v1.md), recorded as assertions.

Every test here asserts a weakness that exists at the baseline commit and is still open. Gaps P1 to P3 (fork,
resurrection, version jump) were closed in Step 2 by `signet.trust` and moved to tests/test_trust.py; P5
(unthrottled refusal logging) was closed in Step 5 and moved to tests/test_flood.py. Each one FAILS the day its gap is closed, and
whoever closes it replaces the assertion with the real test (CLAUDE.md: a recorded gap is an assertion, never a skip).
Nothing here changes signet's behaviour.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instance import Instance
from signet.approval import message
from signet.client import request
from signet.registry import public_key_hex


def test_gap_the_same_approvals_get_a_second_signature(tmp_path):
    """Approvals carry no nonce or expiry: sent again, they get the same bytes signed again and a second log line."""
    team = sorted((Ed25519PrivateKey.generate() for _ in range(2)), key=public_key_hex)
    domain = b"humanity-issuer/approval/1\n"
    purposes = {"cap": {"key_id": "cap-1", "label": "stack-capability/2\n", "allowed_uids": [os.getuid()],
                        "approval": {"domain": domain.decode(), "approvers": [public_key_hex(k) for k in team],
                                     "quorum": 2}}}
    inst = Instance(tmp_path, purposes=purposes, key_ids={"cap": "cap-1"}).start()
    try:
        data = b"stack-capability/2\nslip"
        summary = hashlib.sha256(b"summary").digest()
        approvals = [f"{public_key_hex(k)}:{k.sign(message(domain, data, summary)).hex()}" for k in team]
        first, seq1 = request(inst.socket, "cap", data, approvals=approvals, summary_sha256=summary)
        second, seq2 = request(inst.socket, "cap", data, approvals=approvals, summary_sha256=summary)
    finally:
        inst.kill()
    assert first == second and (seq1, seq2) == (0, 1)
