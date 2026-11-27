"""Baseline gaps found by the RACE 9.5 investigation (docs/SIGNET_BASELINE_v1.md), recorded as assertions.

Every test here asserts a weakness that exists at the baseline commit and is still open. Gaps P1 to P3 (fork,
resurrection, version jump) were closed in Step 2 by `signet.trust` and moved to tests/test_trust.py. Each one FAILS the day its gap is closed, and
whoever closes it replaces the assertion with the real test (CLAUDE.md: a recorded gap is an assertion, never a skip).
Nothing here changes signet's behaviour.
"""

import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instance import Instance
from signet.approval import message
from signet.client import SignetRefused, request
from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import next_body, public_key_hex

ZETA = "zeta-lock-result"
ZETA_LABEL = b"zeta-lock-result-signature/1\n"
PURPOSES = {ZETA: ZETA_LABEL, REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}


def _first():
    keys = {name: Ed25519PrivateKey.generate() for name in ("root", "zeta1", "log")}
    current = {REGISTRY_PURPOSE: ("root", public_key_hex(keys["root"])), ZETA: ("zeta1", public_key_hex(keys["zeta1"])),
               LOG_PURPOSE: ("log", public_key_hex(keys["log"]))}
    return keys, next_body(None, PURPOSES, current)


def _with(body, version, zeta_status=None):
    out = {**body, "version": version, "keys": [dict(k) for k in body["keys"]]}
    if zeta_status is not None:
        for k in out["keys"]:
            if k["key_id"] == "zeta1":
                k["status"] = zeta_status
    return out


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


def test_gap_every_refusal_is_written_to_disk_with_no_rate_limit(tmp_path):
    """Any account can connect (the socket is 0666) and every refusal is an fsynced log line. 300 refusals in a row
    are all written; nothing slows or caps them, so one local account can fill the disk and stop all signing."""
    inst = Instance(tmp_path).start()
    try:
        for _ in range(300):
            try:
                request(inst.socket, ZETA, b"no label")
            except SignetRefused:
                pass
    finally:
        inst.kill()
    lines = inst.log_lines()
    assert len(lines) == 300 and all(line["outcome"] == "refused" for line in lines)
    assert inst.log.stat().st_size > 300 * 300
