"""Baseline gaps found by the RACE 9.5 investigation (docs/SIGNET_BASELINE_v1.md), recorded as assertions.

Every test here asserts a weakness that exists at the baseline commit. Each one FAILS the day its gap is closed, and
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
from signet.registry import load_registry, next_body, public_key_hex, sign_registry
from signet.verify import verifier

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


def test_gap_two_different_registries_with_one_version_are_both_accepted():
    """Registry fork: a checker that remembers only the highest version cannot tell two version-2 files apart."""
    keys, body = _first()
    pin = public_key_hex(keys["root"])
    a = load_registry(sign_registry(_with(body, 2), keys["root"], "root"), pin, min_version=2)
    b = load_registry(sign_registry(_with(body, 2, "revoked"), keys["root"], "root"), pin, min_version=2)
    assert a.version == b.version == 2 and a.body() != b.body()


def test_gap_a_checker_accepts_a_registry_that_brings_a_revoked_key_back():
    """Revocation is final only in `next_body`, the writer. A checker given a newer signed file does not compare it
    with what it accepted before, so a root-signed version 3 can make a version-2 revoked key current again."""
    keys, body = _first()
    pin = public_key_hex(keys["root"])
    v2 = load_registry(sign_registry(_with(body, 2, "revoked"), keys["root"], "root"), pin, min_version=2)
    v3 = load_registry(sign_registry(_with(v2.body(), 3, "current"), keys["root"], "root"), pin, min_version=2)
    data = ZETA_LABEL + b"{}"
    sig = b"zeta1:" + keys["zeta1"].sign(data)
    assert not verifier(v2, ZETA)(data, sig)
    assert verifier(v3, ZETA)(data, sig)


def test_gap_a_checker_accepts_any_jump_in_version():
    """A registry may jump from version 1 to version 1000; a checker that then remembers 1000 refuses every honest
    version after a compromise until someone resets it by hand (docs/KEY_RECOVERY_v1.md, case 4)."""
    keys, body = _first()
    pin = public_key_hex(keys["root"])
    assert load_registry(sign_registry(_with(body, 1000), keys["root"], "root"), pin, min_version=2).version == 1000


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
