"""signet signs a purpose with an approval rule only when enough listed approvers signed the exact bytes.

This is what stops a taken-over HUMANITY issuer: it can still reach signet, but without real approvers' signatures over
the capability it asks for, signet refuses, and the refusal is in the log.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instance import Instance, cli
from signet.approval import message
from signet.client import SignetRefused, request
from signet.registry import load_registry, public_key_hex
from signet.verify import verifier

CAP = "humanity-capability"
CAP_LABEL = "stack-capability/2\n"
DOMAIN = b"humanity-issuer/approval/1\n"
SUMMARY = hashlib.sha256(b"APPROVE: run test.echo on r1").digest()
SLIP = CAP_LABEL.encode() + b"the signed region of one capability"


def people(n):
    return sorted((Ed25519PrivateKey.generate() for _ in range(n)), key=public_key_hex)


def purposes(listed, quorum=2):
    return {CAP: {"key_id": "cap-1", "label": CAP_LABEL, "allowed_uids": [os.getuid()],
                  "approval": {"domain": DOMAIN.decode(), "approvers": [public_key_hex(k) for k in listed],
                               "quorum": quorum}},
            "zeta-lock-result": {"key_id": "zeta-1", "label": "zeta-lock-result-signature/1\n",
                                 "allowed_uids": [os.getuid()]}}


def approve(key, data=SLIP, summary=SUMMARY):
    return f"{public_key_hex(key)}:{key.sign(message(DOMAIN, data, summary)).hex()}"


@pytest.fixture
def team():
    return people(3)


@pytest.fixture
def live(tmp_path, team):
    inst = Instance(tmp_path, purposes=purposes(team), key_ids={"cap": "cap-1"}).start()
    yield inst
    inst.kill()


def ask(inst, approvals, data=SLIP, summary=SUMMARY):
    return request(inst.socket, CAP, data, approvals=approvals, summary_sha256=summary)


def refused_code(inst, approvals, **kw):
    with pytest.raises(SignetRefused) as caught:
        ask(inst, approvals, **kw)
    return caught.value.code, caught.value.reason


def test_two_listed_approvers_get_a_signature_that_checks_and_the_log_names_them(live, team):
    a, b, _ = team
    signature, seq = ask(live, [approve(a), approve(b)])
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    assert verifier(reg, CAP)(SLIP, signature) is True
    assert reg.approvals[CAP].quorum == 2
    line = live.log_lines()[seq]
    assert line["outcome"] == "signed" and line["approvers"] == ",".join(sorted([public_key_hex(a), public_key_hex(b)]))
    assert cli("verify-log", "--log", str(live.log)).returncode == 0


def test_one_approver_is_not_enough(live, team):
    assert refused_code(live, [approve(team[0])]) == ("not-approved", f"1 listed approver(s) signed these bytes; '{CAP}' needs 2")


def test_no_approvals_at_all_is_refused(live):
    with pytest.raises(SignetRefused) as caught:
        request(live.socket, CAP, SLIP)
    assert caught.value.code == "not-approved"


def test_the_same_approver_twice_counts_once(live, team):
    assert refused_code(live, [approve(team[0]), approve(team[0])])[0] == "not-approved"


def test_an_approver_who_is_not_listed_does_not_count(live, team):
    assert refused_code(live, [approve(team[0]), approve(people(1)[0])])[0] == "not-approved"


def test_approvals_for_other_bytes_or_another_summary_do_not_count(live, team):
    a, b, _ = team
    assert refused_code(live, [approve(a), approve(b, data=SLIP + b"!")])[0] == "not-approved"
    assert refused_code(live, [approve(a), approve(b, summary=b"\x00" * 32)])[0] == "not-approved"


def test_approvals_reused_for_another_capability_do_not_count(live, team):
    a, b, _ = team
    other = CAP_LABEL.encode() + b"a different capability"
    assert refused_code(live, [approve(a), approve(b)], data=other)[0] == "not-approved"


def test_every_refusal_is_in_the_log_and_releases_nothing(live, team):
    refused_code(live, [approve(team[0])])
    lines = live.log_lines()
    assert [line["outcome"] for line in lines] == ["refused"] and lines[0]["code"] == "not-approved"
    assert lines[0]["signature_sha256"] == "" and "approvers" not in lines[0]


def test_a_purpose_without_a_rule_takes_no_approvals(live, team):
    with pytest.raises(SignetRefused) as caught:
        request(live.socket, "zeta-lock-result", b"zeta-lock-result-signature/1\nx", approvals=[approve(team[0])],
                summary_sha256=SUMMARY)
    assert caught.value.code == "malformed"


def test_an_approver_taken_off_the_list_stops_counting_after_a_restart(tmp_path, team):
    a, b, c = team
    inst = Instance(tmp_path, purposes=purposes(team), key_ids={"cap": "cap-1"}).start()
    try:
        ask(inst, [approve(a), approve(b)])
    finally:
        inst.kill()
    doc = json.loads(inst.config.read_text())
    doc["purposes"][CAP]["approval"]["approvers"] = sorted([public_key_hex(a), public_key_hex(c)])
    inst.config.write_text(json.dumps(doc))
    inst.start()
    try:
        with pytest.raises(SignetRefused) as caught:
            ask(inst, [approve(a), approve(b)])
        assert caught.value.code == "not-approved"
        ask(inst, [approve(a), approve(c)])
    finally:
        inst.kill()


def test_an_edited_approvers_field_breaks_the_log(live, team):
    a, b, c = team
    ask(live, [approve(a), approve(b)])
    lines = live.log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["approvers"] = ",".join(sorted([public_key_hex(a), public_key_hex(c)]))
    live.kill()
    live.log.write_text(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
    assert cli("verify-log", "--log", str(live.log)).returncode != 0
