"""An approval rule with max_age_ms: an approval counts only while it is fresh (threat model T10).

Approvers sign the time they approved with the bytes; signet counts the approval only from that time until max_age_ms
later (and up to a minute early, for clock drift), on its own clock. A rule without max_age_ms is unchanged and never
expires; that gap stays asserted in `test_baseline_gaps.py`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from instance import Instance
from signet.approval import CLOCK_SKEW_MS, MAX_AGE_LIMIT_MS, check_rule, counted, message
from signet.client import SignetRefused, request
from signet.config import ConfigError, parse
from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import check_body, next_body, public_key_hex

CAP = "humanity-capability"
CAP_LABEL = "stack-capability/2\n"
DOMAIN = b"humanity-issuer/approval/1\n"
SUMMARY = hashlib.sha256(b"APPROVE: run test.echo on r1").digest()
SLIP = CAP_LABEL.encode() + b"the signed region of one capability"
AGE = 60_000


def people(n):
    return sorted((Ed25519PrivateKey.generate() for _ in range(n)), key=public_key_hex)


def spec(team, max_age=AGE):
    out = {"domain": DOMAIN.decode(), "approvers": [public_key_hex(k) for k in team], "quorum": 2}
    if max_age is not None:
        out["max_age_ms"] = max_age
    return out


def timed(key, at, data=SLIP, summary=SUMMARY):
    return f"{public_key_hex(key)}:{at}:{key.sign(message(DOMAIN, data, summary, at)).hex()}"


def untimed(key, data=SLIP, summary=SUMMARY):
    return f"{public_key_hex(key)}:{key.sign(message(DOMAIN, data, summary)).hex()}"


def now_ms():
    return int(time.time() * 1000)


# The rule itself.


def test_a_rule_with_max_age_reads_and_is_published_as_written():
    team = people(3)
    rule = check_rule(spec(team), CAP_LABEL.encode())
    assert rule.max_age_ms == AGE and rule.as_json()["max_age_ms"] == AGE
    assert "max_age_ms" not in check_rule(spec(team, None), CAP_LABEL.encode()).as_json()


@pytest.mark.parametrize("bad", [0, -1, MAX_AGE_LIMIT_MS + 1, 1.5, "60000", True, None])
def test_a_max_age_out_of_range_or_not_a_whole_number_is_refused(bad):
    s = spec(people(3))
    s["max_age_ms"] = bad
    with pytest.raises(ValueError, match="max_age_ms"):
        check_rule(s, CAP_LABEL.encode())


def test_a_config_with_a_bad_max_age_refuses_to_load():
    cfg = {"schema": "signet-config/1", "socket": "/run/s.sock", "keys_dir": "/k", "log": "/l",
           "registry_key_id": "root", "log_key_id": "log",
           "purposes": {CAP: {"key_id": "cap", "label": CAP_LABEL, "allowed_uids": [1],
                              "approval": spec(people(3), 0)}}}
    with pytest.raises(ConfigError):
        parse(json.dumps(cfg))


def test_the_signed_registry_carries_max_age_and_reads_back():
    team = people(3)
    labels = {CAP: CAP_LABEL.encode(), REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}
    root, log, cap = (public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))
    body = next_body(None, labels, {REGISTRY_PURPOSE: ("root-1", root), LOG_PURPOSE: ("log-1", log),
                                    CAP: ("cap-1", cap)}, approvals={CAP: check_rule(spec(team), labels[CAP])})
    assert body["purposes"][CAP]["approval"]["max_age_ms"] == AGE
    assert check_body(body).approvals[CAP].max_age_ms == AGE


# Counting, on a given clock.


def test_counting_follows_the_window_on_the_given_clock():
    team = people(3)
    rule = check_rule(spec(team), CAP_LABEL.encode())
    t = 1_800_000_000_000
    two = lambda at: [timed(team[0], at), timed(team[1], at)]  # noqa: E731
    assert len(counted(rule, SLIP, SUMMARY, two(t), now_ms=t)) == 2
    assert len(counted(rule, SLIP, SUMMARY, two(t - AGE), now_ms=t)) == 2, "exactly max_age old still counts"
    assert counted(rule, SLIP, SUMMARY, two(t - AGE - 1), now_ms=t) == [], "one ms past max_age does not"
    assert len(counted(rule, SLIP, SUMMARY, two(t + CLOCK_SKEW_MS), now_ms=t)) == 2, "a minute of drift is allowed"
    assert counted(rule, SLIP, SUMMARY, two(t + CLOCK_SKEW_MS + 1), now_ms=t) == [], "further in the future is not"


def test_a_time_the_approver_did_not_sign_does_not_count():
    team = people(3)
    rule = check_rule(spec(team), CAP_LABEL.encode())
    t = 1_800_000_000_000
    old = timed(team[0], t - 10 * AGE)
    key, _, sig = old.split(":")
    moved = f"{key}:{t}:{sig}"  # a fresh time pasted onto an old approval
    assert counted(rule, SLIP, SUMMARY, [moved, timed(team[1], t)], now_ms=t) == [public_key_hex(team[1])]


@pytest.mark.parametrize("text", ["", "01", "-5", "1e3", "1" * 16, " 5"])
def test_a_malformed_time_does_not_count(text):
    team = people(3)
    rule = check_rule(spec(team), CAP_LABEL.encode())
    key = public_key_hex(team[0])
    assert counted(rule, SLIP, SUMMARY, [f"{key}:{text}:{'00' * 64}"], now_ms=1_800_000_000_000) == []


def test_untimed_approvals_do_not_count_under_max_age_and_timed_ones_do_not_count_without_it():
    team = people(3)
    t = 1_800_000_000_000
    timed_rule = check_rule(spec(team), CAP_LABEL.encode())
    plain_rule = check_rule(spec(team, None), CAP_LABEL.encode())
    assert counted(timed_rule, SLIP, SUMMARY, [untimed(team[0]), untimed(team[1])], now_ms=t) == []
    assert counted(plain_rule, SLIP, SUMMARY, [timed(team[0], t), timed(team[1], t)]) == []


def test_a_rule_with_max_age_is_never_counted_without_a_clock():
    rule = check_rule(spec(people(3)), CAP_LABEL.encode())
    with pytest.raises(ValueError, match="now_ms"):
        counted(rule, SLIP, SUMMARY, [])


# A running signet.


@pytest.fixture
def team():
    return people(3)


@pytest.fixture
def live(tmp_path, team):
    purposes = {CAP: {"key_id": "cap-1", "label": CAP_LABEL, "allowed_uids": [os.getuid()],
                      "approval": spec(team)}}
    inst = Instance(tmp_path, purposes=purposes, key_ids={"cap": "cap-1"}).start()
    yield inst
    inst.kill()


def ask(inst, approvals):
    return request(inst.socket, CAP, SLIP, approvals=approvals, summary_sha256=SUMMARY)


def test_live_fresh_timed_approvals_are_signed(live, team):
    now = now_ms()
    signature, _ = ask(live, [timed(team[0], now), timed(team[2], now)])
    assert signature


def test_live_approvals_collected_and_left_unused_stop_working(live, team):
    stale = now_ms() - AGE - 5_000
    with pytest.raises(SignetRefused) as caught:
        ask(live, [timed(team[0], stale), timed(team[1], stale)])
    assert caught.value.code == "not-approved"
    lines = live.log_lines()
    assert lines[-1]["outcome"] == "refused" and lines[-1]["code"] == "not-approved"


def test_live_approvals_dated_in_the_future_are_refused(live, team):
    later = now_ms() + CLOCK_SKEW_MS + 60_000
    with pytest.raises(SignetRefused) as caught:
        ask(live, [timed(team[0], later), timed(team[1], later)])
    assert caught.value.code == "not-approved"


def test_live_untimed_approvals_are_refused_under_max_age(live, team):
    with pytest.raises(SignetRefused) as caught:
        ask(live, [untimed(team[0]), untimed(team[1])])
    assert caught.value.code == "not-approved"


def test_live_the_longest_timed_approval_fits_the_request_limit(live, team):
    at = 10**15 - 1  # 15 digits, far in the future: it fits the frame check and then does not count
    approval = timed(team[0], at)
    assert len(approval) == 64 + 1 + 15 + 1 + 128
    with pytest.raises(SignetRefused) as caught:
        ask(live, [approval, timed(team[1], at)])
    assert caught.value.code == "not-approved", "a long approval is counted (and refused as stale), not malformed"
