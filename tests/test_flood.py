"""Flood limits (RACE 9.5, Step 5): a connection cap answered `busy`, a per-account refusal budget with summary lines,
and a disk floor. Baseline probes P5 and P6 (docs/SIGNET_BASELINE_v1.md) were the unthrottled versions of these.
A signature is never suppressed by any of them."""

from __future__ import annotations

import json
import os
import socket
import time

import pytest

from instance import ZETA_LABEL, Instance
from signet.client import SignetRefused, request
from signet.config import ConfigError, parse
from signet.log import verify_file
from signet.server import RefusalBudget

ZETA = ZETA_LABEL.encode()


def with_limits(tmp_path, **limits):
    inst = Instance(tmp_path)
    doc = json.loads(inst.config.read_text())
    doc.update(limits)
    inst.config.write_text(json.dumps(doc))
    return inst


def refuse(inst, n):
    codes = []
    for _ in range(n):
        try:
            request(inst.socket, "zeta-lock-result", b"no label")
        except SignetRefused as exc:
            codes.append(exc.code)
    return codes


def test_over_budget_refusals_are_answered_counted_and_summarised(tmp_path):
    inst = with_limits(tmp_path, refusal_budget={"per_account": 50, "window_ms": 600000}).start()
    codes = refuse(inst, 300)
    inst.stop()  # SIGTERM: the open window's count is written as one summary line
    assert codes == ["wrong-label"] * 300, "every caller still hears why"
    lines = inst.log_lines()
    single = [e for e in lines if e["code"] == "wrong-label"]
    summary = [e for e in lines if e["code"] == "suppressed"]
    assert len(single) == 50 and len(summary) == 1
    assert summary[0]["suppressed"] == 250 and summary[0]["uid"] == os.getuid()
    assert verify_file(inst.log)[0] == 51


def test_a_signature_is_never_suppressed(tmp_path):
    inst = with_limits(tmp_path, refusal_budget={"per_account": 5, "window_ms": 600000}).start()
    try:
        refuse(inst, 20)
        sig, seq = request(inst.socket, "zeta-lock-result", ZETA + b"still signed")
    finally:
        inst.kill()
    signed = [e for e in inst.log_lines() if e["outcome"] == "signed"]
    assert len(signed) == 1 and signed[0]["seq"] == seq


def test_the_summary_is_written_when_the_window_ends_while_signet_runs(tmp_path):
    inst = with_limits(tmp_path, refusal_budget={"per_account": 3, "window_ms": 1000}).start()
    try:
        refuse(inst, 10)
        deadline = time.time() + 15
        while time.time() < deadline and not any(e["code"] == "suppressed" for e in inst.log_lines()):
            time.sleep(0.2)
    finally:
        inst.kill()
    summary = [e for e in inst.log_lines() if e["code"] == "suppressed"]
    assert summary and summary[0]["suppressed"] == 7


def test_below_the_disk_floor_refusals_are_counted_and_signatures_still_written(tmp_path):
    inst = with_limits(tmp_path, min_free_bytes=2**53 - 1).start()  # no disk has this much free
    try:
        assert refuse(inst, 10) == ["wrong-label"] * 10
        request(inst.socket, "zeta-lock-result", ZETA + b"signed anyway")
    finally:
        inst.kill()
    assert [e["outcome"] for e in inst.log_lines()] == ["signed"]


def test_one_connection_over_the_cap_is_answered_busy_and_no_thread_is_made(tmp_path):
    inst = with_limits(tmp_path, max_connections=4, request_timeout_ms=600000).start()
    held = []
    try:
        for _ in range(4):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(inst.socket))
            held.append(s)
        time.sleep(0.3)
        with pytest.raises(SignetRefused) as caught:
            request(inst.socket, "zeta-lock-result", ZETA + b"x", timeout=5)
        assert caught.value.code == "busy"
        for _ in range(200):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(inst.socket))
            held.append(s)
        time.sleep(0.5)
        threads = len(os.listdir(f"/proc/{inst.proc.pid}/task"))
        assert threads <= 4 + 4, f"{threads} threads for 204 connections with a cap of 4"
        for s in held:
            s.close()
        time.sleep(0.3)
        request(inst.socket, "zeta-lock-result", ZETA + b"served again", timeout=5)
    finally:
        for s in held:
            s.close()
        inst.kill()


def test_the_rate_limiter_counts_per_account_and_restarts_each_window():
    now = [0.0]
    b = RefusalBudget(2, 1000, clock=lambda: now[0])
    assert [b.allow(1), b.allow(1), b.allow(1), b.allow(2)] == [True, True, False, True]
    assert b.due() == {}
    now[0] = 1.5
    assert b.due() == {1: 1}
    assert b.allow(1) is True


@pytest.mark.parametrize("limits, why", [
    ({"max_connections": 0}, "max_connections"),
    ({"max_connections": 5000}, "max_connections"),
    ({"refusal_budget": {"per_account": 0, "window_ms": 60000}}, "per_account"),
    ({"refusal_budget": {"per_account": 5}}, "exactly per_account"),
    ({"refusal_budget": {"per_account": 5, "window_ms": 10}}, "window_ms"),
    ({"min_free_bytes": -1}, "min_free_bytes"),
])
def test_bad_limits_are_refused(tmp_path, limits, why):
    inst = with_limits(tmp_path, **limits)
    with pytest.raises(ConfigError, match=why):
        parse(inst.config.read_bytes())
