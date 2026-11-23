"""signet as its own process: every check a request goes through, the log it keeps, and what survives a SIGKILL.

Each test starts `python -m signet serve` and talks to it over its Unix socket, as a library in another program would.
"""

import os
import socket
import struct
import threading
import time

import pytest

from instance import DELTA_LABEL, ZETA_LABEL, Instance, cli
from signet.client import SignetRefused, SignetUnavailable, request, signer
from signet.config import load as load_config
from signet.log import LogError, SignatureLog, verify_file
from signet.registry import load_registry
from signet.server import Signer
from signet.verify import verifier

ZETA = ZETA_LABEL.encode()
DELTA = DELTA_LABEL.encode()


@pytest.fixture
def live(tmp_path):
    inst = Instance(tmp_path).start()
    yield inst
    inst.stop()


def test_a_signature_checks_under_the_registry(live):
    sig, seq = request(live.socket, "zeta-lock-result", ZETA + b"{}")
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    assert verifier(reg, "zeta-lock-result")(ZETA + b"{}", sig) is True
    assert verifier(reg, "delta-receipt")(ZETA + b"{}", sig) is False
    assert seq == 0 and live.log_lines()[0]["outcome"] == "signed"


def test_bytes_without_the_purpose_label_are_refused_and_logged(live):
    with pytest.raises(SignetRefused) as caught:
        request(live.socket, "zeta-lock-result", DELTA + b"{}")
    assert caught.value.code == "wrong-label"
    entry = live.log_lines()[-1]
    assert entry["outcome"] == "refused" and entry["code"] == "wrong-label" and entry["signature_sha256"] == ""


def test_an_unknown_or_reserved_purpose_is_refused(live):
    for purpose in ("nothing", "signet-log", "signet-registry"):
        with pytest.raises(SignetRefused) as caught:
            request(live.socket, purpose, b"signet-log-checkpoint/1\n{}")
        assert caught.value.code == "unknown-purpose"


def test_an_account_not_allowed_is_refused(tmp_path):
    uid = os.getuid()
    inst = Instance(tmp_path, purposes={
        "zeta-lock-result": {"key_id": "zeta-1", "label": ZETA_LABEL, "allowed_uids": [uid + 4242]}}).start()
    try:
        with pytest.raises(SignetRefused) as caught:
            request(inst.socket, "zeta-lock-result", ZETA + b"{}")
        assert caught.value.code == "not-allowed"
        assert inst.log_lines()[-1]["uid"] == uid
    finally:
        inst.stop()


def raw_exchange(path, payload: bytes) -> bytes:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(str(path))
    sock.sendall(payload)
    head = sock.recv(4)
    (n,) = struct.unpack(">I", head)
    body = b""
    while len(body) < n:
        body += sock.recv(n - len(body))
    sock.close()
    return body


def frame(body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + body


@pytest.mark.parametrize("payload, code", [
    (frame(b'{"v":1,"purpose":"zeta-lock-result","data":"00","data":"11"}'), "malformed"),
    (frame(b'{"v":1,"purpose":"zeta-lock-result","data":"ZZ"}'), "malformed"),
    (frame(b'{"v":1,"purpose":"zeta-lock-result","data":"AB"}'), "malformed"),
    (frame(b'{"v":2,"purpose":"zeta-lock-result","data":"00"}'), "malformed"),
    (frame(b'{"v":1.0,"purpose":"zeta-lock-result","data":"00"}'), "malformed"),
    (struct.pack(">I", 50 * 1024 * 1024), "too-large"),
])
def test_malformed_requests_are_refused(live, payload, code):
    assert f'"code":"{code}"'.encode() in raw_exchange(live.socket, payload)


def test_a_silent_connection_is_closed_and_others_are_still_served(tmp_path):
    inst = Instance(tmp_path, timeout_ms=200).start()
    try:
        idle = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        idle.connect(str(inst.socket))
        idle.sendall(b"\x00\x00")
        request(inst.socket, "zeta-lock-result", ZETA + b"a")
        idle.settimeout(5)
        assert idle.recv(16) == b""
        idle.close()
    finally:
        inst.stop()


def test_many_callers_at_once_get_distinct_logged_signatures(live):
    results, errors = [], []

    def one(i):
        try:
            results.append(request(live.socket, "delta-receipt", DELTA + str(i).encode()))
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(32)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert sorted(seq for _, seq in results) == list(range(32))
    assert verify_file(live.log)[0] == 32


def test_the_log_holds_digests_never_the_signed_bytes(live):
    secret = b"patient-7f3a-very-identifiable"
    request(live.socket, "zeta-lock-result", ZETA + secret)
    assert secret not in live.log.read_bytes()


def test_sigkill_then_restart_keeps_one_verified_history(tmp_path):
    inst = Instance(tmp_path).start()
    for i in range(5):
        request(inst.socket, "zeta-lock-result", ZETA + bytes([i]))
    inst.kill()
    assert inst.socket.exists()  # a dead signet leaves its socket file
    assert verify_file(inst.log)[0] == 5
    inst.start()  # the stale socket is reclaimed
    try:
        _, seq = request(inst.socket, "zeta-lock-result", ZETA + b"after")
        assert seq == 5 and verify_file(inst.log)[0] == 6
    finally:
        inst.stop()


def test_a_second_signet_on_a_live_socket_is_refused(live):
    done = cli("serve", "--config", str(live.config))
    assert done.returncode == 2 and "already serving" in done.stderr


def test_a_key_open_to_others_stops_the_start(tmp_path):
    inst = Instance(tmp_path)
    os.chmod(inst.keys_dir / "zeta-1.key", 0o640)
    done = cli("serve", "--config", str(inst.config))
    assert done.returncode == 2 and "group and others" in done.stderr
    assert not inst.socket.exists()


def test_an_edited_log_stops_the_start(tmp_path):
    inst = Instance(tmp_path).start()
    request(inst.socket, "zeta-lock-result", ZETA + b"x")
    inst.stop()
    inst.log.write_text(inst.log.read_text().replace('"outcome":"signed"', '"outcome":"refused"'))
    done = cli("serve", "--config", str(inst.config))
    assert done.returncode == 2 and "edited" in done.stderr


def test_no_signet_means_no_signature(tmp_path):
    sign = signer(tmp_path / "absent.sock", "zeta-lock-result")
    with pytest.raises(SignetUnavailable):
        sign(ZETA + b"x")


def test_a_log_that_cannot_be_written_releases_no_signature(tmp_path):
    inst = Instance(tmp_path)
    cfg = load_config(inst.config)

    class BrokenLog(SignatureLog):
        def append(self, **kwargs):
            raise LogError("disk full")

    s = Signer(cfg, BrokenLog(inst.log))
    answer = s.handle(b'{"v":1,"purpose":"zeta-lock-result","data":"%s"}' % (ZETA + b"x").hex().encode(),
                      os.getuid(), os.getpid())
    assert answer == {"v": 1, "ok": False, "code": "log-failed", "reason": "not released: disk full"}


def test_checkpoint_and_rotation_through_the_command_line(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        old_sig, _ = request(inst.socket, "zeta-lock-result", ZETA + b"old")
        reg1 = inst.registry("registry-1.json")
        checkpoint = tmp_path / "checkpoint-1.json"
        done = cli("checkpoint", "--config", str(inst.config), "--out", str(checkpoint))
        assert done.returncode == 0, done.stderr
        done = cli("check-checkpoint", "--registry", str(reg1), "--root-key", inst.root_key(),
                   "--checkpoint", str(checkpoint))
        assert done.returncode == 0 and "1 entries" in done.stdout
        again = cli("checkpoint", "--config", str(inst.config), "--out", str(checkpoint))
        assert again.returncode == 2 and "already exists" in again.stderr
    finally:
        inst.stop()
    # Rotate the zeta key: a new key id, the old key verify-only in version 2.
    rotated = Instance(tmp_path, key_ids={"zeta": "zeta-2"})
    rotated.public["root"] = inst.public["root"]
    reg2 = rotated.registry("registry-2.json", "--previous", str(reg1), "--root-key", inst.root_key())
    v2 = load_registry(reg2.read_bytes(), inst.root_key(), min_version=2)
    assert v2.current("zeta-lock-result").key_id == "zeta-2" and v2.entry("zeta-1").status == "verify-only"
    assert verifier(v2, "zeta-lock-result")(ZETA + b"old", old_sig) is True
    reg3 = rotated.registry("registry-3.json", "--previous", str(reg2), "--root-key", inst.root_key(),
                            "--revoke", "zeta-1")
    v3 = load_registry(reg3.read_bytes(), inst.root_key(), min_version=3)
    assert verifier(v3, "zeta-lock-result")(ZETA + b"old", old_sig) is False
    stale = cli("check-checkpoint", "--registry", str(reg1), "--root-key", inst.root_key(), "--checkpoint",
                str(checkpoint), "--min-version", "3")
    assert stale.returncode == 1 and "older than version 3" in stale.stderr


def test_verify_log_command(live):
    request(live.socket, "zeta-lock-result", ZETA + b"x")
    time.sleep(0.05)
    done = cli("verify-log", "--log", str(live.log))
    assert done.returncode == 0 and "1 entries" in done.stdout
