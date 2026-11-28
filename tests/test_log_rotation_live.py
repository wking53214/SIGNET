"""Log rotation (T14) against a real signet process: seals are signed by the log key, checkpoints, status and the
anchor all read across segments, and a restart starts from the newest segment."""

import json

import pytest

from instance import ZETA_LABEL, Instance, cli
from signet.client import request
from signet.config import ConfigError, parse
from signet.log import segment_dir, verify_file
from signet_anchor import check, publish_checkpoint, publish_registry

ZETA = ZETA_LABEL.encode("ascii")


def rotating(tmp_path, rotate_bytes=4096) -> Instance:
    inst = Instance(tmp_path)
    doc = json.loads(inst.config.read_text())
    doc["rotate_bytes"] = rotate_bytes
    inst.config.write_text(json.dumps(doc))
    return inst


def sign(inst: Instance, n: int) -> None:
    for i in range(n):
        request(inst.socket, "zeta-lock-result", ZETA + str(i).encode())


def test_rotate_bytes_is_checked():
    base = {"schema": "signet-config/1", "socket": "/s", "keys_dir": "/k", "log": "/l", "registry_key_id": "root-1",
            "log_key_id": "log-1", "purposes": {"p": {"key_id": "p-1", "label": "p/1\n", "allowed_uids": [1]}}}
    assert parse(json.dumps(base)).rotate_bytes == 0
    assert parse(json.dumps({**base, "rotate_bytes": 4096})).rotate_bytes == 4096
    for bad in (1, 4095, -1, "4096", True):
        with pytest.raises(ConfigError, match="rotate_bytes"):
            parse(json.dumps({**base, "rotate_bytes": bad}))


def test_seals_checkpoints_status_and_the_anchor_work_across_segments(tmp_path):
    inst = rotating(tmp_path).start()
    try:
        sign(inst, 60)
        seals = sorted(segment_dir(inst.log).glob("*.seal.json"))
        assert len(seals) >= 3
        reg = inst.registry("registry.json")
        for seal in seals:  # every seal is a checkpoint signed by this signet's log key
            done = cli("check-checkpoint", "--registry", str(reg), "--root-key", inst.root_key(),
                       "--checkpoint", str(seal))
            assert done.returncode == 0, done.stderr
        anchor = tmp_path / "anchor"
        publish_registry(anchor, reg.read_bytes(), inst.root_key())
        first = tmp_path / "c1.json"
        assert cli("checkpoint", "--config", str(inst.config), "--out", str(first), "--first").returncode == 0
        publish_checkpoint(anchor, first.read_bytes(), inst.log, inst.root_key())
        sign(inst, 40)  # more rotations after the published checkpoint
        second = tmp_path / "c2.json"
        done = cli("checkpoint", "--config", str(inst.config), "--out", str(second), "--previous", str(first))
        assert done.returncode == 0, done.stderr
        publish_checkpoint(anchor, second.read_bytes(), inst.log, inst.root_key())
        assert check(anchor, inst.log, inst.root_key()) == []
        status = cli("status", "--config", str(inst.config))
        report = json.loads(status.stdout)
        assert report["log_entries"] == 100 and report["recent"]["signed"] == 100
        assert 0 <= report["log_live_bytes"] < 4096 + 1024
    finally:
        inst.stop()
    assert verify_file(inst.log)[0] == 100
    inst.start()  # a restart reads the newest segment and the live file, and the chain goes on
    try:
        sign(inst, 5)
    finally:
        inst.stop()
    assert verify_file(inst.log)[0] == 105
    assert check(anchor, inst.log, inst.root_key()) == []


def test_a_rewritten_old_segment_is_found_by_the_anchor(tmp_path):
    inst = rotating(tmp_path).start()
    try:
        sign(inst, 60)
        reg = inst.registry("registry.json")
        anchor = tmp_path / "anchor"
        publish_registry(anchor, reg.read_bytes(), inst.root_key())
        cp = tmp_path / "c1.json"
        assert cli("checkpoint", "--config", str(inst.config), "--out", str(cp), "--first").returncode == 0
        publish_checkpoint(anchor, cp.read_bytes(), inst.log, inst.root_key())
    finally:
        inst.stop()
    first = segment_dir(inst.log) / "000001.log"
    lines = first.read_bytes().split(b"\n")
    entry = json.loads(lines[2])
    entry["pid"] = 424242
    lines[2] = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
    first.write_bytes(b"\n".join(lines))
    problems = check(anchor, inst.log, inst.root_key())
    assert problems and "000001.log" in " ".join(problems)
    assert cli("verify-log", "--log", str(inst.log)).returncode == 1


def test_a_missing_log_key_stops_a_rotating_signet(tmp_path):
    inst = rotating(tmp_path)
    (inst.keys_dir / "log-1.key").unlink()
    done = cli("serve", "--config", str(inst.config))
    assert done.returncode != 0 and "log-1" in done.stderr
