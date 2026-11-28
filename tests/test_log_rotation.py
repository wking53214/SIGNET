"""Log rotation (T14): the log is split into sealed segments that stay one chain, start-up reads only the newest of
them, and nothing is ever deleted."""

import json
import os

import pytest

from signet.log import (GENESIS, LogError, SignatureLog, entries, head_at, last_entries, segment_dir, verify_file)
from signet.strict import canonical


def fake_seal(length, head):
    return canonical({"schema": "signet-log-checkpoint/1", "length": length, "head": head,
                      "signature": "00" * 8}) + b"\n"


def fill(log, count):
    heads = []
    for n in range(count):
        log.append(outcome="signed", code="", purpose="zeta", key_id="z1", uid=1000, pid=n, data=bytes([n % 256]) * 8,
                   signature=b"sig")
        heads.append(log.head)
    return heads


@pytest.fixture
def path(tmp_path):
    return tmp_path / "signatures.log"


def open_log(path, rotate=1024):
    return SignatureLog(path, rotate_bytes=rotate, seal=fake_seal)


def test_segments_stay_one_chain_and_nothing_is_lost(path):
    log = open_log(path)
    heads = fill(log, 40)
    log.close()
    sealed = sorted(segment_dir(path).iterdir())
    assert len([p for p in sealed if p.suffix == ".log"]) >= 3
    assert verify_file(path) == (40, heads[-1])
    assert [e["seq"] for e in entries(path)] == list(range(40))
    assert [e["seq"] for e in last_entries(path, 5)] == list(range(35, 40))
    for n in (1, 7, 20, 39, 40):
        assert head_at(path, n) == heads[n - 1]
    assert head_at(path, 0) == GENESIS


def test_a_restart_continues_the_chain(path):
    log = open_log(path)
    fill(log, 25)
    log.close()
    log = open_log(path)
    assert log.length == 25
    heads = fill(log, 10)
    log.close()
    assert verify_file(path) == (35, heads[-1])


def test_rotation_off_by_default_keeps_one_file(path):
    log = SignatureLog(path)
    fill(log, 40)
    log.close()
    assert not segment_dir(path).exists()
    assert verify_file(path)[0] == 40


def test_gap_startup_does_not_recheck_older_sealed_segments(path):
    """Recorded gap: start-up checks only the newest sealed segment. An edit to an older one is caught by every
    full check (verify-log, checkpoint, status, the anchor), not by start-up."""
    log = open_log(path)
    fill(log, 60)
    log.close()
    first = segment_dir(path) / "000001.log"
    lines = first.read_bytes().split(b"\n")
    entry = json.loads(lines[1])
    entry["pid"] = 424242
    lines[1] = canonical(entry)
    first.write_bytes(b"\n".join(lines))
    SignatureLog(path, rotate_bytes=1024, seal=fake_seal).close()  # the gap: start-up does not see it
    with pytest.raises(LogError, match="000001.log"):
        verify_file(path)


def test_an_edited_newest_segment_stops_startup(path):
    log = open_log(path)
    fill(log, 60)
    log.close()
    newest = sorted(p for p in segment_dir(path).iterdir() if p.suffix == ".log")[-1]
    lines = newest.read_bytes().split(b"\n")
    entry = json.loads(lines[0])
    entry["pid"] = 4242
    lines[0] = canonical(entry)
    newest.write_bytes(b"\n".join(lines))
    with pytest.raises(LogError):
        open_log(path)


def test_a_changed_seal_stops_startup(path):
    log = open_log(path)
    fill(log, 60)
    log.close()
    seal = sorted(segment_dir(path).glob("*.seal.json"))[-1]
    doc = json.loads(seal.read_bytes())
    doc["head"] = "ab" * 32
    seal.write_bytes(canonical(doc) + b"\n")
    with pytest.raises(LogError, match="seal"):
        open_log(path)
    with pytest.raises(LogError, match="seal"):
        verify_file(path)


def test_a_missing_middle_segment_is_refused(path):
    log = open_log(path)
    fill(log, 60)
    log.close()
    (segment_dir(path) / "000001.log").unlink()
    with pytest.raises(LogError, match="missing"):
        open_log(path)
    with pytest.raises(LogError, match="missing"):
        verify_file(path)


def test_a_stray_file_in_the_segment_folder_is_refused(path):
    log = open_log(path)
    fill(log, 30)
    log.close()
    (segment_dir(path) / "notes.txt").write_text("x")
    with pytest.raises(LogError, match="not a log segment"):
        open_log(path)


def test_an_interrupted_rotation_is_finished_on_start(path):
    log = SignatureLog(path)
    heads = fill(log, 5)
    log.close()
    folder = segment_dir(path)
    folder.mkdir()
    (folder / "000001.seal.json").write_bytes(fake_seal(5, heads[-1]))  # sealed, but the file was never moved
    log = open_log(path)
    assert log.length == 5 and (folder / "000001.log").exists()
    more = fill(log, 3)
    log.close()
    assert verify_file(path) == (8, more[-1])


def test_a_seal_torn_before_its_rename_is_ignored(path):
    log = open_log(path)
    heads = fill(log, 30)
    log.close()
    (segment_dir(path) / ".000009.seal.tmp").write_bytes(b'{"schema":')
    log = open_log(path)
    assert (log.length, log.head) == (30, heads[-1])
    log.close()


def test_an_interrupted_rotation_that_does_not_match_is_refused(path):
    log = SignatureLog(path)
    heads = fill(log, 5)
    log.close()
    folder = segment_dir(path)
    folder.mkdir()
    (folder / "000001.seal.json").write_bytes(fake_seal(4, heads[-2]))  # the live file went on past the seal
    with pytest.raises(LogError, match="seal"):
        open_log(path)
    assert path.exists() and not (folder / "000001.log").exists()


def test_a_failed_rotation_closes_the_log_to_writes(path):
    calls = []

    def broken_seal(length, head):
        calls.append(length)
        raise OSError("no key")
    log = SignatureLog(path, rotate_bytes=512, seal=broken_seal)
    with pytest.raises(LogError, match="rotation"):
        fill(log, 20)
    with pytest.raises(LogError, match="closed to writes"):
        fill(log, 1)
    written = calls[0]
    assert verify_file(path)[0] == written  # nothing logged was lost, nothing unlogged was written
    log = open_log(path)
    assert log.length == written
    log.close()


def test_segments_are_private(path):
    log = open_log(path)
    fill(log, 30)
    log.close()
    assert os.stat(segment_dir(path)).st_mode & 0o777 == 0o700
    for item in segment_dir(path).iterdir():
        assert os.stat(item).st_mode & 0o077 == 0
