"""The key store refuses keys it cannot keep private, and the log refuses any history but the one it wrote."""

import json
import os

import pytest

from signet.keys import KeyStoreError, generate, key_path, load
from signet.log import GENESIS, LogError, SignatureLog, verify_file
from signet.registry import public_key_hex


@pytest.fixture
def keys_dir(tmp_path):
    d = tmp_path / "keys"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


def test_generate_then_load(keys_dir):
    public = generate(keys_dir, "zeta1")
    assert public_key_hex(load(keys_dir, "zeta1")) == public
    assert os.stat(key_path(keys_dir, "zeta1")).st_mode & 0o777 == 0o600


def test_generate_never_overwrites(keys_dir):
    generate(keys_dir, "zeta1")
    with pytest.raises(KeyStoreError, match="already exists"):
        generate(keys_dir, "zeta1")


def test_a_key_readable_by_others_is_refused(keys_dir):
    generate(keys_dir, "zeta1")
    os.chmod(key_path(keys_dir, "zeta1"), 0o644)
    with pytest.raises(KeyStoreError, match="group and others"):
        load(keys_dir, "zeta1")


def test_a_directory_open_to_others_is_refused(keys_dir):
    generate(keys_dir, "zeta1")
    os.chmod(keys_dir, 0o755)
    with pytest.raises(KeyStoreError, match="group and others"):
        load(keys_dir, "zeta1")


def test_a_linked_key_is_refused(keys_dir, tmp_path):
    generate(keys_dir, "zeta1")
    os.symlink(key_path(keys_dir, "zeta1"), key_path(keys_dir, "alias"))
    with pytest.raises(KeyStoreError, match="link"):
        load(keys_dir, "alias")


def test_a_damaged_key_file_is_refused(keys_dir):
    generate(keys_dir, "zeta1")
    path = key_path(keys_dir, "zeta1")
    path.write_text("signet-key/1\nnot-hex\n")
    with pytest.raises(KeyStoreError, match="not a signet key file"):
        load(keys_dir, "zeta1")


def test_a_bad_key_id_is_refused(keys_dir):
    with pytest.raises(ValueError, match="1 to 64"):
        generate(keys_dir, "../escape")


def write_three(path):
    log = SignatureLog(path)
    for i in range(3):
        log.append(outcome="signed", code="", purpose="p", key_id="k", uid=0, pid=1, data=bytes([i]), signature=b"s")
    log.close()


def test_the_log_chains_and_survives_a_restart(tmp_path):
    path = tmp_path / "log"
    assert verify_file(path) == (0, GENESIS)
    write_three(path)
    length, head = verify_file(path)
    assert length == 3
    log = SignatureLog(path)
    assert log.state() == (3, head)
    assert log.append(outcome="refused", code="wrong-label", purpose="p", key_id="", uid=0, pid=1, data=b"x",
                      signature=b"") == 3
    log.close()
    assert verify_file(path)[0] == 4


def lines(path):
    return path.read_bytes().split(b"\n")[:-1]


def put(path, rows):
    path.write_bytes(b"".join(r + b"\n" for r in rows))


def test_an_edited_line_is_found(tmp_path):
    path = tmp_path / "log"
    write_three(path)
    rows = lines(path)
    entry = json.loads(rows[1])
    entry["purpose"] = "other"
    rows[1] = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
    put(path, rows)
    with pytest.raises(LogError, match="line 2 was edited"):
        verify_file(path)


def test_a_removed_line_is_found(tmp_path):
    path = tmp_path / "log"
    write_three(path)
    rows = lines(path)
    put(path, [rows[0], rows[2]])
    with pytest.raises(LogError, match="line 2 has seq 2"):
        verify_file(path)


def test_reordered_lines_are_found(tmp_path):
    path = tmp_path / "log"
    write_three(path)
    rows = lines(path)
    put(path, [rows[1], rows[0], rows[2]])
    with pytest.raises(LogError, match="line 1 has seq 1"):
        verify_file(path)


def test_a_rewritten_chain_is_not_found_by_the_log_alone(tmp_path):
    """A recorded limit, asserted: whoever can write the file can write a whole new consistent chain. Only a checkpoint
    published outside signet's reach shows it (README, Limits)."""
    path = tmp_path / "log"
    write_three(path)
    original = verify_file(path)
    path.unlink()
    log = SignatureLog(path)
    for i in range(3):
        log.append(outcome="signed", code="", purpose="p", key_id="k", uid=0, pid=1, data=bytes([9, i]), signature=b"s")
    log.close()
    rewritten = verify_file(path)
    assert rewritten[0] == original[0] and rewritten[1] != original[1]


def test_a_torn_last_line_stops_the_start(tmp_path):
    path = tmp_path / "log"
    write_three(path)
    with open(path, "ab") as handle:
        handle.write(b'{"seq":3')
    with pytest.raises(LogError, match="torn"):
        SignatureLog(path)
