"""Chained checkpoints (schema 2), anchored registries that cannot un-revoke, and staleness (RACE 9.5, Step 3).

Moves with signet_anchor (docs/OUTSIDE_ANCHOR_v1.md).
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from instance import ZETA_LABEL, Instance, cli
from signet.client import request
from signet.keys import load as load_key
from signet.registry import load_registry, sign_registry
from signet.verify import CHECKPOINT_SCHEMA_2
from signet_anchor import AnchorError, check, publish_checkpoint, publish_registry
from signet_anchor.__main__ import main as anchor_main


def sign(inst: Instance, n: int = 1) -> None:
    for i in range(n):
        request(inst.socket, "zeta-lock-result", ZETA_LABEL.encode() + f"entry {i}".encode())


def chained(inst: Instance, name: str, previous: "str | None" = None) -> bytes:
    out = inst.root / name
    extra = ["--previous", str(inst.root / previous)] if previous else ["--first"]
    done = cli("checkpoint", "--config", str(inst.config), "--out", str(out), *extra)
    assert done.returncode == 0, done.stderr
    return out.read_bytes()


@pytest.fixture
def live(tmp_path):
    (tmp_path / "signet").mkdir()
    inst = Instance(tmp_path / "signet").start()
    yield inst
    inst.kill()


@pytest.fixture
def anchor(tmp_path, live):
    path = tmp_path / "anchor"
    publish_registry(path, live.registry().read_bytes(), live.root_key())
    return path


def three(live, anchor):
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c1.json"), live.log, live.root_key())
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c2.json", "c1.json"), live.log, live.root_key())
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c3.json", "c2.json"), live.log, live.root_key())


def test_a_chained_sequence_checks_clean_and_each_names_the_one_before(live, anchor):
    three(live, anchor)
    assert check(anchor, live.log, live.root_key()) == []
    docs = [json.loads((anchor / "checkpoints" / f"00000{n}.json").read_text()) for n in (1, 2, 3)]
    assert all(d["schema"] == CHECKPOINT_SCHEMA_2 for d in docs) and docs[0]["previous"] == ""
    assert docs[1]["previous"] == hashlib.sha256((anchor / "checkpoints" / "000001.json").read_bytes()).hexdigest()


def test_a_removed_middle_checkpoint_shows(live, anchor):
    three(live, anchor)
    cps = anchor / "checkpoints"
    (cps / "000002.json").unlink()
    os.rename(cps / "000003.json", cps / "000002.json")
    assert any("does not name the checkpoint before it" in p for p in check(anchor, live.log, live.root_key()))


def test_swapped_checkpoints_show(live, anchor):
    three(live, anchor)
    cps = anchor / "checkpoints"
    a, b = (cps / "000002.json").read_bytes(), (cps / "000003.json").read_bytes()
    (cps / "000002.json").write_bytes(b)
    (cps / "000003.json").write_bytes(a)
    assert check(anchor, live.log, live.root_key())


def test_an_unlinked_checkpoint_is_not_published(live, anchor):
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c1.json"), live.log, live.root_key())
    sign(live, 1)
    with pytest.raises(AnchorError, match="does not name"):
        publish_checkpoint(anchor, chained(live, "c2.json"), live.log, live.root_key())  # --first again


def test_a_downgrade_to_an_unchained_checkpoint_is_refused(live, anchor):
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c1.json"), live.log, live.root_key())
    sign(live, 1)
    out = live.root / "plain.json"
    assert cli("checkpoint", "--config", str(live.config), "--out", str(out)).returncode == 0
    with pytest.raises(AnchorError, match="downgrade"):
        publish_checkpoint(anchor, out.read_bytes(), live.log, live.root_key())


def test_a_checkpoint_signed_earlier_than_the_one_it_follows_is_refused(live, anchor):
    """Forge one with the log key itself (what signet's account could do) whose time goes backwards."""
    from signet.verify import checkpoint_signing_input
    sign(live, 2)
    first = chained(live, "c1.json")
    publish_checkpoint(anchor, first, live.log, live.root_key())
    sign(live, 1)
    length, head = 3, json.loads(live.log.read_text().splitlines()[-1])["hash"]
    prev, at = hashlib.sha256(first).hexdigest(), json.loads(first)["at_ms"] - 1
    key = load_key(live.keys_dir, "log-1")
    sig = b"log-1:" + key.sign(checkpoint_signing_input(length, head, at_ms=at, previous=prev))
    doc = {"schema": CHECKPOINT_SCHEMA_2, "length": length, "head": head, "at_ms": at, "previous": prev,
           "signature": sig.hex()}
    with pytest.raises(AnchorError, match="before the checkpoint it follows"):
        publish_checkpoint(anchor, json.dumps(doc), live.log, live.root_key())


def test_previous_must_still_match_the_live_log(live):
    sign(live, 3)
    chained(live, "c1.json")
    live.kill()
    live.log.unlink()
    live.start()
    sign(live, 4)
    done = cli("checkpoint", "--config", str(live.config), "--out", str(live.root / "c2.json"), "--previous",
               str(live.root / "c1.json"))
    assert done.returncode == 2 and "rewritten" in done.stderr


def test_an_anchored_registry_cannot_bring_a_revoked_key_back(live, anchor, tmp_path):
    first = load_registry((live.root / "registry.json").read_bytes(), live.root_key())
    revoke = live.registry("r2.json", "--previous", str(live.root / "registry.json"), "--root-key", live.root_key(),
                           "--revoke", "zeta-1")
    publish_registry(anchor, revoke.read_bytes(), live.root_key())
    body = first.body()
    body["version"] = 3  # zeta-1 current again, signed by the real root
    text = sign_registry(body, load_key(live.keys_dir, "root-1"), "root-1")
    with pytest.raises(AnchorError, match="resurrection"):
        publish_registry(anchor, text, live.root_key())


def test_stalled_publishing_is_named(live, anchor):
    sign(live, 2)
    publish_checkpoint(anchor, chained(live, "c1.json"), live.log, live.root_key())
    at = json.loads((anchor / "checkpoints" / "000001.json").read_text())["at_ms"]
    assert check(anchor, live.log, live.root_key(), max_unanchored=3, max_age_ms=60_000, now_ms=at + 1) == []
    sign(live, 5)
    problems = check(anchor, live.log, live.root_key(), max_unanchored=3, max_age_ms=60_000, now_ms=at + 120_000)
    assert any("5 log entries are not covered" in p for p in problems)
    assert any("ms old" in p for p in problems)


def test_age_cannot_be_checked_without_a_chained_checkpoint(live, anchor):
    assert any("no chained" in p for p in check(anchor, live.log, live.root_key(), max_age_ms=1))


def test_the_command_line_check_takes_the_staleness_limits(live, anchor, capsys):
    sign(live, 4)
    code = anchor_main(["check", "--anchor", str(anchor), "--root-key", live.root_key(), "--log", str(live.log),
                        "--max-unanchored", "2"])
    assert code == 1 and "stale" in capsys.readouterr().err
