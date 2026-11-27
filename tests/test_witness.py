"""The outside witness record (signet_anchor.witness), checked without the network.

These tests build bundles with the shape Sigstore writes, to test what signet_anchor itself checks: the binding to
the exact checkpoint bytes, order, and time. Sigstore's cryptographic verification against real Rekor records runs in
CI (.github/workflows/witness-drill.yml); here it is only shown to fail closed when the sigstore command is absent.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from instance import ZETA_LABEL, Instance, cli
from signet.client import request
from signet_anchor import AnchorError, publish_checkpoint, publish_registry
from signet_anchor.__main__ import main as anchor_main
from signet_anchor.witness import bundle_binding, check_witnesses, sigstore_verify, witness_path


def bundle(artifact: bytes, when_s: int, index: int = 7) -> bytes:
    return json.dumps({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}, "tlogEntries": [{
            "logIndex": str(index), "logId": {"keyId": "AAAA"}, "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
            "integratedTime": str(when_s), "inclusionProof": {"logIndex": str(index), "rootHash": "AAAA",
                                                              "treeSize": "9", "hashes": []},
            "canonicalizedBody": "AAAA"}]},
        "messageSignature": {"messageDigest": {"algorithm": "SHA2_256",
                                               "digest": base64.b64encode(hashlib.sha256(artifact).digest()).decode()},
                             "signature": "AAAA"}}).encode()


@pytest.fixture
def anchored(tmp_path):
    (tmp_path / "signet").mkdir()
    inst = Instance(tmp_path / "signet").start()
    anchor = tmp_path / "anchor"
    publish_registry(anchor, inst.registry().read_bytes(), inst.root_key())
    previous = None
    for n in (1, 2, 3):
        request(inst.socket, "zeta-lock-result", ZETA_LABEL.encode() + str(n).encode())
        out = inst.root / f"c{n}.json"
        extra = ["--previous", str(previous)] if previous else ["--first"]
        assert cli("checkpoint", "--config", str(inst.config), "--out", str(out), *extra).returncode == 0
        publish_checkpoint(anchor, out.read_bytes(), inst.log, inst.root_key())
        previous = out
    inst.kill()
    return inst, anchor


def raw(anchor, n):
    return (anchor / "checkpoints" / f"{n:06d}.json").read_bytes()


def at(anchor, n):
    return json.loads(raw(anchor, n))["at_ms"]


def witness_all(anchor, delay_s=5, order=(1, 2, 3)):
    (anchor / "witness").mkdir(exist_ok=True)
    for i, n in enumerate(order):
        witness_path(anchor, n).write_bytes(bundle(raw(anchor, n), at(anchor, n) // 1000 + delay_s + i, index=100 + i))


def test_every_checkpoint_witnessed_in_order_checks_clean(anchored):
    inst, anchor = anchored
    witness_all(anchor)
    assert check_witnesses(anchor, inst.root_key(), max_delay_ms=3_600_000) == []


def test_an_unwitnessed_checkpoint_is_named_unless_it_is_the_pending_newest(anchored):
    inst, anchor = anchored
    witness_all(anchor)
    witness_path(anchor, 3).unlink()
    assert check_witnesses(anchor, inst.root_key(), allow_pending=1) == []
    witness_path(anchor, 2).unlink()
    assert any("never shown to Rekor" in p for p in check_witnesses(anchor, inst.root_key(), allow_pending=1))


def test_a_bundle_for_other_bytes_is_refused(anchored):
    inst, anchor = anchored
    witness_all(anchor)
    witness_path(anchor, 2).write_bytes(witness_path(anchor, 1).read_bytes())
    assert any("other bytes" in p for p in check_witnesses(anchor, inst.root_key()))


def test_a_checkpoint_replaced_after_it_was_witnessed_is_found(anchored):
    """signet's account rewrites checkpoint 3 (say, after rewriting the log). Its old witness no longer matches."""
    inst, anchor = anchored
    witness_all(anchor)
    doc = json.loads(raw(anchor, 3))
    doc["length"] += 0
    (anchor / "checkpoints" / "000003.json").write_bytes(json.dumps(doc, indent=1).encode())
    assert any("other bytes" in p for p in check_witnesses(anchor, inst.root_key()))


def test_witness_times_going_backwards_are_named(anchored):
    inst, anchor = anchored
    (anchor / "witness").mkdir()
    for n, t in ((1, 300), (2, 200), (3, 400)):
        witness_path(anchor, n).write_bytes(bundle(raw(anchor, n), at(anchor, n) // 1000 + t))
    assert any("before the checkpoint it follows" in p for p in check_witnesses(anchor, inst.root_key()))


def test_a_checkpoint_witnessed_before_signet_says_it_was_signed_is_named(anchored):
    inst, anchor = anchored
    witness_all(anchor)
    witness_path(anchor, 1).write_bytes(bundle(raw(anchor, 1), at(anchor, 1) // 1000 - 3600))
    assert any("before signet says" in p for p in check_witnesses(anchor, inst.root_key()))


def test_an_old_time_on_a_late_checkpoint_is_named(anchored):
    """Backdating: signet's account writes a chain today with at_ms a week ago. Rekor's time is today."""
    inst, anchor = anchored
    witness_all(anchor, delay_s=7 * 86400)
    assert any("ms after signet says" in p for p in check_witnesses(anchor, inst.root_key(), max_delay_ms=3_600_000))


def test_a_witness_for_a_checkpoint_the_anchor_does_not_hold_is_named(anchored):
    inst, anchor = anchored
    witness_all(anchor)
    witness_path(anchor, 9).write_bytes(witness_path(anchor, 1).read_bytes())
    assert any("does not hold" in p for p in check_witnesses(anchor, inst.root_key()))


@pytest.mark.parametrize("edit, why", [
    (lambda d: d.update(mediaType="other"), "not a Sigstore bundle"),
    (lambda d: d["messageSignature"]["messageDigest"].update(algorithm="SHA2_512"), "SHA-256"),
    (lambda d: d["verificationMaterial"].update(tlogEntries=[]), "single Rekor entry"),
    (lambda d: d["verificationMaterial"]["tlogEntries"][0].update(integratedTime="soon"), "malformed"),
    (lambda d: d["verificationMaterial"]["tlogEntries"][0].pop("inclusionProof"), "inclusionProof"),
])
def test_a_malformed_bundle_is_refused(edit, why):
    doc = json.loads(bundle(b"x", 1))
    edit(doc)
    with pytest.raises(AnchorError, match=why):
        bundle_binding(json.dumps(doc).encode(), b"x")


def test_without_the_sigstore_command_the_cryptographic_check_fails_closed(tmp_path):
    with pytest.raises(AnchorError, match="not installed"):
        sigstore_verify(tmp_path / "b", tmp_path / "a", "id", command=("no-such-sigstore-command",))


def test_the_command_line_checks_the_witness(anchored, capsys):
    inst, anchor = anchored
    witness_all(anchor)
    assert anchor_main(["check-witness", "--anchor", str(anchor), "--root-key", inst.root_key()]) == 0
    witness_path(anchor, 1).unlink()
    assert anchor_main(["check-witness", "--anchor", str(anchor), "--root-key", inst.root_key()]) == 1
    assert "never shown to Rekor" in capsys.readouterr().err
