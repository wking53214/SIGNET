"""The rehearsal for docs/KEY_RECOVERY_v1.md: each of its four cases walked with the commands the runbook names.

1. A purpose key is lost: a new key takes over, and what the lost key signed keeps checking.
2. A purpose key is stolen: once it is revoked, what it signs (forged or not) stops checking everywhere.
3. The root key is lost: restoring the offline backup works under the same pin; without a backup, a re-pin is the only
   way out, and the old pin then refuses every newer registry (an asserted gap, not a skip).
4. The root key is stolen: the thief's registries are accepted under the old pin; after the re-pin they are refused,
   and a checker that remembered the thief's version number must reset it (an asserted gap).
"""

from __future__ import annotations

import json
import os
import shutil

import pytest

from instance import ZETA_LABEL, Instance, cli
from signet.client import request
from signet.keys import generate, load as load_key
from signet.registry import RegistryError, load_registry, public_key_hex, sign_registry
from signet.verify import verifier

ZETA = ZETA_LABEL.encode()


def test_case_1_a_lost_purpose_key_is_replaced_and_old_signatures_keep_checking(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        old_sig, _ = request(inst.socket, "zeta-lock-result", ZETA + b"before")
    finally:
        inst.stop()
    reg1 = inst.registry("registry-1.json")
    (inst.keys_dir / "zeta-1.key").unlink()  # the key is gone
    gone = cli("serve", "--config", str(inst.config))
    assert gone.returncode == 2  # signet will not start without it: the loss is loud, not silent
    # Runbook: a new key id, the next registry, restart.
    new = Instance(tmp_path, key_ids={"zeta": "zeta-2"})
    new.public["root"] = inst.public["root"]
    reg2 = new.registry("registry-2.json", "--previous", str(reg1), "--root-key", inst.root_key())
    v2 = load_registry(reg2.read_bytes(), inst.root_key(), min_version=2)
    assert v2.current("zeta-lock-result").key_id == "zeta-2" and v2.entry("zeta-1").status == "verify-only"
    assert verifier(v2, "zeta-lock-result")(ZETA + b"before", old_sig) is True
    new.start()
    try:
        sig, _ = request(new.socket, "zeta-lock-result", ZETA + b"after")
    finally:
        new.stop()
    assert verifier(v2, "zeta-lock-result")(ZETA + b"after", sig) is True


def test_case_2_a_stolen_purpose_key_is_revoked_and_its_signatures_stop_checking(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        honest_sig, _ = request(inst.socket, "zeta-lock-result", ZETA + b"honest")
    finally:
        inst.stop()
    reg1 = inst.registry("registry-1.json")
    stolen = load_key(inst.keys_dir, "zeta-1")
    forged = b"zeta-1:" + stolen.sign(ZETA + b"forged")
    v1 = load_registry(reg1.read_bytes(), inst.root_key())
    assert verifier(v1, "zeta-lock-result")(ZETA + b"forged", forged) is True  # the danger, before the runbook
    # Runbook: replace and revoke in one registry.
    new = Instance(tmp_path, key_ids={"zeta": "zeta-2"})
    new.public["root"] = inst.public["root"]
    reg2 = new.registry("registry-2.json", "--previous", str(reg1), "--root-key", inst.root_key(),
                        "--revoke", "zeta-1")
    v2 = load_registry(reg2.read_bytes(), inst.root_key(), min_version=2)
    assert v2.entry("zeta-1").status == "revoked"
    assert verifier(v2, "zeta-lock-result")(ZETA + b"forged", forged) is False
    # The cost the runbook names: honest work the stolen key signed stops checking too, and must be signed again.
    assert verifier(v2, "zeta-lock-result")(ZETA + b"honest", honest_sig) is False
    # A checker that remembers version 2 cannot be handed version 1 again, where the stolen key still checks.
    with pytest.raises(RegistryError, match="older than version 2"):
        load_registry(reg1.read_bytes(), inst.root_key(), min_version=2)


def test_case_3a_a_lost_root_key_is_restored_from_the_offline_backup_under_the_same_pin(tmp_path):
    inst = Instance(tmp_path)
    reg1 = inst.registry("registry-1.json")
    backup = tmp_path / "offline-backup"
    backup.mkdir(mode=0o700)
    shutil.copy2(inst.keys_dir / "root-1.key", backup / "root-1.key")
    (inst.keys_dir / "root-1.key").unlink()  # the working copy is gone
    lost = cli("registry", "--config", str(inst.config), "--out", str(tmp_path / "registry-2.json"),
               "--previous", str(reg1), "--root-key", inst.root_key())
    assert lost.returncode == 2  # without the root key no registry can be written: nothing can be rotated or revoked
    # Runbook: copy the backup back, owner-only, and carry on. No checker changes anything.
    shutil.copy2(backup / "root-1.key", inst.keys_dir / "root-1.key")
    os.chmod(inst.keys_dir / "root-1.key", 0o600)
    reg2 = inst.registry("registry-2.json", "--previous", str(reg1), "--root-key", inst.root_key())
    assert load_registry(reg2.read_bytes(), inst.root_key(), min_version=2).version == 2


def test_case_3b_a_lost_root_key_without_a_backup_needs_a_re_pin_everywhere(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        old_sig, _ = request(inst.socket, "zeta-lock-result", ZETA + b"before")
    finally:
        inst.stop()
    old_root = inst.root_key()
    reg1 = inst.registry("registry-1.json")
    (inst.keys_dir / "root-1.key").unlink()  # gone, and no backup
    # Runbook: a new root key id; the next registry is checked against the OLD pin (only its public key is needed)
    # and signed by the NEW root, so versions keep counting up.
    new = Instance(tmp_path, key_ids={"root": "root-2"})
    reg2 = new.registry("registry-2.json", "--previous", str(reg1), "--root-key", old_root)
    v2 = load_registry(reg2.read_bytes(), new.root_key(), min_version=2)
    assert v2.current("signet-registry").key_id == "root-2" and v2.entry("root-1").status == "verify-only"
    assert verifier(v2, "zeta-lock-result")(ZETA + b"before", old_sig) is True  # purpose keys were never touched
    # The gap, asserted: a checker still pinned to the old root refuses every registry from now on. Nothing inside
    # signet can move it; each checker is re-pinned by hand.
    with pytest.raises(RegistryError, match="pinned root key"):
        load_registry(reg2.read_bytes(), old_root, min_version=2)


def _thief_registry(reg1_text: bytes, root_key, thief_public: str, version: int) -> str:
    """What a holder of the stolen root can write: any version number, any key made current."""
    body = json.loads(reg1_text)["registry"]
    body["version"] = version
    for key in body["keys"]:
        if key["purpose"] == "zeta-lock-result":
            key["status"] = "verify-only"
    body["keys"].append({"key_id": "zeta-thief", "purpose": "zeta-lock-result", "public_key": thief_public,
                         "status": "current"})
    body["keys"].sort(key=lambda k: k["key_id"])
    return sign_registry(body, root_key, "root-1")


def test_case_4_a_stolen_root_key_is_re_pinned_and_the_thiefs_registries_are_refused(tmp_path):
    inst = Instance(tmp_path)
    old_root = inst.root_key()
    reg1 = inst.registry("registry-1.json")
    thief_dir = tmp_path / "thief"
    thief_dir.mkdir(mode=0o700)
    thief_public = generate(thief_dir, "zeta-thief")
    thief_key = load_key(thief_dir, "zeta-thief")
    stolen_root = load_key(inst.keys_dir, "root-1")
    fake = tmp_path / "registry-50.json"
    fake.write_text(_thief_registry(reg1.read_bytes(), stolen_root, thief_public, 50))
    forged = b"zeta-thief:" + thief_key.sign(ZETA + b"forged")
    # The danger, before the runbook: under the old pin the thief's registry is accepted, and so is its forgery.
    v_fake = load_registry(fake.read_bytes(), old_root, min_version=1)
    assert verifier(v_fake, "zeta-lock-result")(ZETA + b"forged", forged) is True
    # Runbook: new root, the next registry built from the LAST LEGITIMATE one, the stolen root revoked in it.
    new = Instance(tmp_path, key_ids={"root": "root-2"})
    reg2 = new.registry("registry-2.json", "--previous", str(reg1), "--root-key", old_root, "--revoke", "root-1")
    new_root = new.root_key()
    v2 = load_registry(reg2.read_bytes(), new_root, min_version=1)
    assert v2.entry("root-1").status == "revoked" and v2.entry("zeta-thief") is None
    assert verifier(v2, "zeta-lock-result")(ZETA + b"forged", forged) is False
    # Under the new pin, anything the stolen root signs is refused, whatever version it claims.
    with pytest.raises(RegistryError, match="pinned root key"):
        load_registry(fake.read_bytes(), new_root, min_version=1)
    later = tmp_path / "registry-99.json"
    later.write_text(_thief_registry(reg1.read_bytes(), stolen_root, thief_public, 99))
    with pytest.raises(RegistryError, match="pinned root key"):
        load_registry(later.read_bytes(), new_root, min_version=2)
    # The gap, asserted: a checker that accepted the thief's version 50 refuses the honest version 2 until its
    # remembered version is reset along with its pin. The runbook makes that reset part of every re-pin.
    with pytest.raises(RegistryError, match="older than version 50"):
        load_registry(reg2.read_bytes(), new_root, min_version=50)
    assert public_key_hex(stolen_root) == old_root


def test_the_outside_anchor_does_not_survive_a_re_pin(tmp_path):
    """The gap, asserted: the anchor checks every registry it holds against one pinned root, and it never removes a
    file. After a re-pin the old registries fail under the new pin, so the anchor refuses everything, including the
    honest next registry. The way out today is a new anchor directory started at the re-pin, with the old one kept as
    frozen history; an anchor that follows a root change itself is not built."""
    from signet_anchor.anchor import AnchorError, latest_registry, publish_registry

    inst = Instance(tmp_path)
    old_root = inst.root_key()
    reg1 = inst.registry("registry-1.json")
    anchor = tmp_path / "anchor"
    anchor.mkdir()
    publish_registry(anchor, reg1.read_bytes(), old_root)
    new = Instance(tmp_path, key_ids={"root": "root-2"})
    reg2 = new.registry("registry-2.json", "--previous", str(reg1), "--root-key", old_root, "--revoke", "root-1")
    with pytest.raises(AnchorError, match="pinned root key"):
        publish_registry(anchor, reg2.read_bytes(), new.root_key())
    with pytest.raises(AnchorError, match="pinned root key"):
        latest_registry(anchor, new.root_key())
    fresh = tmp_path / "anchor-after-re-pin"
    fresh.mkdir()
    publish_registry(fresh, reg2.read_bytes(), new.root_key())  # the runbook's way out: a new anchor directory
    assert latest_registry(fresh, new.root_key()).version == 2
    assert latest_registry(anchor, old_root).version == 1  # the old one stays readable, frozen, under the old pin
