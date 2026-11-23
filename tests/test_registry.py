"""The registry: one signed list of keys, checked against a pinned root, and the verifier built from it."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import RegistryError, check_body, load_registry, next_body, public_key_hex, sign_registry
from signet.verify import check_checkpoint, checkpoint_signing_input, verifier

ZETA = "zeta-lock-result"
ZETA_LABEL = b"zeta-lock-result-signature/1\n"
PURPOSES = {ZETA: ZETA_LABEL, REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}


@pytest.fixture
def keys():
    return {name: Ed25519PrivateKey.generate() for name in ("root", "zeta1", "zeta2", "log", "stranger")}


def first(keys):
    current = {REGISTRY_PURPOSE: ("root", public_key_hex(keys["root"])), ZETA: ("zeta1", public_key_hex(keys["zeta1"])),
               LOG_PURPOSE: ("log", public_key_hex(keys["log"]))}
    return next_body(None, PURPOSES, current)


def signed(body, keys):
    return sign_registry(body, keys["root"], "root")


def env(key_id, key, data):
    return key_id.encode() + b":" + key.sign(data)


def test_round_trip_and_verify(keys):
    reg = load_registry(signed(first(keys), keys), public_key_hex(keys["root"]))
    assert reg.version == 1 and reg.current(ZETA).key_id == "zeta1"
    verify = verifier(reg, ZETA)
    data = ZETA_LABEL + b"{}"
    assert verify(data, env("zeta1", keys["zeta1"], data)) is True


def test_a_wrong_pinned_root_is_refused(keys):
    with pytest.raises(RegistryError, match="pinned root"):
        load_registry(signed(first(keys), keys), public_key_hex(keys["stranger"]))


def test_an_edited_registry_is_refused(keys):
    text = signed(first(keys), keys)
    doc = json.loads(text)
    doc["registry"]["keys"][-1]["public_key"] = public_key_hex(keys["stranger"])
    with pytest.raises(RegistryError, match="does not check out"):
        load_registry(json.dumps(doc), public_key_hex(keys["root"]))


def test_a_registry_signed_by_a_key_it_does_not_name_as_root_is_refused(keys):
    body = first(keys)
    with pytest.raises(RegistryError, match="not this registry's current"):
        sign_registry(body, keys["zeta1"], "zeta1")


def test_rollback_to_an_older_version_is_refused(keys):
    root = public_key_hex(keys["root"])
    v1 = load_registry(signed(first(keys), keys), root)
    v2_text = signed(next_body(v1, {}, {ZETA: ("zeta2", public_key_hex(keys["zeta2"]))}, revoke=["zeta1"]), keys)
    assert load_registry(v2_text, root, min_version=2).version == 2
    with pytest.raises(RegistryError, match="older than version 2"):
        load_registry(signed(first(keys), keys), root, min_version=2)


def test_rotation_keeps_the_old_key_verifying_and_revocation_ends_it(keys):
    root = public_key_hex(keys["root"])
    v1 = load_registry(signed(first(keys), keys), root)
    v2 = load_registry(signed(next_body(v1, {}, {ZETA: ("zeta2", public_key_hex(keys["zeta2"]))}), keys), root)
    assert v2.entry("zeta1").status == "verify-only" and v2.current(ZETA).key_id == "zeta2"
    data = ZETA_LABEL + b"x"
    assert verifier(v2, ZETA)(data, env("zeta1", keys["zeta1"], data)) is True
    v3 = load_registry(signed(next_body(v2, {}, {}, revoke=["zeta1"]), keys), root)
    assert verifier(v3, ZETA)(data, env("zeta1", keys["zeta1"], data)) is False
    assert verifier(v3, ZETA)(data, env("zeta2", keys["zeta2"], data)) is True


def test_a_revoked_key_cannot_be_made_current_again(keys):
    root = public_key_hex(keys["root"])
    v1 = load_registry(signed(first(keys), keys), root)
    v2 = load_registry(signed(next_body(v1, {}, {ZETA: ("zeta2", public_key_hex(keys["zeta2"]))},
                                        revoke=["zeta1"]), keys), root)
    with pytest.raises(RegistryError, match="forever"):
        next_body(v2, {}, {ZETA: ("zeta1", public_key_hex(keys["zeta1"]))})


def test_revoking_an_unknown_id_is_refused(keys):
    with pytest.raises(RegistryError, match="revoke nothing"):
        next_body(None, PURPOSES, {ZETA: ("zeta1", public_key_hex(keys["zeta1"]))}, revoke=["zeta9"])


def body_with(keys, entries):
    return {"schema": "signet-registry/1", "version": 1,
            "purposes": {p: {"label": label.decode()} for p, label in PURPOSES.items()}, "keys": entries}


def entry(key_id, purpose, key, status="current"):
    return {"key_id": key_id, "purpose": purpose, "public_key": public_key_hex(key), "status": status}


@pytest.mark.parametrize("make, why", [
    (lambda k: [entry("a", ZETA, k["zeta1"]), entry("a", LOG_PURPOSE, k["log"])], "twice"),
    (lambda k: [entry("a", ZETA, k["zeta1"], "verify-only"), entry("b", LOG_PURPOSE, k["zeta1"])], "revoking"),
    (lambda k: [entry("a", ZETA, k["zeta1"]), entry("b", ZETA, k["zeta2"])], "two current"),
    (lambda k: [entry("a", "unlisted", k["zeta1"])], "does not list"),
    (lambda k: [entry("a", ZETA, k["zeta1"], "retired")], "status"),
    (lambda k: [entry("a:b", ZETA, k["zeta1"])], "1 to 64"),
])
def test_ambiguous_bodies_are_refused(keys, make, why):
    with pytest.raises(RegistryError, match=why):
        check_body(body_with(keys, make(keys)))


def test_a_reserved_purpose_cannot_take_another_label(keys):
    body = body_with(keys, [])
    body["purposes"][LOG_PURPOSE] = {"label": "zeta-lock-result-signature/1\n"}
    with pytest.raises(RegistryError, match="fixed"):
        check_body(body)


def test_verifier_refuses_other_purposes_labels_unknown_keys_and_junk(keys):
    reg = load_registry(signed(first(keys), keys), public_key_hex(keys["root"]))
    verify = verifier(reg, ZETA)
    good = ZETA_LABEL + b"x"
    assert verify(b"delta-ledger-receipt-signature/1\nx", env("zeta1", keys["zeta1"], b"delta-ledger-receipt-signature/1\nx")) is False
    assert verify(good, env("log", keys["log"], good)) is False  # a key of another purpose
    assert verify(good, env("zeta1", keys["stranger"], good)) is False  # right id, wrong key
    assert verify(good, env("nobody", keys["zeta1"], good)) is False
    for junk in (b"", b"zeta1", b"zeta1:short", "zeta1:x", None):
        assert verify(good, junk) is False
    assert verify(bytearray(good), env("zeta1", keys["zeta1"], good)) is False


def test_checkpoint_checks_only_under_the_log_key(keys):
    reg = load_registry(signed(first(keys), keys), public_key_hex(keys["root"]))
    data = checkpoint_signing_input(5, "a" * 64)
    good = json.dumps({"schema": "signet-log-checkpoint/1", "length": 5, "head": "a" * 64,
                       "signature": env("log", keys["log"], data).hex()})
    assert check_checkpoint(good, reg) == (5, "a" * 64)
    bad = json.dumps({"schema": "signet-log-checkpoint/1", "length": 6, "head": "a" * 64,
                      "signature": env("log", keys["log"], data).hex()})
    with pytest.raises(ValueError, match="does not check out"):
        check_checkpoint(bad, reg)
