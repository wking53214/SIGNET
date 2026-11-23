"""An approval rule: read from the config, published in the signed registry, and refused when it could never be safe."""

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signet.approval import MIN_QUORUM, check_rule, counted, message
from signet.config import ConfigError, parse
from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import RegistryError, check_body, load_registry, next_body, public_key_hex, sign_registry

CAP = "humanity-capability"
CAP_LABEL = b"stack-capability/2\n"
DOMAIN = "humanity-issuer/approval/1\n"


def approvers(n):
    keys = [Ed25519PrivateKey.generate() for _ in range(n)]
    return sorted(keys, key=public_key_hex)


def rule(keys, quorum=2, domain=DOMAIN):
    return {"domain": domain, "approvers": [public_key_hex(k) for k in keys], "quorum": quorum}


def config(spec_rule):
    return {"schema": "signet-config/1", "socket": "/run/s.sock", "keys_dir": "/k", "log": "/l",
            "registry_key_id": "root", "log_key_id": "log",
            "purposes": {CAP: {"key_id": "cap", "label": CAP_LABEL.decode(), "allowed_uids": [1],
                               "approval": spec_rule}}}


def test_a_config_with_a_rule_reads():
    keys = approvers(3)
    cfg = parse(json.dumps(config(rule(keys))))
    got = cfg.purposes[CAP].approval
    assert got.quorum == 2 and got.domain == DOMAIN.encode() and len(got.approvers) == 3


def test_a_purpose_without_a_rule_has_none():
    doc = config(rule(approvers(2)))
    del doc["purposes"][CAP]["approval"]
    assert parse(json.dumps(doc)).purposes[CAP].approval is None


@pytest.mark.parametrize("change, why", [
    (lambda r: r.update(quorum=1), f"at least {MIN_QUORUM}"),
    (lambda r: r.update(quorum=0), f"at least {MIN_QUORUM}"),
    (lambda r: r.update(quorum=True), f"at least {MIN_QUORUM}"),
    (lambda r: r.update(quorum=4), "nothing could pass"),
    (lambda r: r.update(approvers=r["approvers"][:1] * 2), "listed twice"),
    (lambda r: r.update(approvers=list(reversed(r["approvers"]))), "sorted order"),
    (lambda r: r.update(approvers=[]), "1 to 16"),
    (lambda r: r.update(approvers=["AB" * 32] + r["approvers"][1:]), "64 lowercase hex"),
    (lambda r: r.update(domain=CAP_LABEL.decode()), "must differ"),
    (lambda r: r.update(domain="no newline"), "label"),
    (lambda r: r.update(extra=1), "exactly domain"),
])
def test_an_unsafe_rule_is_refused(change, why):
    r = rule(approvers(3))
    change(r)
    with pytest.raises(ConfigError, match=why):
        parse(json.dumps(config(r)))


def test_a_rule_cannot_list_more_than_sixteen_approvers():
    with pytest.raises(ValueError, match="1 to 16"):
        check_rule(rule(approvers(17)), CAP_LABEL)


def test_only_distinct_listed_approvers_with_a_good_signature_count():
    a, b, c = approvers(3)
    stranger = Ed25519PrivateKey.generate()
    r = check_rule(rule([a, b]), CAP_LABEL)
    data, summary = CAP_LABEL + b"slip", b"\x11" * 32
    signed = message(r.domain, data, summary)

    def ok(key, over=signed):
        return f"{public_key_hex(key)}:{key.sign(over).hex()}"
    assert counted(r, data, summary, [ok(a), ok(b)]) == sorted([public_key_hex(a), public_key_hex(b)])
    assert counted(r, data, summary, [ok(a), ok(a)]) == [public_key_hex(a)]
    assert counted(r, data, summary, [ok(a), ok(stranger), ok(c)]) == [public_key_hex(a)]
    assert counted(r, data, summary, [ok(a), ok(b, message(r.domain, data + b"!", summary))]) == [public_key_hex(a)]
    assert counted(r, data, summary, [ok(a), ok(b, message(r.domain, data, b"\x22" * 32))]) == [public_key_hex(a)]
    assert counted(r, data, summary, [ok(a), f"{public_key_hex(b)}:zz", "garbage"]) == [public_key_hex(a)]


def registry_keys():
    return {name: Ed25519PrivateKey.generate() for name in ("root", "log", "cap")}


def body_with(rules, keys, previous=None):
    current = {REGISTRY_PURPOSE: ("root", public_key_hex(keys["root"])), LOG_PURPOSE: ("log", public_key_hex(keys["log"])),
               CAP: ("cap", public_key_hex(keys["cap"]))}
    labels = {REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL, CAP: CAP_LABEL}
    return next_body(previous, labels, current, approvals=rules)


def test_the_registry_publishes_the_rule_signed_and_a_checker_reads_it():
    keys = registry_keys()
    r = check_rule(rule(approvers(2)), CAP_LABEL)
    text = sign_registry(body_with({CAP: r}, keys), keys["root"], "root")
    reg = load_registry(text, public_key_hex(keys["root"]))
    assert reg.approvals[CAP] == r
    assert check_body(reg.body()) == reg


def test_changing_the_approvers_is_a_new_signed_version_and_dropping_the_rule_drops_it():
    keys = registry_keys()
    first = load_registry(sign_registry(body_with({CAP: check_rule(rule(approvers(2)), CAP_LABEL)}, keys), keys["root"],
                                        "root"), public_key_hex(keys["root"]))
    changed = check_rule(rule(approvers(3), quorum=3), CAP_LABEL)
    second = check_body(body_with({CAP: changed}, keys, previous=first))
    assert second.version == 2 and second.approvals[CAP] == changed
    assert CAP not in check_body(body_with({}, keys, previous=first)).approvals


def test_a_registry_without_any_rule_still_reads():
    keys = registry_keys()
    reg = load_registry(sign_registry(body_with({}, keys), keys["root"], "root"), public_key_hex(keys["root"]))
    assert reg.approvals == {}


def test_a_rule_on_signets_own_purpose_or_an_unsafe_rule_in_a_registry_is_refused():
    keys = registry_keys()
    body = body_with({}, keys)
    own = json.loads(json.dumps(body))
    own["purposes"][REGISTRY_PURPOSE]["approval"] = rule(approvers(2))
    with pytest.raises(RegistryError, match="takes no approval rule"):
        check_body(own)
    weak = json.loads(json.dumps(body))
    weak["purposes"][CAP]["approval"] = rule(approvers(2), quorum=1)
    with pytest.raises(RegistryError, match="at least 2"):
        check_body(weak)
