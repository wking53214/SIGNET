"""Write the verification test vectors: docs/vectors/signet-vectors-v1.json.

Each case names its input and the answer a correct verifier must give. Python's verifier (`signet.registry`,
`signet.verify`) and the independent Rust verifier (`rust/signet-verify`) are both tested against the same file and
must give every answer, refusals included. Regenerating makes new keys; commit the result.

    python tools/make_vectors.py
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import next_body, public_key_hex, sign_registry, signing_input
from signet.strict import canonical
from signet.verify import checkpoint_signing_input

OUT = Path(__file__).resolve().parent.parent / "docs" / "vectors" / "signet-vectors-v1.json"
ZETA, DELTA = "zeta-lock-result", "delta-receipt"
ZL, DL = b"zeta-lock-result-signature/1\n", b"delta-ledger-receipt-signature/1\n"


def main() -> None:
    k = {n: Ed25519PrivateKey.generate() for n in ("root", "log", "zeta1", "zeta2", "delta1", "stranger")}
    pin = public_key_hex(k["root"])
    labels = {ZETA: ZL, DELTA: DL, REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}
    cur = {REGISTRY_PURPOSE: ("root-1", pin), LOG_PURPOSE: ("log-1", public_key_hex(k["log"])),
           ZETA: ("zeta-1", public_key_hex(k["zeta1"])), DELTA: ("delta-1", public_key_hex(k["delta1"]))}
    from signet.approval import Approval
    team = sorted(public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))
    rule = {DELTA: Approval(b"delta/approval/1\n", tuple(team), 2)}
    v1 = next_body(None, labels, cur, approvals=rule)
    from signet.registry import check_body
    v2 = next_body(check_body(v1), labels, {**cur, ZETA: ("zeta-2", public_key_hex(k["zeta2"]))}, approvals=rule)
    v3 = next_body(check_body(v2), labels, cur | {ZETA: ("zeta-2", public_key_hex(k["zeta2"]))}, revoke=["delta-1"],
                   approvals=rule)
    t1, t2, t3 = (sign_registry(b, k["root"], "root-1") for b in (v1, v2, v3))

    def raw_sign(body, key=k["root"], key_id="root-1"):
        return canonical({"registry": body, "signature": (key_id.encode() + b":" + key.sign(
            signing_input(body))).hex()}).decode() + "\n"

    registries = []

    def reg(name, text, accept, min_version=1, root=pin):
        registries.append({"name": name, "text": text, "root": root, "min_version": min_version, "accept": accept})

    reg("v1, with an approval rule", t1, True)
    reg("v2 rotates zeta", t2, True)
    reg("v3 revokes delta-1", t3, True)
    reg("v3 pretty-printed and keys reordered (whitespace is not signed)",
        json.dumps(json.loads(t3), indent=3, sort_keys=False), True)
    reg("v1 refused at min_version 2 (rollback)", t1, False, min_version=2)
    reg("v1 under another pinned root", t1, False, root=public_key_hex(k["stranger"]))
    edited = json.loads(t2)
    edited["registry"]["keys"][0]["status"] = "verify-only"
    reg("v2 with one status edited after signing", json.dumps(edited), False)
    reg("a key twice in one object", t1.replace('{"registry":', '{"signature":"00","registry":', 1), False)
    reg("a key twice, once spelled with an escape", t1.replace('{"registry":', '{"\\u0072egistry":{},"registry":', 1),
        False)
    reg("a float in the file", t1.replace('"version":1', '"version":1.0', 1), False)
    reg("an integer past 2**53-1", t1.replace('"version":1', '"version":9007199254740993', 1), False)
    two = json.loads(json.dumps(v1))
    for e in two["keys"]:
        if e["key_id"] == "zeta-1":
            e["status"] = "current"
    two["keys"].append({"key_id": "zeta-9", "purpose": ZETA, "public_key": public_key_hex(k["zeta2"]),
                        "status": "current"})
    reg("two current keys for one purpose (signed by the real root)", raw_sign(two), False)
    dup = json.loads(json.dumps(v1))
    dup["keys"].append({"key_id": "zeta-9", "purpose": ZETA, "public_key": public_key_hex(k["zeta1"]),
                        "status": "verify-only"})
    reg("one public key under two ids", raw_sign(dup), False)
    unlisted = json.loads(json.dumps(v1))
    unlisted["keys"].append({"key_id": "x-1", "purpose": "not-listed", "public_key": public_key_hex(k["stranger"]),
                             "status": "current"})
    reg("a key for a purpose the registry does not list", raw_sign(unlisted), False)
    revoked_root = json.loads(json.dumps(v1))
    for e in revoked_root["keys"]:
        if e["key_id"] == "root-1":
            e["status"] = "revoked"
    reg("signed by a root the registry lists as revoked", raw_sign(revoked_root), False)
    reg("signed under an id the registry does not list", raw_sign(v1, key_id="root-9"), False)
    bad_label = json.loads(json.dumps(v1))
    bad_label["purposes"][ZETA]["label"] = "zeta\tlabel\n"
    reg("a label with a tab", raw_sign(bad_label), False)
    reserved = json.loads(json.dumps(v1))
    reserved["purposes"][LOG_PURPOSE]["label"] = "another/1\n"
    reg("signet's own purpose given another label", raw_sign(reserved), False)
    zero = json.loads(json.dumps(v1))
    zero["version"] = 0
    reg("version 0", raw_sign(zero), False)
    extra = json.loads(json.dumps(v1))
    extra["comment"] = "hi"
    reg("an extra field in the registry", raw_sign(extra), False)
    reg("not an object at the top", "[1,2]", False)
    reg("trailing bytes after the object", t1.strip() + " {}", False)
    reg("upper-case hex in a public key", t1.replace(pin, pin.upper()), False)
    reg("a lone surrogate in a key id", t1.replace('"zeta-1"', '"zeta-\\ud800"', 1), False)

    signatures = []

    def sig(name, registry, purpose, data, signature, accept):
        signatures.append({"name": name, "registry": registry, "purpose": purpose, "data": data.hex(),
                           "signature": signature.hex(), "accept": accept})

    zd, dd = ZL + b'{"lock":"r1"}', DL + b'{"entry":7}'
    s_z1 = b"zeta-1:" + k["zeta1"].sign(zd)
    s_z2 = b"zeta-2:" + k["zeta2"].sign(zd)
    s_d1 = b"delta-1:" + k["delta1"].sign(dd)
    sig("current zeta key", 1, ZETA, zd, s_z2, True)
    sig("retired zeta key still checks (verify-only)", 1, ZETA, zd, s_z1, True)
    sig("delta key before its revocation", 1, DELTA, dd, s_d1, True)
    sig("delta key after its revocation", 2, DELTA, dd, s_d1, False)
    sig("a zeta signature checked as delta", 2, DELTA, zd, s_z2, False)
    sig("bytes without the purpose's label", 2, ZETA, b"no label", b"zeta-2:" + k["zeta2"].sign(b"no label"), False)
    sig("data changed after signing", 2, ZETA, zd + b" ", s_z2, False)
    sig("a stranger's signature under a listed id", 2, ZETA, zd, b"zeta-2:" + k["stranger"].sign(zd), False)
    sig("an id the registry does not list", 2, ZETA, zd, b"zeta-7:" + k["zeta2"].sign(zd), False)
    sig("no envelope", 2, ZETA, zd, k["zeta2"].sign(zd), False)
    sig("a signature one byte short", 2, ZETA, zd, s_z2[:-1], False)
    sig("the root key signing for zeta", 2, ZETA, zd, b"root-1:" + k["root"].sign(zd), False)
    raw = bytearray(s_z2)
    raw[-1] ^= 1
    sig("one bit flipped in the signature", 2, ZETA, zd, bytes(raw), False)
    sig("a key id with a non-ASCII byte", 2, ZETA, zd, b"zeta-\xc3\xa9:" + k["zeta2"].sign(zd), False)

    checkpoints = []

    def cp(name, registry, text, accept, length=None, head=None):
        checkpoints.append({"name": name, "registry": registry, "text": text, "accept": accept, "length": length,
                            "head": head})

    head = "ab" * 32
    c1 = canonical({"schema": "signet-log-checkpoint/1", "length": 5, "head": head, "signature": (
        b"log-1:" + k["log"].sign(checkpoint_signing_input(5, head))).hex()}).decode()
    c2 = canonical({"schema": "signet-log-checkpoint/2", "length": 9, "head": head, "at_ms": 1764000000000,
                    "previous": "cd" * 32, "signature": (b"log-1:" + k["log"].sign(checkpoint_signing_input(
                        9, head, at_ms=1764000000000, previous="cd" * 32))).hex()}).decode()
    cp("schema 1", 2, c1, True, 5, head)
    cp("schema 2, chained", 2, c2, True, 9, head)
    cp("schema 1 with its length edited", 2, c1.replace('"length":5', '"length":6'), False)
    cp("schema 2 with at_ms edited", 2, c2.replace("1764000000000", "1764000000001"), False)
    cp("signed by the zeta key", 2, canonical({"schema": "signet-log-checkpoint/1", "length": 5, "head": head,
                                                "signature": (b"zeta-2:" + k["zeta2"].sign(
                                                    checkpoint_signing_input(5, head))).hex()}).decode(), False)
    cp("schema 2 fields under schema 1", 2, c2.replace("checkpoint/2", "checkpoint/1"), False)
    cp("schema 2 with a malformed previous", 2, canonical({
        "schema": "signet-log-checkpoint/2", "length": 9, "head": head, "at_ms": 1, "previous": "xyz",
        "signature": "00"}).decode(), False)

    doc = {"schema": "signet-vectors/1", "root": pin,
           "about": "signature and checkpoint cases name their registry by its index in signature_registries. Every verifier of signet's formats must give each answer here. See tools/make_vectors.py.",
           "registries": registries, "signature_registries": [t1, t2, t3], "signatures": signatures,
           "checkpoints": checkpoints}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=1) + "\n")
    print(f"wrote {OUT}: {len(registries)} registries, {len(signatures)} signatures, {len(checkpoints)} checkpoints")


if __name__ == "__main__":
    main()
