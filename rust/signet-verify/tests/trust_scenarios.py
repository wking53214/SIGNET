"""Registry sequences and signet's own answers for them, for rust/signet-verify/tests/trust.rs.

Each sequence starts from an empty memory (`TrustState(root)`) and feeds registries in order, as a checker would over
time. For each step it records whether signet's `signet.trust` accepts it and, if so, the memory it moves to, written
as signet writes it. The Rust checker must give the same answer at every step and write the same bytes.

Prints one JSON object: {"root": "<64 hex>", "steps": [...]}. Fresh keys every run.
"""

from __future__ import annotations

import copy
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from signet.approval import Approval
from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import RegistryError, check_body, load_registry, next_body, public_key_hex, signing_input
from signet.strict import canonical
from signet.trust import TrustState

ZETA, DELTA = "zeta-lock-result", "delta-receipt"


def main() -> None:
    k = {n: Ed25519PrivateKey.generate() for n in ("root", "log", "zeta1", "zeta2", "delta1", "delta2")}
    pin = public_key_hex(k["root"])
    labels = {ZETA: b"zeta-lock-result-signature/1\n", DELTA: b"delta-ledger-receipt-signature/1\n",
              REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}
    cur = {REGISTRY_PURPOSE: ("root-1", pin), LOG_PURPOSE: ("log-1", public_key_hex(k["log"])),
           ZETA: ("zeta-1", public_key_hex(k["zeta1"])), DELTA: ("delta-1", public_key_hex(k["delta1"]))}

    def signed(body) -> str:
        sig = b"root-1:" + k["root"].sign(signing_input(body))
        return canonical({"registry": body, "signature": sig.hex()}).decode("ascii") + "\n"

    # An approval rule on delta's purpose, carried through every version, as HUMANITY's real purpose has one.
    team = sorted(public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))
    rule = {DELTA: Approval(b"delta/approval/1\n", tuple(team), 2)}
    v1 = next_body(None, labels, cur, approvals=rule)
    v2 = next_body(check_body(v1), labels, {**cur, ZETA: ("zeta-2", public_key_hex(k["zeta2"]))}, approvals=rule)
    fork2 = next_body(check_body(v1), labels, {**cur, DELTA: ("delta-2", public_key_hex(k["delta2"]))}, approvals=rule)
    reordered2 = copy.deepcopy(v2)
    reordered2["keys"].reverse()
    v3 = next_body(check_body(v2), labels, {**cur, ZETA: ("zeta-2", public_key_hex(k["zeta2"])),
                                            DELTA: ("delta-2", public_key_hex(k["delta2"]))}, revoke=["delta-1"],
                   approvals=rule)
    back = copy.deepcopy(v3)
    back["version"] = 4
    for e in back["keys"]:
        if e["key_id"] == "delta-1":
            e["status"] = "verify-only"
    renamed = copy.deepcopy(v3)
    renamed["version"] = 4
    for e in renamed["keys"]:
        if e["key_id"] == "delta-1":
            e["key_id"], e["status"] = "delta-9", "verify-only"
    dropped = copy.deepcopy(v3)
    dropped["version"] = 4
    dropped["keys"] = [e for e in dropped["keys"] if e["key_id"] != "delta-1"]
    far = copy.deepcopy(v1)
    far["version"] = 5

    sequences = {
        "history": (None, [
            ("v1", v1), ("v1 again", v1), ("v2 rotates zeta", v2), ("v1 replayed (rollback)", v1),
            ("a second, different v2 (fork)", fork2), ("v2 with its key list reordered", reordered2),
            ("v3 revokes delta-1", v3), ("v4 lists delta-1 again (resurrection by id)", back),
            ("v4 lists delta-1's key under a new id (resurrection by key)", renamed),
            ("v4 drops delta-1", dropped), ("v3 replayed (rollback)", v3),
        ]),
        "bounded": (2, [("v1", v1), ("v5 (a jump past max_step 2)", far), ("v3", v3)]),
    }
    steps = []
    for seq, (max_step, items) in sequences.items():
        state = TrustState(pin)
        for name, body in items:
            text = signed(body)
            try:
                registry = load_registry(text, pin, min_version=max(state.version, 1))
                state = state.accept(registry, max_step=max_step)
                accept, out = True, canonical(state.as_json()).decode("ascii") + "\n"
            except RegistryError:
                accept, out = False, None
            steps.append({"sequence": seq, "name": name, "text": text, "max_step": max_step, "accept": accept,
                          "state": out})
    assert all('"approval"' in st["text"] for st in steps), "every registry carries the approval rule"
    json.dump({"root": pin, "steps": steps}, sys.stdout)


if __name__ == "__main__":
    main()
