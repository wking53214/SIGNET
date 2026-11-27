"""signet's own verifier against the shared test vectors (docs/vectors/signet-vectors-v1.json, tools/make_vectors.py).

The independent Rust verifier (rust/signet-verify) is tested against the same file; both must give every answer."""

import json
from pathlib import Path

import pytest

from signet.registry import RegistryError, load_registry
from signet.verify import read_checkpoint, verifier

VECTORS = json.loads((Path(__file__).resolve().parent.parent / "docs" / "vectors" / "signet-vectors-v1.json").read_text())


@pytest.mark.parametrize("case", VECTORS["registries"], ids=lambda c: c["name"])
def test_registry_vectors(case):
    try:
        load_registry(case["text"], case["root"], min_version=case["min_version"])
        accepted = True
    except RegistryError:
        accepted = False
    assert accepted == case["accept"]


@pytest.mark.parametrize("case", VECTORS["signatures"], ids=lambda c: c["name"])
def test_signature_vectors(case):
    registry = load_registry(VECTORS["signature_registries"][case["registry"]], VECTORS["root"])
    ok = verifier(registry, case["purpose"])(bytes.fromhex(case["data"]), bytes.fromhex(case["signature"]))
    assert ok == case["accept"]


@pytest.mark.parametrize("case", VECTORS["checkpoints"], ids=lambda c: c["name"])
def test_checkpoint_vectors(case):
    registry = load_registry(VECTORS["signature_registries"][case["registry"]], VECTORS["root"])
    try:
        cp = read_checkpoint(case["text"], registry)
        assert (cp.length, cp.head) == (case["length"], case["head"])
        accepted = True
    except ValueError:
        accepted = False
    assert accepted == case["accept"]
