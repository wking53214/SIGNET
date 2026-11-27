"""The checker's memory (`signet.trust`): rollback, fork, resurrection and jumps refused, the memory only moves forward.

Baseline probes P1 to P3 (docs/SIGNET_BASELINE_v1.md) showed `load_registry` alone accepts each of these. It still
does, on purpose (a checker with no memory has nothing to compare with); each test below shows that, then shows the
memory refusing it.
"""

import ast
import json
import multiprocessing
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

import signet
from signet.names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from signet.registry import RegistryError, load_registry, next_body, public_key_hex, sign_registry
from signet.trust import TrustError, TrustState, TrustStore
from signet.verify import verifier

ZETA = "zeta-lock-result"
ZETA_LABEL = b"zeta-lock-result-signature/1\n"
PURPOSES = {ZETA: ZETA_LABEL, REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}


@pytest.fixture
def world():
    keys = {name: Ed25519PrivateKey.generate() for name in ("root", "zeta1", "zeta2", "log")}
    current = {REGISTRY_PURPOSE: ("root", public_key_hex(keys["root"])), ZETA: ("zeta1", public_key_hex(keys["zeta1"])),
               LOG_PURPOSE: ("log", public_key_hex(keys["log"]))}
    return keys, next_body(None, PURPOSES, current)


def signed(keys, body):
    return sign_registry(body, keys["root"], "root")


def variant(body, version, **statuses):
    out = {**body, "version": version, "keys": [dict(k) for k in body["keys"]]}
    for k in out["keys"]:
        if k["key_id"] in statuses:
            k["status"] = statuses[k["key_id"]]
    return out


def store(tmp_path, keys, **kw):
    return TrustStore.create(tmp_path / "trust.json", public_key_hex(keys["root"]), **kw)


def test_the_memory_accepts_an_honest_sequence_and_remembers_it(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    assert s.load(signed(keys, body)).version == 1
    v2 = variant(body, 2)
    assert s.load(signed(keys, v2)).version == 2
    assert s.load(signed(keys, v2)).version == 2  # the same file again is fine
    assert s.state().version == 2


def test_rollback_is_refused_without_the_checker_passing_any_number(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    old = signed(keys, body)
    s.load(old)
    s.load(signed(keys, variant(body, 2)))
    with pytest.raises(RegistryError, match="older"):
        s.load(old)


def test_fork_two_registries_with_one_version(tmp_path, world):
    """Baseline P1. load_registry alone accepts both; the memory refuses the second."""
    keys, body = world
    pin = public_key_hex(keys["root"])
    a, b = signed(keys, variant(body, 2)), signed(keys, variant(body, 2, zeta1="revoked"))
    assert load_registry(a, pin, min_version=2).body() != load_registry(b, pin, min_version=2).body()
    s = store(tmp_path, keys)
    s.load(a)
    with pytest.raises(TrustError, match="fork"):
        s.load(b)
    assert s.state().version == 2 and not s.state().revoked_ids


def test_resurrection_of_a_revoked_key(tmp_path, world):
    """Baseline P2. A root-signed later version makes a revoked key current again; the memory refuses it."""
    keys, body = world
    pin = public_key_hex(keys["root"])
    v2 = signed(keys, variant(body, 2, zeta1="revoked"))
    v3 = signed(keys, variant(body, 3, zeta1="current"))
    data = ZETA_LABEL + b"{}"
    sig = b"zeta1:" + keys["zeta1"].sign(data)
    assert verifier(load_registry(v3, pin, min_version=2), ZETA)(data, sig)  # the gap, still there without memory
    s = store(tmp_path, keys)
    s.load(v2)
    with pytest.raises(TrustError, match="resurrection"):
        s.load(v3)


def test_resurrection_under_a_new_id_is_refused(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, variant(body, 2, zeta1="revoked")))
    reborn = variant(body, 3)
    reborn["keys"] = [k for k in reborn["keys"] if k["key_id"] != "zeta1"]
    reborn["keys"].append({"key_id": "zeta9", "purpose": ZETA, "public_key": public_key_hex(keys["zeta1"]),
                           "status": "current"})
    reborn["keys"].sort(key=lambda k: k["key_id"])
    with pytest.raises(TrustError, match="another id"):
        s.load(signed(keys, reborn))


def test_a_revoked_key_may_be_dropped_and_stays_untrusted(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, variant(body, 2, zeta1="revoked")))
    dropped = variant(body, 3)
    dropped["keys"] = [k for k in dropped["keys"] if k["key_id"] != "zeta1"]
    assert s.load(signed(keys, dropped)).entry("zeta1") is None
    assert "zeta1" in s.state().revoked_ids


def test_a_jump_is_refused_when_the_checker_sets_a_step(tmp_path, world):
    """Baseline P3. Without max_step the jump is accepted (as before); with it, refused."""
    keys, body = world
    s = store(tmp_path, keys, max_step=10)
    s.load(signed(keys, body))
    with pytest.raises(TrustError, match="jump"):
        s.load(signed(keys, variant(body, 1000)))
    assert s.load(signed(keys, variant(body, 11))).version == 11


def test_a_missing_memory_stops_the_checker(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, variant(body, 2)))
    (tmp_path / "trust.json").unlink()
    with pytest.raises(TrustError, match="missing"):
        s.load(signed(keys, body))


def test_create_never_starts_over_an_existing_memory(tmp_path, world):
    keys, _ = world
    store(tmp_path, keys)
    with pytest.raises(TrustError, match="already exists"):
        store(tmp_path, keys)


def test_a_memory_under_another_root_is_refused(tmp_path, world):
    keys, body = world
    store(tmp_path, keys)
    other = TrustStore(tmp_path / "trust.json", public_key_hex(Ed25519PrivateKey.generate()))
    with pytest.raises(TrustError, match="another root"):
        other.load(signed(keys, body))


@pytest.mark.parametrize("edit", [
    lambda d: d.update(version=-1),
    lambda d: d.update(digest="zz"),
    lambda d: d.update(revoked_keys=["nothex"]),
    lambda d: d.update(extra=1),
    lambda d: d.update(schema="other"),
])
def test_a_damaged_memory_is_refused(tmp_path, world, edit):
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, body))
    doc = json.loads((tmp_path / "trust.json").read_text())
    edit(doc)
    (tmp_path / "trust.json").write_text(json.dumps(doc))
    with pytest.raises(TrustError):
        s.load(signed(keys, variant(body, 2)))


def test_a_refused_registry_leaves_the_memory_unchanged(tmp_path, world):
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, variant(body, 2)))
    before = (tmp_path / "trust.json").read_bytes()
    with pytest.raises(RegistryError):
        s.load(signed(keys, variant(body, 2, zeta1="revoked")))
    assert (tmp_path / "trust.json").read_bytes() == before


def _race(path, root, text, out):
    try:
        TrustStore(path, root).load(text)
        out.put("accepted")
    except TrustError as exc:
        out.put(str(exc).split(":")[0])


def test_two_checkers_sharing_a_memory_cannot_both_accept_a_fork(tmp_path, world):
    """Each checker process races to load its own version-2 file. The lock makes one accept and the other see a fork."""
    keys, body = world
    s = store(tmp_path, keys)
    s.load(signed(keys, body))
    texts = [signed(keys, variant(body, 2)), signed(keys, variant(body, 2, zeta1="revoked"))]
    ctx = multiprocessing.get_context("fork")
    out = ctx.Queue()
    procs = [ctx.Process(target=_race, args=(s.path, s.root, t, out)) for t in texts]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert sorted(out.get(timeout=5) for _ in procs) == ["accepted", "fork"]


@settings(max_examples=60, deadline=None)
@given(st.lists(st.tuples(st.integers(min_value=1, max_value=6), st.booleans(), st.booleans()), min_size=1,
                max_size=12))
def test_property_the_memory_never_accepts_a_non_monotonic_history(steps):
    """Random sequences of (version, revoke zeta1?, variant body?) offered to one memory. Whatever is accepted is
    non-decreasing in version, one body per version, and a revocation once accepted never comes undone."""
    keys = {name: Ed25519PrivateKey.generate() for name in ("root", "zeta1", "log")}
    current = {REGISTRY_PURPOSE: ("root", public_key_hex(keys["root"])), ZETA: ("zeta1", public_key_hex(keys["zeta1"])),
               LOG_PURPOSE: ("log", public_key_hex(keys["log"]))}
    body = next_body(None, PURPOSES, current)
    state = TrustState(public_key_hex(keys["root"]))
    pin = state.root
    accepted = []
    for version, revoke, alt in steps:
        b = variant(body, version, **({"zeta1": "revoked"} if revoke else {}))
        if alt:
            b["purposes"] = {**b["purposes"], "extra-purpose": {"label": "extra/1\n"}}
        registry = load_registry(signed(keys, b), pin)
        try:
            state = state.accept(registry)
        except TrustError:
            continue
        accepted.append((registry.version, state.digest, registry.entry("zeta1").status))
    for (v1, d1, _), (v2, d2, _) in zip(accepted, accepted[1:]):
        assert v2 >= v1 and (v2 != v1 or d2 == d1)
    seen_revoked = False
    for _, _, status in accepted:
        seen_revoked = seen_revoked or status == "revoked"
        assert not (seen_revoked and status != "revoked")


def test_signet_trust_is_caller_side():
    """CLAUDE.md rule 3 for the new module: a checker that imports it loads none of the signer side."""
    tree = ast.parse(Path(signet.__file__).with_name("trust.py").read_text())
    names = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module}
    assert not names & {"keys", "server", "log", "config"}
    code = "import sys, signet.trust; print(sorted(m for m in sys.modules if m in %r))" % [
        "signet.keys", "signet.server", "signet.log", "signet.config"]
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and done.stdout.strip() == "[]", done.stderr
