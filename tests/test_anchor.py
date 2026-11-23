"""signet_anchor: what an outside anchor catches that the log alone cannot (a whole rewrite, lost history, a fork, an
older registry), and that the package stays separable from signet.

Moves with signet_anchor (docs/OUTSIDE_ANCHOR_v1.md). It uses signet's own test helper, `tests/instance.py`.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import signet
import signet_anchor
from instance import ZETA_LABEL, Instance, cli
from signet.client import request
from signet.registry import RegistryError, load_registry
from signet_anchor import AnchorError, check, latest_registry, publish_checkpoint, publish_registry


def sign(inst: Instance, n: int = 1) -> None:
    for i in range(n):
        request(inst.socket, "zeta-lock-result", ZETA_LABEL.encode() + f"entry {i}".encode())


def checkpoint(inst: Instance, name: str) -> bytes:
    out = inst.root / name
    done = cli("checkpoint", "--config", str(inst.config), "--out", str(out))
    assert done.returncode == 0, done.stderr
    return out.read_bytes()


def fresh(path: Path, **kw) -> Instance:
    path.mkdir()
    return Instance(path, **kw)


def rewrite(inst: Instance, n: int) -> None:
    """What signet's operator could do: throw the log away and write a new, consistent one."""
    inst.kill()
    inst.log.unlink()
    inst.start()
    sign(inst, n)


@pytest.fixture
def live(tmp_path):
    inst = fresh(tmp_path / "signet").start()
    yield inst
    inst.kill()


@pytest.fixture
def anchor(tmp_path, live):
    path = tmp_path / "anchor"
    publish_registry(path, live.registry().read_bytes(), live.root_key())
    return path


def test_a_log_that_extends_every_published_checkpoint_checks_clean(live, anchor):
    sign(live, 3)
    publish_checkpoint(anchor, checkpoint(live, "c1.json"), live.log, live.root_key())
    sign(live, 2)
    publish_checkpoint(anchor, checkpoint(live, "c2.json"), live.log, live.root_key())
    sign(live, 1)  # signing goes on after the last checkpoint; that is fine
    assert check(anchor, live.log, live.root_key()) == []
    assert sorted(p.name for p in (anchor / "checkpoints").iterdir()) == ["000001.json", "000002.json"]


def test_a_whole_rewrite_the_log_alone_cannot_see_is_found(live, anchor):
    sign(live, 3)
    publish_checkpoint(anchor, checkpoint(live, "c1.json"), live.log, live.root_key())
    rewrite(live, 4)
    assert cli("verify-log", "--log", str(live.log)).returncode == 0  # the new chain is consistent on its own
    problems = check(anchor, live.log, live.root_key())
    assert len(problems) == 1 and "history was rewritten" in problems[0]


def test_lost_history_is_found(live, anchor):
    sign(live, 3)
    publish_checkpoint(anchor, checkpoint(live, "c1.json"), live.log, live.root_key())
    rewrite(live, 1)
    problems = check(anchor, live.log, live.root_key())
    assert len(problems) == 1 and "history was lost" in problems[0]


def test_a_fork_is_found_and_a_rewritten_log_cannot_be_published(live, anchor):
    sign(live, 3)
    first = checkpoint(live, "c1.json")
    publish_checkpoint(anchor, first, live.log, live.root_key())
    rewrite(live, 3)
    second = checkpoint(live, "c2.json")  # validly signed, same length, another head
    with pytest.raises(AnchorError, match="already fails its check"):
        publish_checkpoint(anchor, second, live.log, live.root_key())
    (anchor / "checkpoints" / "000002.json").write_bytes(second)  # planted by hand, past publish
    problems = check(anchor, live.log, live.root_key())
    assert any("forked" in p for p in problems) and any("rewritten" in p for p in problems)


def test_published_history_going_backwards_is_found(live, anchor):
    sign(live, 1)
    short = checkpoint(live, "c1.json")
    sign(live, 2)
    publish_checkpoint(anchor, checkpoint(live, "c2.json"), live.log, live.root_key())
    with pytest.raises(AnchorError, match="already covers"):
        publish_checkpoint(anchor, short, live.log, live.root_key())
    (anchor / "checkpoints" / "000002.json").write_bytes(short)
    assert any("went backwards" in p for p in check(anchor, live.log, live.root_key()))


def test_a_checkpoint_from_another_signet_or_for_another_log_is_refused(live, anchor, tmp_path):
    sign(live, 2)
    stranger = fresh(tmp_path / "stranger").start()
    try:
        sign(stranger, 2)
        foreign = checkpoint(stranger, "c.json")
    finally:
        stranger.kill()
    with pytest.raises(AnchorError, match="does not check out"):
        publish_checkpoint(anchor, foreign, live.log, live.root_key())


def test_a_checkpoint_that_does_not_match_the_live_log_is_refused(live, anchor):
    sign(live, 2)
    taken = checkpoint(live, "c1.json")
    rewrite(live, 3)
    with pytest.raises(AnchorError, match="does not match the live log"):
        publish_checkpoint(anchor, taken, live.log, live.root_key())


def test_the_anchor_never_replaces_a_file(live, anchor):
    sign(live, 1)
    publish_checkpoint(anchor, checkpoint(live, "c1.json"), live.log, live.root_key())
    before = (anchor / "checkpoints" / "000001.json").read_bytes()
    with pytest.raises(AnchorError, match="never replaces"):
        signet_anchor.anchor._write_new(anchor / "checkpoints", 1, b"{}")
    assert (anchor / "checkpoints" / "000001.json").read_bytes() == before


def test_the_anchor_is_the_checkers_memory_of_the_newest_registry(live, anchor):
    first = (live.root / "registry.json").read_bytes()
    second = live.registry("registry-2.json", "--previous", str(live.root / "registry.json"),
                           "--root-key", live.root_key()).read_bytes()
    publish_registry(anchor, second, live.root_key())
    newest = latest_registry(anchor, live.root_key())
    assert newest.version == 2
    with pytest.raises(RegistryError, match="older than version 2"):
        load_registry(first, live.root_key(), min_version=newest.version)
    with pytest.raises(AnchorError, match="older than version 3"):
        publish_registry(anchor, first, live.root_key())
    with pytest.raises(AnchorError, match="older than version 3"):
        publish_registry(anchor, second, live.root_key())


def test_a_registry_under_another_root_is_refused(live, anchor, tmp_path):
    stranger = fresh(tmp_path / "stranger2")
    with pytest.raises(AnchorError, match="pinned root"):
        publish_registry(anchor, stranger.registry().read_bytes(), live.root_key())


def test_the_command_line_publishes_and_checks(live, anchor):
    sign(live, 2)
    cp = live.root / "c1.json"
    cp.write_bytes(checkpoint(live, "c0.json"))

    def run(*args):
        return subprocess.run([sys.executable, "-m", "signet_anchor", *args], capture_output=True, text=True, timeout=60)
    base = ("--anchor", str(anchor), "--root-key", live.root_key())
    assert run("publish-checkpoint", *base, "--checkpoint", str(cp), "--log", str(live.log)).returncode == 0
    assert run("check", *base, "--log", str(live.log)).returncode == 0
    rewrite(live, 3)
    done = run("check", *base, "--log", str(live.log))
    assert done.returncode == 1 and "rewritten" in done.stderr


# --- separable: signet_anchor can be lifted out without touching signet ------------------------------------------

FORBIDDEN = {"signet.keys", "signet.server", "signet.config"}


def _imports(path: Path) -> set:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.add(node.module)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    return names


def test_signet_anchor_never_imports_signets_keys_server_or_config():
    for path in Path(signet_anchor.__file__).parent.glob("*.py"):
        assert not (_imports(path) & FORBIDDEN), f"{path.name} imports {_imports(path) & FORBIDDEN}"
    code = "import sys, signet_anchor; print(sorted(m for m in sys.modules if m in %r))" % sorted(FORBIDDEN)
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0 and done.stdout.strip() == "[]", done.stderr


def test_nothing_in_signet_imports_signet_anchor():
    for path in Path(signet.__file__).parent.glob("*.py"):
        assert not any(n.startswith("signet_anchor") for n in _imports(path)), path.name
