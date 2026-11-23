"""CLAUDE.md rule 3: what a caller and a checker import never reaches signet's keys, server, log or config.

A program that needs signatures imports `signet.client`; a checker imports `signet.verify` and `signet.registry`. If
any of those three pulled in the key store, a caller would have the code to read keys in its own process, which is
the thing signet exists to prevent. This reads the source and the import graph; nothing is assumed."""

import ast
import subprocess
import sys
from pathlib import Path

import signet

PACKAGE = Path(signet.__file__).parent
CALLER_SIDE = ("client", "verify", "registry")
FORBIDDEN = {"signet.keys", "signet.server", "signet.log", "signet.config"}


def imported(module: str) -> set:
    tree = ast.parse((PACKAGE / f"{module}.py").read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = "signet." + base if base else "signet"
            names.add(base)
            names.update(f"{base}.{a.name}" for a in node.names)
        elif isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
    return names


def test_caller_side_modules_do_not_import_the_signer_side():
    for module in CALLER_SIDE:
        assert not (imported(module) & FORBIDDEN), f"signet.{module} imports {imported(module) & FORBIDDEN}"


def test_importing_the_caller_side_loads_none_of_the_signer_side():
    code = ("import sys, signet.client, signet.verify, signet.registry; "
            "print(sorted(m for m in sys.modules if m in %r))" % sorted(FORBIDDEN))
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "[]"
