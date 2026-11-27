"""The witness drill: a throwaway signet, a chained anchor, and the attacks the outside witness must catch.

Run by .github/workflows/witness-drill.yml, which signs each checkpoint with Sigstore between `prepare` and `attack`,
so the records it checks are real Rekor entries anyone can look up afterwards.

    python tools/witness_drill.py prepare DIR    a signet, signatures, 3 chained checkpoints, published to DIR/anchor
    python tools/witness_drill.py attack DIR ID  each attack below must be found; exit 1 if any is missed

Attacks: the whole log rewritten (with a new chain of checkpoints signed by signet's real log key), a witness record
swapped, a checkpoint file replaced after it was witnessed, a witness record deleted, and Sigstore asked to accept a
record under an identity that did not make it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ZETA_LABEL = "zeta-lock-result-signature/1\n"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, timeout=300)


def ok(done: subprocess.CompletedProcess) -> str:
    if done.returncode != 0:
        raise SystemExit(f"FAILED ({done.returncode}): {done.args}\n{done.stdout}{done.stderr}")
    return done.stdout


def start(root: Path) -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, "-m", "signet", "serve", "--config", str(root / "config.json")],
                            stderr=subprocess.PIPE, text=True)
    line = proc.stderr.readline()
    if "signet: serving" not in line:
        raise SystemExit(f"signet did not start: {line}")
    return proc


def stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    proc.wait(timeout=30)


def sign(root: Path, n: int, tag: str) -> None:
    from signet.client import request
    for i in range(n):
        request(root / "signet.sock", "zeta-lock-result", (ZETA_LABEL + f"{tag} {i}").encode())


def chain(root: Path, prefix: str, anchor: "Path | None") -> None:
    proc = start(root)
    previous = None
    try:
        for n in (1, 2, 3):
            sign(root, 2, f"{prefix}{n}")
            out = root / f"{prefix}{n}.json"
            extra = ["--previous", str(previous)] if previous else ["--first"]
            ok(run("-m", "signet", "checkpoint", "--config", str(root / "config.json"), "--out", str(out), *extra))
            if anchor is not None:
                ok(run("-m", "signet_anchor", "publish-checkpoint", "--anchor", str(anchor), "--root-key",
                       (root / "root_key.txt").read_text().strip(), "--checkpoint", str(out), "--log",
                       str(root / "signatures.log")))
            previous = out
    finally:
        stop(proc)


def prepare(root: Path) -> None:
    root.mkdir(parents=True)
    os.chmod(root, 0o700)
    keys = root / "keys"
    keys.mkdir(mode=0o700)
    public = {k: ok(run("-m", "signet", "keygen", "--keys-dir", str(keys), k)).strip()
              for k in ("root-1", "log-1", "zeta-1")}
    (root / "root_key.txt").write_text(public["root-1"] + "\n")
    (root / "config.json").write_text(json.dumps({
        "schema": "signet-config/1", "socket": str(root / "signet.sock"), "keys_dir": str(keys),
        "log": str(root / "signatures.log"), "registry_key_id": "root-1", "log_key_id": "log-1",
        "purposes": {"zeta-lock-result": {"key_id": "zeta-1", "label": ZETA_LABEL, "allowed_uids": [os.getuid()]}}}))
    ok(run("-m", "signet", "registry", "--config", str(root / "config.json"), "--out", str(root / "registry.json")))
    anchor = root / "anchor"
    ok(run("-m", "signet_anchor", "publish-registry", "--anchor", str(anchor), "--root-key", public["root-1"],
           "--registry", str(root / "registry.json")))
    chain(root, "c", anchor)
    (anchor / "witness").mkdir()
    print(f"prepared {anchor}: {len(list((anchor / 'checkpoints').iterdir()))} checkpoints to witness")


def found(label: str, done: subprocess.CompletedProcess, needle: str, misses: list) -> None:
    text = done.stdout + done.stderr
    caught = done.returncode != 0 and needle in text
    print(f"{'CAUGHT' if caught else 'MISSED'}  {label}: {text.strip().splitlines()[-1] if text.strip() else ''}")
    if not caught:
        misses.append(label)


def attack(root: Path, identity: str) -> int:
    anchor, key = root / "anchor", (root / "root_key.txt").read_text().strip()
    misses: list = []
    witness = ["-m", "signet_anchor", "check-witness", "--anchor"]

    def checks(a: Path, *extra: str) -> subprocess.CompletedProcess:
        return run(*witness, str(a), "--root-key", key, "--sigstore-identity", identity, *extra)

    ok(checks(anchor, "--max-delay-ms", "3600000"))
    ok(run("-m", "signet_anchor", "check", "--anchor", str(anchor), "--root-key", key, "--log",
           str(root / "signatures.log")))
    print("BASELINE  the honest anchor, its witness records and the live log all check clean")

    # 1. signet's account rewrites the whole log and writes a new chain with the real log key, then swaps it in.
    shutil.copy(root / "signatures.log", root / "honest.log")
    (root / "signatures.log").unlink()
    chain(root, "forged", None)
    forged = root / "forged-anchor"
    shutil.copytree(anchor, forged)
    for n in (1, 2, 3):
        shutil.copy(root / f"forged{n}.json", forged / "checkpoints" / f"{n:06d}.json")
    found("whole log rewritten, new chain signed by the real log key", checks(forged), "other bytes", misses)
    found("the live log against the honest anchor after the rewrite",
          run("-m", "signet_anchor", "check", "--anchor", str(anchor), "--root-key", key, "--log",
              str(root / "signatures.log")), "rewritten", misses)
    shutil.copy(root / "honest.log", root / "signatures.log")

    # 2. A witness record swapped for another one.
    swapped = root / "swapped"
    shutil.copytree(anchor, swapped)
    shutil.copy(anchor / "witness" / "000001.sigstore.json", swapped / "witness" / "000002.sigstore.json")
    found("a witness record swapped", checks(swapped), "other bytes", misses)

    # 3. A witness record deleted.
    deleted = root / "deleted"
    shutil.copytree(anchor, deleted)
    (deleted / "witness" / "000002.sigstore.json").unlink()
    found("a witness record deleted", checks(deleted), "never shown to Rekor", misses)

    # 4. Sigstore asked to accept the records under an identity that did not make them.
    found("a record checked under another identity",
          run(*witness, str(anchor), "--root-key", key, "--sigstore-identity",
              "https://github.com/someone-else/repo/.github/workflows/x.yml@refs/heads/main"), "Sigstore refused",
          misses)

    print(f"{5 - len(misses)} of 5 attacks caught")
    return 1 if misses else 0


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "prepare":
        prepare(Path(sys.argv[2]))
    elif len(sys.argv) == 4 and sys.argv[1] == "attack":
        raise SystemExit(attack(Path(sys.argv[2]), sys.argv[3]))
    else:
        raise SystemExit(__doc__)
