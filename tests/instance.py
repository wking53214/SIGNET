"""A real signet for the tests: private keys on disk, a config, and `python -m signet serve` as its own process."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

from signet.keys import generate

ZETA_LABEL = "zeta-lock-result-signature/1\n"
DELTA_LABEL = "delta-ledger-receipt-signature/1\n"


def cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "signet", *args], capture_output=True, text=True, timeout=60)


class Instance:
    def __init__(self, root: Path, *, purposes: Optional[Dict[str, dict]] = None, timeout_ms: int = 5000,
                 key_ids: Optional[Dict[str, str]] = None) -> None:
        self.root = root
        self.keys_dir = root / "keys"
        self.keys_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.keys_dir, 0o700)
        self.socket = root / "signet.sock"
        self.log = root / "signatures.log"
        ids = {"root": "root-1", "log": "log-1", "zeta": "zeta-1", "delta": "delta-1", **(key_ids or {})}
        self.ids = ids
        self.public = {}
        for name, key_id in ids.items():
            if not (self.keys_dir / f"{key_id}.key").exists():
                self.public[name] = generate(self.keys_dir, key_id)
        uid = os.getuid()
        self.purposes = purposes or {
            "zeta-lock-result": {"key_id": ids["zeta"], "label": ZETA_LABEL, "allowed_uids": [uid]},
            "delta-receipt": {"key_id": ids["delta"], "label": DELTA_LABEL, "allowed_uids": [uid]},
        }
        self.config = root / "config.json"
        self.config.write_text(json.dumps({
            "schema": "signet-config/1", "socket": str(self.socket), "keys_dir": str(self.keys_dir),
            "log": str(self.log), "registry_key_id": ids["root"], "log_key_id": ids["log"],
            "request_timeout_ms": timeout_ms, "purposes": self.purposes}))
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> "Instance":
        """Start signet and wait for its "serving" line. Connecting to check would itself be a logged request."""
        self.proc = subprocess.Popen([sys.executable, "-m", "signet", "serve", "--config", str(self.config)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        line = self.proc.stderr.readline()
        if "signet: serving" not in line:
            self.proc.wait(timeout=10)
            raise RuntimeError(f"signet did not start: {line}{self.proc.stderr.read()}")
        return self

    def kill(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
            self.proc.wait(timeout=10)

    def stop(self) -> str:
        if self.proc is None:
            return ""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            _, err = self.proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            _, err = self.proc.communicate()
        return err

    def registry(self, name: str = "registry.json", *extra: str) -> Path:
        out = self.root / name
        done = cli("registry", "--config", str(self.config), "--out", str(out), *extra)
        assert done.returncode == 0, done.stderr
        return out

    def root_key(self) -> str:
        return self.public["root"]

    def log_lines(self) -> List[dict]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]
