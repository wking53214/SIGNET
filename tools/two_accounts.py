"""The separation, proven with real accounts: signet under its own account, a caller and an intruder under others.

Every other test runs signet and its callers as one account, which proves the wiring and not the separation (README,
"On a one-user machine"). This runs on a CI machine where it can make accounts (it needs passwordless sudo, which
GitHub's Linux runners give), and exits 1 if any claim below fails:

  1. signet serves under its own account with no same-account warning;
  2. the allowed caller gets a signature that checks under the registry;
  3. the caller's account cannot read signet's key files;
  4. another account on the machine is refused (`not-allowed`), and the refusal is logged under its uid;
  5. a client that expects signet's account talks to it; one that expects another account sends nothing;
  6. `signet status`, run as signet's account, reports healthy.

    python tools/two_accounts.py        (run as the caller's account, after `pip install .` somewhere world-readable)
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path

PY = sys.executable
STATE, RUN, ETC = Path("/var/lib/signet"), Path("/run/signet"), Path("/etc/signet")
LABEL = "zeta-lock-result-signature/1\n"
failures = []


def sh(*args: str, check: bool = True, user: "str | None" = None) -> subprocess.CompletedProcess:
    cmd = (["sudo", "-n", "-u", user] if user else ["sudo", "-n"]) + list(args)
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if check and done.returncode != 0:
        raise SystemExit(f"FAILED: {' '.join(cmd)}\n{done.stdout}{done.stderr}")
    return done


def claim(text: str, held: bool) -> None:
    print(f"{'HELD  ' if held else 'FAILED'}  {text}")
    if not held:
        failures.append(text)


def main() -> int:
    me = os.getuid()
    for name in ("signet", "intruder"):
        sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name, check=False)
    signet_uid = pwd.getpwnam("signet").pw_uid
    sh("install", "-d", "-o", "signet", "-g", "signet", "-m", "0700", str(STATE), str(STATE / "keys"))
    sh("install", "-d", "-o", "signet", "-g", "signet", "-m", "0755", str(RUN))
    sh("install", "-d", "-m", "0755", str(ETC))
    for key_id in ("root-1", "log-1", "zeta-1"):
        sh(PY, "-m", "signet", "keygen", "--keys-dir", str(STATE / "keys"), key_id, user="signet")
    config = {"schema": "signet-config/1", "socket": str(RUN / "signet.sock"), "keys_dir": str(STATE / "keys"),
              "log": str(STATE / "signatures.log"), "registry_key_id": "root-1", "log_key_id": "log-1",
              "purposes": {"zeta-lock-result": {"key_id": "zeta-1", "label": LABEL, "allowed_uids": [me]}}}
    tmp = Path("/tmp/signet-config.json")
    tmp.write_text(json.dumps(config))
    sh("install", "-m", "0644", str(tmp), str(ETC / "config.json"))
    sh(PY, "-m", "signet", "registry", "--config", str(ETC / "config.json"), "--out", str(STATE / "registry.json"),
       user="signet")
    registry_text = sh("cat", str(STATE / "registry.json")).stdout
    root_key = json.loads(registry_text)["registry"]["keys"]
    root_key = next(k["public_key"] for k in root_key if k["key_id"] == "root-1")

    proc = subprocess.Popen(["sudo", "-n", "-u", "signet", PY, "-m", "signet", "serve", "--config",
                             str(ETC / "config.json")], stderr=subprocess.PIPE, text=True)
    first = proc.stderr.readline()
    try:
        time.sleep(0.5)
        os.set_blocking(proc.stderr.fileno(), False)
        rest = proc.stderr.read() or ""
        claim("1. signet serves under its own account with no same-account warning",
              "signet: serving" in first and "WARNING" not in rest)

        from signet.client import SignetRefused, SignetUnavailable, request
        from signet.registry import load_registry
        from signet.verify import verifier
        data = LABEL.encode() + b"signed across accounts"
        sig, _ = request(RUN / "signet.sock", "zeta-lock-result", data, expected_uid=signet_uid)
        reg = load_registry(registry_text, root_key)
        claim("2. the allowed caller gets a signature that checks under the registry",
              verifier(reg, "zeta-lock-result")(data, sig))

        try:
            (STATE / "keys" / "zeta-1.key").read_bytes()
            unreadable = False
        except PermissionError:
            unreadable = True
        claim("3. the caller's account cannot read signet's key files", unreadable)

        probe = ("import sys; from signet.client import request, SignetRefused\n"
                 "try:\n    request(sys.argv[1], 'zeta-lock-result', sys.argv[2].encode())\n"
                 "except SignetRefused as e:\n    print(e.code)\n")
        intruder = sh(PY, "-c", probe, str(RUN / "signet.sock"), LABEL + "intruder", user="intruder", check=False)
        log = [json.loads(line) for line in sh("cat", str(STATE / "signatures.log")).stdout.splitlines()]
        intruder_uid = pwd.getpwnam("intruder").pw_uid
        claim("4. another account is refused and the refusal is logged under its uid",
              intruder.stdout.strip() == "not-allowed"
              and any(e["uid"] == intruder_uid and e["code"] == "not-allowed" for e in log))

        try:
            request(RUN / "signet.sock", "zeta-lock-result", data, expected_uid=signet_uid + 1)
            wrong = False
        except SignetUnavailable as exc:
            wrong = "nothing was sent" in str(exc)
        except SignetRefused:
            wrong = False
        claim("5. a client expecting another account sends nothing", wrong)

        status = sh(PY, "-m", "signet", "status", "--config", str(ETC / "config.json"), user="signet", check=False)
        claim("6. signet status, as signet's account, reports healthy",
              status.returncode == 0 and json.loads(status.stdout)["healthy"])
    finally:
        sh("pkill", "-TERM", "-u", "signet", "-f", "signet serve", check=False)
        proc.wait(timeout=30)
    print(f"{6 - len(failures)} of 6 claims held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
