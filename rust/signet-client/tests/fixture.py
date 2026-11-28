"""Set up a real signet for the Rust client's tests: keys, a config with a `humanity-slip` purpose, nothing started.

Usage: python fixture.py ROOT_DIR [APPROVER_HEX,APPROVER_HEX,... [MAX_AGE_MS]]. With approvers, `humanity-slip` gets an approval
rule (domain `humanity-issuer/approval/1\n`, quorum 2, those public keys) and signet signs a slip only with two of
their approvals. Prints one JSON line: the config path, the socket path, the slip key id and its
public key. The Rust test then starts `python -m signet serve --config ...` itself, as its own process.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tests"))

from instance import Instance  # noqa: E402

root = Path(sys.argv[1])
root.mkdir(mode=0o700, parents=True, exist_ok=True)
uid = os.getuid()
slip = {"key_id": "slip-1", "label": "stack-capability/2\n", "allowed_uids": [uid]}
if len(sys.argv) > 2:
    slip["approval"] = {"domain": "humanity-issuer/approval/1\n", "approvers": sorted(sys.argv[2].split(",")),
                        "quorum": 2}
    if len(sys.argv) > 3:
        slip["approval"]["max_age_ms"] = int(sys.argv[3])
inst = Instance(root, key_ids={"slip": "slip-1"}, purposes={
    "humanity-slip": slip,
    "zeta-lock-result": {"key_id": "zeta-1", "label": "zeta-lock-result-signature/1\n", "allowed_uids": [uid]},
})
print(json.dumps({"config": str(inst.config), "socket": str(inst.socket), "slip_key_id": "slip-1",
                  "slip_public_key": inst.public["slip"], "log": str(inst.log)}))
