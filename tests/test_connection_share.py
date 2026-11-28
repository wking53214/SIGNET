"""Each account's share of connection slots (T21): one account cannot hold every slot, so the others are not all
answered `busy`."""

import json
import socket
import time

import pytest

from instance import ZETA_LABEL, Instance
from signet.client import SignetRefused, request
from signet.config import ConfigError, parse
from signet.server import ConnectionSlots

ZETA = ZETA_LABEL.encode("ascii")
BASE = {"schema": "signet-config/1", "socket": "/s", "keys_dir": "/k", "log": "/l", "registry_key_id": "root-1",
        "log_key_id": "log-1", "purposes": {"p": {"key_id": "p-1", "label": "p/1\n", "allowed_uids": [1]}}}


def test_the_share_is_checked_and_defaults_to_no_share():
    assert parse(json.dumps(BASE)).max_connections_per_account == 64
    assert parse(json.dumps({**BASE, "max_connections": 10})).max_connections_per_account == 10
    assert parse(json.dumps({**BASE, "max_connections_per_account": 8})).max_connections_per_account == 8
    for bad in (0, 65, -1, "8", True):
        with pytest.raises(ConfigError, match="max_connections_per_account"):
            parse(json.dumps({**BASE, "max_connections_per_account": bad}))


def test_one_account_is_held_to_its_share_and_others_still_get_slots():
    slots = ConnectionSlots(total=6, per_account=2)
    assert slots.take(1000) == "" and slots.take(1000) == ""
    assert "share" in slots.take(1000)
    assert slots.take(1001) == "" and slots.take(1002) == ""
    slots.give_back(1000)
    assert slots.take(1000) == ""
    for uid in (1000, 1000, 1001, 1002):
        slots.give_back(uid)
    assert slots.take(1000) == "" and slots.take(1000) == ""
    assert slots._used == 2 and slots._by_uid == {1000: 2}


def test_gap_a_share_reserves_nothing_so_enough_accounts_still_fill_the_cap():
    """Recorded gap: the share caps each account; it does not keep slots free. Three accounts each at their share fill
    a cap of 6, and a fourth is answered busy."""
    slots = ConnectionSlots(total=6, per_account=2)
    for uid in (1000, 1001, 1002):
        assert slots.take(uid) == "" and slots.take(uid) == ""
    assert "most connections" in slots.take(1003)


def test_a_running_signet_holds_one_account_to_its_share(tmp_path):
    inst = Instance(tmp_path, timeout_ms=600000)
    doc = json.loads(inst.config.read_text())
    doc.update(max_connections=4, max_connections_per_account=2)
    inst.config.write_text(json.dumps(doc))
    inst.start()
    held = []
    try:
        for _ in range(2):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(str(inst.socket))
            held.append(s)
        time.sleep(0.3)
        with pytest.raises(SignetRefused) as caught:
            request(inst.socket, "zeta-lock-result", ZETA + b"x", timeout=5)
        assert caught.value.code == "busy" and "share" in caught.value.reason
        held.pop().close()
        time.sleep(0.3)
        request(inst.socket, "zeta-lock-result", ZETA + b"served again", timeout=5)  # the slot came back
        for _ in range(50):  # every slot given back after many turned away
            request(inst.socket, "zeta-lock-result", ZETA + b"y", timeout=5)
    finally:
        for s in held:
            s.close()
        inst.kill()
