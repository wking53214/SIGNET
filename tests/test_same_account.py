"""signet warns when a caller shares its account, because that caller can read the keys without asking signet."""

from __future__ import annotations

import os

import pytest

from signet.client import SignetRefused, request
from instance import DELTA_LABEL, ZETA_LABEL, Instance


def _purposes(zeta_uids, delta_uids):
    return {
        "zeta-lock-result": {"key_id": "zeta-1", "label": ZETA_LABEL, "allowed_uids": zeta_uids},
        "delta-receipt": {"key_id": "delta-1", "label": DELTA_LABEL, "allowed_uids": delta_uids},
    }


def _lines_until_the_first_refusal(inst: Instance) -> list:
    """Everything signet printed after "serving", up to a refusal. The warnings come before the first request."""
    with pytest.raises(SignetRefused):
        request(inst.socket, "zeta-lock-result", b"not labelled")
    lines = []
    while True:
        line = inst.proc.stderr.readline()
        lines.append(line)
        if "refused" in line:
            return lines


def test_a_purpose_open_to_signets_own_account_is_warned_about(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        lines = _lines_until_the_first_refusal(inst)
    finally:
        inst.kill()
    warned = [line for line in lines if "WARNING" in line]
    assert len(warned) == 2
    assert any("'zeta-lock-result'" in line for line in warned) and any("'delta-receipt'" in line for line in warned)
    assert all(f"uid {os.geteuid()}" in line for line in warned)


def test_only_the_purpose_that_shares_the_account_is_named(tmp_path):
    other = os.geteuid() + 1
    inst = Instance(tmp_path, purposes=_purposes([other], [os.geteuid(), other])).start()
    try:
        # zeta's label is wrong for this request on purpose; the account check refuses it first, which is all we need
        lines = _lines_until_the_first_refusal(inst)
    finally:
        inst.kill()
    warned = [line for line in lines if "WARNING" in line]
    assert len(warned) == 1 and "'delta-receipt'" in warned[0]


def test_a_separate_account_gets_no_warning(tmp_path):
    other = os.geteuid() + 1
    inst = Instance(tmp_path, purposes=_purposes([other], [other])).start()
    try:
        lines = _lines_until_the_first_refusal(inst)
    finally:
        inst.kill()
    assert not [line for line in lines if "WARNING" in line]
