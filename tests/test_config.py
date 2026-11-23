"""A config signet would sign wrongly with is refused at start."""

import json

import pytest

from signet.config import ConfigError, parse


def base(**purposes):
    return {"schema": "signet-config/1", "socket": "/run/s.sock", "keys_dir": "/k", "log": "/l",
            "registry_key_id": "root", "log_key_id": "log",
            "purposes": purposes or {"zeta-lock-result": {"key_id": "z", "label": "zeta/1\n", "allowed_uids": [1]}}}


def test_a_good_config_reads():
    cfg = parse(json.dumps(base()))
    assert cfg.purposes["zeta-lock-result"].label == b"zeta/1\n" and cfg.request_timeout_ms == 5000


@pytest.mark.parametrize("change, why", [
    (lambda d: d.update(socket="relative.sock"), "absolute"),
    (lambda d: d.update(log_key_id="root"), "two different keys"),
    (lambda d: d["purposes"].update({"signet-log": {"key_id": "x", "label": "x/1\n", "allowed_uids": [1]}}),
     "signet's own"),
    (lambda d: d["purposes"].update({"other": {"key_id": "z", "label": "o/1\n", "allowed_uids": [1]}}), "one job"),
    (lambda d: d["purposes"].update({"other": {"key_id": "root", "label": "o/1\n", "allowed_uids": [1]}}), "one job"),
    (lambda d: d["purposes"].update({"other": {"key_id": "o", "label": "zeta/1\n", "allowed_uids": [1]}}),
     "same label"),
    (lambda d: d["purposes"].update({"other": {"key_id": "o", "label": "signet-log-checkpoint/1\n",
                                               "allowed_uids": [1]}}), "same label"),
    (lambda d: d["purposes"]["zeta-lock-result"].update(allowed_uids=[]), "at least one"),
    (lambda d: d["purposes"]["zeta-lock-result"].update(allowed_uids=[1, 1]), "distinct"),
    (lambda d: d["purposes"]["zeta-lock-result"].update(label="no newline"), "label"),
    (lambda d: d.update(request_timeout_ms=1), "request_timeout_ms"),
    (lambda d: d.update(extra=1), "exactly"),
])
def test_refusals(change, why):
    doc = base()
    change(doc)
    with pytest.raises(ConfigError, match=why):
        parse(json.dumps(doc))


def test_a_duplicate_key_in_the_config_is_refused():
    text = json.dumps(base()).replace('"log": "/l"', '"log": "/l", "log": "/other"')
    with pytest.raises(ConfigError, match="twice"):
        parse(text)
