"""config: what one signet instance signs, with which key, for whom.

    {"schema": "signet-config/1",
     "socket": "/run/signet/signet.sock",
     "keys_dir": "/var/lib/signet/keys",
     "log": "/var/lib/signet/signatures.log",
     "registry_key_id": "root-2026-11",
     "log_key_id": "log-2026-11",
     "request_timeout_ms": 5000,
     "purposes": {
       "zeta-lock-result": {"key_id": "zeta-2026-11", "label": "zeta-lock-result-signature/1\\n",
                            "allowed_uids": [1001]}}}

`request_timeout_ms` is optional (default 5000): how long one connection may take to send its request before signet
closes it. Everything else is required. REFUSED at start, naming why (`ConfigError`):

  - a path that is not absolute;
  - a purpose or key id that breaks the naming rules (`signet.names`), or a purpose named `signet-registry` or
    `signet-log` (those are signet's own and are never signed for a caller);
  - one key id used for two purposes, or for a purpose and for the registry or log (one key, one job);
  - two purposes with one label (a key for one could then sign bytes meant for the other);
  - a purpose with no allowed account, or an account listed twice;
  - an `approval` rule that `signet.approval.check_rule` refuses (a quorum under 2, more than the approvers listed, an
    approver twice or out of order, a domain equal to the purpose's label).

A purpose may carry an optional `approval` rule (`signet.approval`): signet then signs for it only when enough listed
approvers signed the exact bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional, Tuple

from .approval import Approval, check_rule
from .names import CHECKPOINT_LABEL, REGISTRY_LABEL, RESERVED_PURPOSES, check_label, check_name
from .strict import FormatError, loads

SCHEMA = "signet-config/1"
_REQUIRED = {"schema", "socket", "keys_dir", "log", "registry_key_id", "log_key_id", "purposes"}


class ConfigError(ValueError):
    """A config signet will not start with, and why."""


@dataclass(frozen=True)
class Purpose:
    name: str
    key_id: str
    label: bytes
    allowed_uids: Tuple[int, ...]
    approval: Optional[Approval] = None


@dataclass(frozen=True)
class Config:
    socket: Path
    keys_dir: Path
    log: Path
    registry_key_id: str
    log_key_id: str
    request_timeout_ms: int
    purposes: Mapping[str, Purpose]


def _path(doc: Mapping[str, Any], name: str) -> Path:
    value = doc[name]
    if type(value) is not str or not value.startswith("/"):
        raise ConfigError(f"{name} must be an absolute path; got {value!r}")
    return Path(value)


def parse(text: "bytes | str") -> Config:
    try:
        doc = loads(text, max_bytes=256 * 1024)
    except FormatError as exc:
        raise ConfigError(f"the config is not strict JSON: {exc}") from None
    if not _REQUIRED <= set(doc) <= _REQUIRED | {"request_timeout_ms"}:
        raise ConfigError(f"a config has exactly {', '.join(sorted(_REQUIRED))} and optionally request_timeout_ms")
    if doc["schema"] != SCHEMA:
        raise ConfigError(f"the schema is {doc['schema']!r}, not {SCHEMA!r}")
    timeout = doc.get("request_timeout_ms", 5000)
    if type(timeout) is not int or not 50 <= timeout <= 600_000:
        raise ConfigError("request_timeout_ms is a whole number from 50 to 600000")
    try:
        registry_key = check_name("key id", doc["registry_key_id"])
        log_key = check_name("key id", doc["log_key_id"])
    except ValueError as exc:
        raise ConfigError(str(exc)) from None
    if registry_key == log_key:
        raise ConfigError("the registry key and the log key must be two different keys")
    if type(doc["purposes"]) is not dict or not doc["purposes"]:
        raise ConfigError("purposes is an object with at least one purpose")
    used = {registry_key: "the registry", log_key: "the log"}
    labels = {REGISTRY_LABEL: "the registry", CHECKPOINT_LABEL: "the log"}
    purposes = {}
    for name, spec in doc["purposes"].items():
        try:
            check_name("purpose", name)
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
        if name in RESERVED_PURPOSES:
            raise ConfigError(f"{name!r} is signet's own purpose and is never signed for a caller")
        base = {"key_id", "label", "allowed_uids"}
        if type(spec) is not dict or not base <= set(spec) <= base | {"approval"}:
            raise ConfigError(f"purpose {name!r} has exactly key_id, label and allowed_uids, and optionally approval")
        try:
            key_id = check_name("key id", spec["key_id"])
            label = check_label(spec["label"])
        except ValueError as exc:
            raise ConfigError(f"purpose {name!r}: {exc}") from None
        if key_id in used:
            raise ConfigError(f"key {key_id!r} is used by {used[key_id]} and by {name!r}; one key does one job")
        if label in labels:
            raise ConfigError(f"purpose {name!r} has the same label as {labels[label]}")
        uids = spec["allowed_uids"]
        if type(uids) is not list or not uids or any(type(u) is not int or not 0 <= u < 2**32 for u in uids) \
                or len(set(uids)) != len(uids):
            raise ConfigError(f"purpose {name!r}: allowed_uids is a list of distinct account numbers, at least one")
        rule = None
        if "approval" in spec:
            try:
                rule = check_rule(spec["approval"], label)
            except ValueError as exc:
                raise ConfigError(f"purpose {name!r}: {exc}") from None
        used[key_id] = repr(name)
        labels[label] = repr(name)
        purposes[name] = Purpose(name, key_id, label, tuple(uids), rule)
    return Config(_path(doc, "socket"), _path(doc, "keys_dir"), _path(doc, "log"), registry_key, log_key, timeout,
                  purposes)


def load(path: Path) -> Config:
    try:
        return parse(Path(path).read_bytes())
    except OSError as exc:
        raise ConfigError(f"cannot read the config {path}: {exc}") from None
