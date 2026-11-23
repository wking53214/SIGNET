"""registry: the one signed list of every key, what it is for, and whether it may still be trusted.

WHY IT EXISTS

Before signet, every signing slot in the library (zeta's lock results, delta's receipts and checkpoints, HERALD's
export, the HUMANITY issuer) said "keys, trust and revocation are the deployer's". Each checker was handed its own
trust list. Five lists drift, and revoking a key meant finding every one. The registry is one list, signed by one
root key, that every checker reads.

THE FILE

    {"registry": {"schema": "signet-registry/1", "version": 3,
                  "purposes": {"zeta-lock-result": {"label": "zeta-lock-result-signature/1\\n"}},
                  "keys": [{"key_id": "zeta-2026-11", "purpose": "zeta-lock-result",
                            "public_key": "<64 hex>", "status": "current"}]},
     "signature": "<root key id>:<128 hex>"}

The signature is Ed25519 by the ROOT key over `signet-registry/1\\n` followed by the canonical bytes of the
`registry` object. A checker pins the root public key out of band (it is never read from the file it checks).

STATUS of a key:
  - `current`: the key signet signs with now. At most one per purpose.
  - `verify-only`: retired from signing, still trusted, so what it signed keeps checking. This is how rotation works:
    the new key becomes `current` and the old one `verify-only` in the next version.
  - `revoked`: never trusted, whatever it signed. Revocation is final for that id.

VERSION only goes up. A checker that remembers the highest version it has accepted passes it as `min_version`, and an
older registry (one from before a revocation, replayed by whoever serves the file) is refused. Remembering it is the
checker's: the registry cannot tell a checker which version is newest.

REFUSED, naming why (`RegistryError`): a bad signature or a root other than the pinned one; anything not exactly the
shape above; a key id twice; one public key under two ids (revoking one would leave the other); two `current` keys for
one purpose; a key for a purpose the registry does not list; a reserved purpose (`signet-registry`, `signet-log` are
signet's own) given a label other than signet's.

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3): a checker needs only it,
`signet.verify` and the pinned root public key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE, check_label, check_name
from .strict import FormatError, canonical, loads

SCHEMA = "signet-registry/1"
STATUSES = ("current", "verify-only", "revoked")
_RESERVED_LABELS = {REGISTRY_PURPOSE: REGISTRY_LABEL.decode("ascii"), LOG_PURPOSE: CHECKPOINT_LABEL.decode("ascii")}


class RegistryError(ValueError):
    """A registry that will not be trusted, with the reason."""


@dataclass(frozen=True)
class KeyEntry:
    key_id: str
    purpose: str
    public_key: str  # 64 lowercase hex
    status: str


@dataclass(frozen=True)
class Registry:
    version: int
    purposes: Mapping[str, bytes]  # purpose -> label
    keys: Mapping[str, KeyEntry]  # key_id -> entry

    def entry(self, key_id: str) -> Optional[KeyEntry]:
        return self.keys.get(key_id)

    def current(self, purpose: str) -> Optional[KeyEntry]:
        for entry in self.keys.values():
            if entry.purpose == purpose and entry.status == "current":
                return entry
        return None

    def body(self) -> Dict[str, Any]:
        """The `registry` object as written, for carrying entries into the next version."""
        return {
            "schema": SCHEMA, "version": self.version,
            "purposes": {p: {"label": label.decode("ascii")} for p, label in sorted(self.purposes.items())},
            "keys": [{"key_id": e.key_id, "purpose": e.purpose, "public_key": e.public_key, "status": e.status}
                     for e in sorted(self.keys.values(), key=lambda e: e.key_id)],
        }


def public_key_hex(key: "Ed25519PublicKey | Ed25519PrivateKey") -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _public_key(hex_text: Any, where: str) -> Ed25519PublicKey:
    if type(hex_text) is not str or len(hex_text) != 64 or hex_text != hex_text.lower():
        raise RegistryError(f"{where} is not 64 lowercase hex characters")
    try:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_text))
    except ValueError:
        raise RegistryError(f"{where} is not an Ed25519 public key") from None


def split_signature(signature: Any) -> Tuple[str, bytes]:
    """`(key_id, 64 raw signature bytes)` from the envelope `key_id:signature`, or ValueError."""
    if type(signature) is not bytes:
        raise ValueError("a signature is exact bytes")
    raw_id, sep, body = signature.partition(b":")
    if not sep or len(body) != 64:
        raise ValueError("a signature is key_id, ':', then 64 bytes of Ed25519 signature")
    try:
        key_id = raw_id.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("a signature's key id is not ASCII") from None
    return check_name("key id", key_id), body


def check_body(body: Any) -> Registry:
    """The `registry` object read into a `Registry`, or `RegistryError`. Does not check any signature."""
    if type(body) is not dict or set(body) != {"schema", "version", "purposes", "keys"}:
        raise RegistryError("a registry has exactly schema, version, purposes and keys")
    if body["schema"] != SCHEMA:
        raise RegistryError(f"the schema is {body['schema']!r}, not {SCHEMA!r}")
    version = body["version"]
    if type(version) is not int or version < 1:
        raise RegistryError("the version is a whole number of at least 1")
    if type(body["purposes"]) is not dict or type(body["keys"]) is not list:
        raise RegistryError("purposes is an object and keys a list")
    purposes: Dict[str, bytes] = {}
    for name, spec in body["purposes"].items():
        try:
            check_name("purpose", name)
            if type(spec) is not dict or set(spec) != {"label"}:
                raise ValueError(f"purpose {name!r} has exactly a label")
            label = check_label(spec["label"])
        except ValueError as exc:
            raise RegistryError(str(exc)) from None
        if name in _RESERVED_LABELS and spec["label"] != _RESERVED_LABELS[name]:
            raise RegistryError(f"{name!r} is signet's own purpose and its label is fixed")
        purposes[name] = label
    keys: Dict[str, KeyEntry] = {}
    owners: Dict[str, str] = {}
    current: Dict[str, str] = {}
    for i, item in enumerate(body["keys"]):
        if type(item) is not dict or set(item) != {"key_id", "purpose", "public_key", "status"}:
            raise RegistryError(f"keys[{i}] has exactly key_id, purpose, public_key and status")
        try:
            key_id = check_name("key id", item["key_id"])
        except ValueError as exc:
            raise RegistryError(str(exc)) from None
        if key_id in keys:
            raise RegistryError(f"the key id {key_id!r} appears twice")
        if item["purpose"] not in purposes:
            raise RegistryError(f"key {key_id!r} is for {item['purpose']!r}, which the registry does not list")
        _public_key(item["public_key"], f"the public key of {key_id!r}")
        if item["public_key"] in owners:
            raise RegistryError(f"one public key is listed as {owners[item['public_key']]!r} and {key_id!r}: revoking "
                                "one id would leave the other")
        if item["status"] not in STATUSES:
            raise RegistryError(f"key {key_id!r} has status {item['status']!r}; it is one of {', '.join(STATUSES)}")
        if item["status"] == "current":
            if item["purpose"] in current:
                raise RegistryError(f"purpose {item['purpose']!r} has two current keys, {current[item['purpose']]!r} "
                                    f"and {key_id!r}")
            current[item["purpose"]] = key_id
        owners[item["public_key"]] = key_id
        keys[key_id] = KeyEntry(key_id, item["purpose"], item["public_key"], item["status"])
    return Registry(version, purposes, keys)


def signing_input(body: Mapping[str, Any]) -> bytes:
    return REGISTRY_LABEL + canonical(body)


def sign_registry(body: Mapping[str, Any], root_key: Ed25519PrivateKey, root_key_id: str) -> str:
    """The registry file text: `body` checked, then signed by the root key. The root key must be listed in `body` as
    the current `signet-registry` key, so the file says which key it expects to be checked with."""
    registry = check_body(dict(body))
    entry = registry.entry(root_key_id)
    if entry is None or entry.purpose != REGISTRY_PURPOSE or entry.status != "current" \
            or entry.public_key != public_key_hex(root_key):
        raise RegistryError(f"the root key {root_key_id!r} is not this registry's current {REGISTRY_PURPOSE!r} key")
    signature = root_key_id.encode("ascii") + b":" + root_key.sign(signing_input(body))
    return canonical({"registry": dict(body), "signature": signature.hex()}).decode("ascii") + "\n"


def load_registry(text: "bytes | str", root_public_key: str, *, min_version: int = 1) -> Registry:
    """Read and check a registry file against the pinned root public key (64 hex), or raise `RegistryError`.

    `min_version` is the highest version this checker has accepted before; an older file is refused."""
    root = _public_key(root_public_key, "the pinned root public key")
    try:
        outer = loads(text)
    except FormatError as exc:
        raise RegistryError(f"the registry file is not strict JSON: {exc}") from None
    if set(outer) != {"registry", "signature"} or type(outer["signature"]) is not str:
        raise RegistryError("a registry file has exactly registry and signature")
    try:
        key_id, raw = split_signature(bytes.fromhex(outer["signature"]))
    except ValueError as exc:
        raise RegistryError(f"the registry signature is malformed: {exc}") from None
    try:
        root.verify(raw, signing_input(outer["registry"]))
    except (InvalidSignature, FormatError):
        raise RegistryError("the registry signature does not check out under the pinned root key") from None
    registry = check_body(outer["registry"])
    entry = registry.entry(key_id)
    if entry is None or entry.purpose != REGISTRY_PURPOSE or entry.status != "current" \
            or entry.public_key != root_public_key:
        raise RegistryError(f"the registry is signed by {key_id!r}, which it does not list as its current "
                            f"{REGISTRY_PURPOSE!r} key with the pinned public key")
    if type(min_version) is not int or registry.version < min_version:
        raise RegistryError(f"the registry is version {registry.version}, older than version {min_version} which this "
                            "checker has already accepted")
    return registry


def next_body(previous: Optional[Registry], purposes: Mapping[str, bytes], current: Mapping[str, Tuple[str, str]],
              *, revoke: Sequence[str] = ()) -> Dict[str, Any]:
    """The body of the next version. `current` is {purpose: (key_id, public_key_hex)} for the keys signet signs with
    now. A key the previous version had as current for a purpose that now has another key becomes `verify-only`;
    a key in `revoke` becomes `revoked` (it must be listed, and a revoked key never comes back)."""
    keys: Dict[str, Dict[str, str]] = {}
    if previous is not None:
        for e in previous.keys.values():
            status = e.status
            if status == "current" and current.get(e.purpose, (e.key_id,))[0] != e.key_id:
                status = "verify-only"
            keys[e.key_id] = {"key_id": e.key_id, "purpose": e.purpose, "public_key": e.public_key, "status": status}
    for purpose, (key_id, public) in current.items():
        old = keys.get(key_id)
        if old is not None and (old["purpose"] != purpose or old["public_key"] != public or old["status"] == "revoked"):
            raise RegistryError(f"key {key_id!r} was listed before as {old['purpose']!r} {old['status']}; a key id names "
                                "one key for one purpose forever")
        keys[key_id] = {"key_id": key_id, "purpose": purpose, "public_key": public, "status": "current"}
    for key_id in revoke:
        if key_id not in keys:
            raise RegistryError(f"the revoked id {key_id!r} matches no listed key; it would revoke nothing")
        keys[key_id]["status"] = "revoked"
    labels = dict(previous.purposes) if previous is not None else {}
    labels.update(purposes)
    body = {"schema": SCHEMA, "version": (previous.version + 1) if previous is not None else 1,
            "purposes": {p: {"label": label.decode("ascii")} for p, label in sorted(labels.items())},
            "keys": [keys[k] for k in sorted(keys)]}
    check_body(body)
    return body
