"""trust: a checker's memory of the registries it has accepted, so an old, forked or resurrecting one is refused.

WHY IT EXISTS

`load_registry(..., min_version=N)` refuses a registry older than N, but only if the checker remembers N, and a
version number alone cannot tell two different files of the same version apart. The baseline probes showed three
things a validly root-signed registry could do to a checker that remembers only a number (docs/SIGNET_BASELINE_v1.md,
P1 to P3): fork (two version-2 files), resurrect a revoked key, and jump the version so far that honest versions are
refused afterwards. This module is the memory that closes the first two and bounds the third.

THE STATE

    {"schema": "signet-trust-state/1", "root": "<pinned root, 64 hex>", "version": 3,
     "digest": "<SHA-256 of the accepted registry's signing input, 64 hex>",
     "revoked_ids": ["zeta-1"], "revoked_keys": ["<64 hex>"]}

`digest` is over exactly the bytes the root signed (`signet.registry.signing_input`), so it names one registry body.
`revoked_ids` and `revoked_keys` are every key id and public key ever seen as `revoked`; they only grow.

`TrustState.accept(registry)` returns the next state, or raises `TrustError`, when the registry:

  - is older than the remembered version (rollback);
  - has the remembered version but another body (fork);
  - lists a remembered revoked id or public key as anything but `revoked` (resurrection; dropping it is allowed,
    because a key that is not listed is not trusted either);
  - is more than `max_step` versions ahead, when the checker sets a `max_step` (a jump).

`TrustStore(path)` keeps the state in a file. It is written whole (temporary file, fsync, rename, directory fsync) and
only ever moves forward, under a lock so checkers sharing one file take turns. A missing file is an error unless the store was made with `TrustStore.create`: a checker
whose memory silently vanished would otherwise accept a rollback, so losing the file must stop it. A pin that differs
from the remembered root is refused too: a re-pin (docs/KEY_RECOVERY_v1.md) resets the store on purpose, by hand.

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3).
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, FrozenSet, Optional

from .registry import Registry, RegistryError, load_registry, signing_input
from .strict import FormatError, canonical, loads

SCHEMA = "signet-trust-state/1"
_HEX = frozenset("0123456789abcdef")


class TrustError(RegistryError):
    """A registry this checker's memory refuses, or a memory that cannot be read."""


def registry_digest(registry: Registry) -> str:
    """SHA-256 (hex) of the exact bytes the root signed for this registry."""
    return hashlib.sha256(signing_input(registry.body())).hexdigest()


def _hex64(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and set(value) <= _HEX


@dataclass(frozen=True)
class TrustState:
    root: str
    version: int = 0
    digest: str = ""
    revoked_ids: FrozenSet[str] = frozenset()
    revoked_keys: FrozenSet[str] = frozenset()

    def accept(self, registry: Registry, *, max_step: Optional[int] = None) -> "TrustState":
        digest = registry_digest(registry)
        if registry.version < self.version:
            raise TrustError(f"rollback: registry version {registry.version} is older than version {self.version}, "
                             "which this checker has accepted")
        if registry.version == self.version and digest != self.digest:
            raise TrustError(f"fork: a second, different registry claims version {registry.version}")
        if max_step is not None and self.version and registry.version - self.version > max_step:
            raise TrustError(f"jump: registry version {registry.version} is more than {max_step} ahead of "
                             f"{self.version}")
        for entry in registry.keys.values():
            if entry.status == "revoked":
                continue
            if entry.key_id in self.revoked_ids:
                raise TrustError(f"resurrection: key {entry.key_id!r} was revoked and is now {entry.status!r}")
            if entry.public_key in self.revoked_keys:
                raise TrustError(f"resurrection: the public key of {entry.key_id!r} was revoked under another id")
        revoked = [e for e in registry.keys.values() if e.status == "revoked"]
        return TrustState(self.root, registry.version, digest,
                          self.revoked_ids | {e.key_id for e in revoked},
                          self.revoked_keys | {e.public_key for e in revoked})

    def as_json(self) -> dict:
        return {"schema": SCHEMA, "root": self.root, "version": self.version, "digest": self.digest,
                "revoked_ids": sorted(self.revoked_ids), "revoked_keys": sorted(self.revoked_keys)}

    @classmethod
    def from_json(cls, text: "bytes | str") -> "TrustState":
        try:
            doc = loads(text, max_bytes=1 << 20, max_depth=2)
        except FormatError as exc:
            raise TrustError(f"the trust state is not strict JSON: {exc}") from None
        if set(doc) != {"schema", "root", "version", "digest", "revoked_ids", "revoked_keys"} \
                or doc["schema"] != SCHEMA:
            raise TrustError(f"a trust state has exactly the {SCHEMA} fields")
        version, digest = doc["version"], doc["digest"]
        if not _hex64(doc["root"]) or type(version) is not int or version < 0 \
                or not ((version == 0 and digest == "") or (version > 0 and _hex64(digest))):
            raise TrustError("the trust state's root, version or digest is malformed")
        ids, keys = doc["revoked_ids"], doc["revoked_keys"]
        if type(ids) is not list or type(keys) is not list or any(type(i) is not str for i in ids) \
                or not all(_hex64(k) for k in keys):
            raise TrustError("the trust state's revoked lists are malformed")
        return cls(doc["root"], version, digest, frozenset(ids), frozenset(keys))


class TrustStore:
    """A `TrustState` kept in one file. `load(text)` checks a registry against it and moves it forward."""

    def __init__(self, path: "str | Path", root_public_key: str, *, max_step: Optional[int] = None) -> None:
        self.path = Path(path)
        self.root = root_public_key
        self.max_step = max_step
        if not _hex64(root_public_key):
            raise TrustError("the pinned root public key is 64 lowercase hex characters")

    @classmethod
    def create(cls, path: "str | Path", root_public_key: str, **kw: Any) -> "TrustStore":
        """Start an empty memory for a checker that has never accepted a registry. Refuses an existing file."""
        store = cls(path, root_public_key, **kw)
        store._write(TrustState(root_public_key), new=True)
        return store

    def state(self) -> TrustState:
        try:
            raw = self.path.read_bytes()
        except FileNotFoundError:
            raise TrustError(f"{self.path} is missing: this checker's memory of accepted registries is gone, so a "
                             "rollback could not be seen. Restore it, or start again on purpose with "
                             "TrustStore.create") from None
        state = TrustState.from_json(raw)
        if state.root != self.root:
            raise TrustError("the trust state was kept under another root key; a re-pin resets it on purpose")
        return state

    def load(self, text: "bytes | str") -> Registry:
        """The registry, if it verifies under the pinned root AND this checker's memory accepts it; the memory then
        moves forward. Otherwise `RegistryError` (a `TrustError` for what the memory refuses) and nothing changes."""
        lock = os.open(self.path.with_name(f".{self.path.name}.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)  # two checkers sharing one memory see each other's step, in order
            state = self.state()
            registry = load_registry(text, self.root, min_version=max(state.version, 1))
            self._write(state.accept(registry, max_step=self.max_step), new=False)
        finally:
            os.close(lock)
        return registry

    def _write(self, state: TrustState, *, new: bool) -> None:
        body = canonical(state.as_json()) + b"\n"
        if new and (self.path.exists() or self.path.is_symlink()):
            raise TrustError(f"{self.path} already exists; a checker's memory is never started over silently")
        tmp = self.path.with_name(f".{self.path.name}.tmp-{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
            raise
        dfd = os.open(self.path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
