"""log: signet's own record of every signature it made and every request it refused.

WHY IT EXISTS

Separating the key from the program that uses it stops that program stealing the key. It does not stop a hijacked,
allowed caller from asking for a signature on bytes that look right. What changes is that every such signature is
now written down by a program the caller does not control: an auditor can count them, compare them with the ledger
they should match (delta's entries, zeta's evaluations), and see a signature that matches nothing.

THE FILE

One JSON line per entry, appended and forced to disk (fsync) BEFORE the signature is handed back. A signature that was
not logged is never released. Each line holds:

    seq, prev, at_ms, outcome ("signed" or "refused"), code (empty when signed), purpose, key_id, uid, pid,
    data_sha256, signature_sha256, hash

A signature made for a purpose with an approval rule (`signet.approval`) also holds `approvers`: the public keys (hex,
sorted, comma-separated) of the approvers who counted toward it. Other lines do not have the field, so a log written
before approval rules existed verifies unchanged.

`hash` is SHA-256 of `signet-log-entry/1\\n` and the canonical bytes of every other field. `prev` is the previous
line's hash (64 zeros for the first). So an edited, deleted, inserted or reordered line breaks the chain from that
point on, and `verify_file` names where.

The log holds digests, never the bytes signed: a log of what was signed must not become a copy of everything signed.

A CHECKPOINT is the log's length and head, signed with the `signet-log` key (see `signet.verify.check_checkpoint`).
Published somewhere signet's operator cannot rewrite (delta's outside anchor repository), it fixes the history up to
that point: a later log that does not extend it was rewritten.

ON START, the whole log is read and checked. A broken chain or a torn last line (a crash in the middle of a write) is
refused, and signet does not start. A torn line's signature was never released (the line is synced first), so
removing it is safe, but signet will not decide that for the operator: README, "Running it", says how.

WHAT THIS DOES NOT DO. Whoever controls signet's account can rewrite the whole file and its chain. A published
checkpoint is what makes that visible; the log alone cannot. `at_ms` is signet's own clock.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Sequence, Tuple

from .strict import FormatError, canonical, loads

ENTRY_LABEL = b"signet-log-entry/1\n"
GENESIS = "0" * 64
FIELDS = frozenset({"seq", "prev", "at_ms", "outcome", "code", "purpose", "key_id", "uid", "pid", "data_sha256",
                    "signature_sha256", "hash"})


class LogError(Exception):
    """A log that does not verify, or a write that did not reach the disk."""


def entry_hash(fields: Dict[str, Any]) -> str:
    return hashlib.sha256(ENTRY_LABEL + canonical(fields)).hexdigest()


def verify_file(path: Path) -> Tuple[int, str]:
    """`(length, head)` of a log that verifies from its first line to its last, or `LogError` naming the line."""
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return 0, GENESIS
    if raw and not raw.endswith(b"\n"):
        raise LogError(f"{path}: the last line is torn (no newline): a write was interrupted. Its signature was never "
                       "released; remove the partial line after checking it, then start signet again")
    head, length = GENESIS, 0
    for number, line in enumerate(raw.split(b"\n")[:-1] if raw else []):
        try:
            entry = loads(line, max_bytes=4096, max_depth=1)
        except FormatError as exc:
            raise LogError(f"{path}: line {number + 1} is not a log entry: {exc}") from None
        if set(entry) != FIELDS and set(entry) != FIELDS | {"approvers"}:
            raise LogError(f"{path}: line {number + 1} does not have exactly the log fields")
        if entry["seq"] != number:
            raise LogError(f"{path}: line {number + 1} has seq {entry['seq']!r}, expected {number}: a line was removed, "
                           "added or moved")
        if entry["prev"] != head:
            raise LogError(f"{path}: line {number + 1} does not follow line {number}: the chain is broken here")
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry_hash(body) != entry["hash"]:
            raise LogError(f"{path}: line {number + 1} was edited after it was written (its hash does not match)")
        head, length = entry["hash"], number + 1
    return length, head


def head_at(path: Path, length: int) -> str:
    """The head after the first `length` entries of a log that verifies whole, or `LogError`."""
    total, head = verify_file(path)
    if type(length) is not int or not 0 <= length <= total:
        raise LogError(f"{path}: the log holds {total} entries, not at least {length}")
    if length in (0, total):
        return GENESIS if length == 0 else head
    with open(path, "rb") as handle:
        for number, line in enumerate(handle):
            if number == length - 1:
                return loads(line.rstrip(b"\n"), max_bytes=4096, max_depth=1)["hash"]
    raise LogError(f"{path}: the log changed while it was being read")


class SignatureLog:
    """The open log. `append` writes one entry and syncs it before returning; it is safe to call from many threads."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.length, self.head = verify_file(self.path)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        self._fd = fd
        self._lock = threading.Lock()

    def append(self, *, outcome: str, code: str, purpose: str, key_id: str, uid: int, pid: int, data: bytes,
               signature: bytes, approvers: Sequence[str] = ()) -> int:
        with self._lock:
            fields = {"seq": self.length, "prev": self.head, "at_ms": time.time_ns() // 1_000_000,
                      "outcome": outcome, "code": code, "purpose": purpose, "key_id": key_id, "uid": uid, "pid": pid,
                      "data_sha256": hashlib.sha256(data).hexdigest(),
                      "signature_sha256": hashlib.sha256(signature).hexdigest() if signature else ""}
            if approvers:
                fields["approvers"] = ",".join(approvers)
            digest = entry_hash(fields)
            line = canonical({**fields, "hash": digest}) + b"\n"
            try:
                written = os.write(self._fd, line)
                if written != len(line):
                    raise OSError(f"wrote {written} of {len(line)} bytes")
                os.fsync(self._fd)
            except OSError as exc:
                raise LogError(f"the log write did not reach the disk: {exc}") from None
            seq = self.length
            self.length, self.head = self.length + 1, digest
            return seq

    def state(self) -> Tuple[int, str]:
        with self._lock:
            return self.length, self.head

    def close(self) -> None:
        os.close(self._fd)
