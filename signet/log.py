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

A SUMMARY line stands for refusals that were counted but not written one by one (an account over its refusal
budget, or the disk under its floor; see `signet.server`): outcome `refused`, code `suppressed`, the account, and
`suppressed`, how many. Other lines do not have the field.

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

SEGMENTS (rotation, T14). With `rotate_bytes` and a `seal` (see `signet.server`), once the live file reaches that size
signet closes it before the next write: it signs a checkpoint of the log so far with the `signet-log` key (the SEAL)
and moves the file into `<log>.segments/`:

    <log>.segments/000001.log          entries 0 .. L1-1, unchanged
    <log>.segments/000001.seal.json    a schema 1 checkpoint of length L1 and the head after it
    <log>                              the live segment: its first line is seq L1, prev that head

`seq` never restarts and `prev` crosses the boundary, so all segments in order are ONE chain: `verify_file` checks
every segment and the live file as one, and checks each seal against the point it names. Nothing is ever deleted.

On start, signet checks only the newest sealed segment (from the seal before it) and the live file, so start-up time
no longer grows with history. A rotation interrupted after its seal was written and before the file was moved is
finished on start, but only if the live file ends exactly where that seal says.

WHAT THIS DOES NOT DO. Whoever controls signet's account can rewrite the whole file and its chain. A published
checkpoint is what makes that visible; the log alone cannot. `at_ms` is signet's own clock. Start-up does not re-check
sealed segments older than the newest, nor any seal's signature: `signet verify-log`, `signet checkpoint`, `signet
status` and the anchor check the whole chain, and `signet check-checkpoint` checks a seal's signature.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from pathlib import Path
from collections import deque
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from .strict import FormatError, canonical, loads

ENTRY_LABEL = b"signet-log-entry/1\n"
GENESIS = "0" * 64
SEAL_SCHEMA = "signet-log-checkpoint/1"
SEAL_FIELDS = frozenset({"schema", "length", "head", "signature"})
FIELDS = frozenset({"seq", "prev", "at_ms", "outcome", "code", "purpose", "key_id", "uid", "pid", "data_sha256",
                    "signature_sha256", "hash"})


class LogError(Exception):
    """A log that does not verify, or a write that did not reach the disk."""


def entry_hash(fields: Dict[str, Any]) -> str:
    return hashlib.sha256(ENTRY_LABEL + canonical(fields)).hexdigest()


def segment_dir(path: Path) -> Path:
    """Where sealed segments of the log at `path` are kept."""
    path = Path(path)
    return path.with_name(path.name + ".segments")


def _verify_bytes(raw: bytes, where: Path, seq: int, head: str) -> Tuple[int, str]:
    """`(length, head)` after the lines of one file, which must continue a chain at `seq` entries and `head`."""
    if raw and not raw.endswith(b"\n"):
        raise LogError(f"{where}: the last line is torn (no newline): a write was interrupted. Its signature was never "
                       "released; remove the partial line after checking it, then start signet again")
    length = seq
    for number, line in enumerate(raw.split(b"\n")[:-1] if raw else []):
        try:
            entry = loads(line, max_bytes=4096, max_depth=1)
        except FormatError as exc:
            raise LogError(f"{where}: line {number + 1} is not a log entry: {exc}") from None
        if set(entry) not in (FIELDS, FIELDS | {"approvers"}, FIELDS | {"suppressed"}):
            raise LogError(f"{where}: line {number + 1} does not have exactly the log fields")
        if entry["seq"] != seq + number:
            raise LogError(f"{where}: line {number + 1} has seq {entry['seq']!r}, expected {seq + number}: a line was "
                           "removed, added or moved")
        if entry["prev"] != head:
            raise LogError(f"{where}: line {number + 1} does not follow the entry before it: the chain is broken here")
        body = {k: v for k, v in entry.items() if k != "hash"}
        if entry_hash(body) != entry["hash"]:
            raise LogError(f"{where}: line {number + 1} was edited after it was written (its hash does not match)")
        head, length = entry["hash"], seq + number + 1
    return length, head


def _read(path: Path) -> bytes:
    try:
        return Path(path).read_bytes()
    except FileNotFoundError:
        return b""


def read_seal(path: Path) -> Tuple[int, str]:
    """`(length, head)` a seal file names. Its signature is checked by `signet check-checkpoint`, not here."""
    try:
        doc = loads(Path(path).read_bytes(), max_bytes=4096, max_depth=1)
    except (OSError, FormatError) as exc:
        raise LogError(f"{path}: not a readable seal: {exc}") from None
    if set(doc) != SEAL_FIELDS or doc["schema"] != SEAL_SCHEMA or type(doc["length"]) is not int or doc["length"] < 1 \
            or type(doc["head"]) is not str or len(doc["head"]) != 64:
        raise LogError(f"{path}: not a seal (a schema 1 checkpoint)")
    return doc["length"], doc["head"]


def _segments(path: Path) -> List[Tuple[int, Optional[Path], Path]]:
    """`(number, segment file or None, seal file)` for every sealed segment, oldest first. Only the newest may lack its
    segment file (a rotation interrupted after the seal was written: the live file is still that segment)."""
    folder = segment_dir(path)
    if not folder.exists():
        return []
    logs, seals = {}, {}
    for item in folder.iterdir():
        if item.name.startswith(".") and item.name.endswith(".seal.tmp"):
            continue  # a seal whose rotation crashed before it was renamed into place: it never took effect
        stem, dot, ext = item.name.partition(".")
        if dot == "." and len(stem) == 6 and stem.isdigit() and ext in ("log", "seal.json"):
            (logs if ext == "log" else seals)[int(stem)] = item
        else:
            raise LogError(f"{item} is not a log segment (six digits, .log or .seal.json)")
    numbers = sorted(seals)
    if numbers != list(range(1, len(numbers) + 1)) or set(logs) - set(seals):
        raise LogError(f"{folder}: segments are numbered 1, 2, 3 ... each with its seal, none missing")
    out = [(n, logs.get(n), seals[n]) for n in numbers]
    if any(log is None for _n, log, _seal in out[:-1]):
        raise LogError(f"{folder}: a sealed segment other than the newest is missing")
    return out


def _files(path: Path) -> List[Tuple[Path, Optional[Path]]]:
    """Every file of the log in order, each with the seal that must close it (None for the live file)."""
    path = Path(path)
    segments = _segments(path)
    out: List[Tuple[Path, Optional[Path]]] = [(log, seal) for _n, log, seal in segments if log is not None]
    if segments and segments[-1][1] is None:
        return out + [(path, segments[-1][2])]  # the interrupted rotation: the live file is the sealed segment
    return out + [(path, None)]


def _check_seal(seal: Path, length: int, head: str) -> None:
    if read_seal(seal) != (length, head):
        raise LogError(f"{seal}: the seal does not name the end of its segment ({length} entries): the segment or its "
                       "seal was changed")


def verify_file(path: Path) -> Tuple[int, str]:
    """`(length, head)` of a log that verifies from its first entry to its last, across every sealed segment and the
    live file, or `LogError` naming the file and line."""
    length, head = 0, GENESIS
    for file, seal in _files(path):
        length, head = _verify_bytes(_read(file), file, length, head)
        if seal is not None:
            _check_seal(seal, length, head)
    return length, head


def entries(path: Path) -> Iterator[Dict[str, Any]]:
    """Every entry, oldest first, across segments. Read only; verify with `verify_file` first."""
    for file, _seal in _files(path):
        for line in _read(file).split(b"\n"):
            if line:
                yield loads(line, max_bytes=4096, max_depth=1)


def last_entries(path: Path, count: int) -> List[Dict[str, Any]]:
    return list(deque(entries(path), maxlen=count))


def head_at(path: Path, length: int) -> str:
    """The head after the first `length` entries of a log that verifies whole, or `LogError`."""
    total, head = verify_file(path)
    if type(length) is not int or not 0 <= length <= total:
        raise LogError(f"{path}: the log holds {total} entries, not at least {length}")
    if length in (0, total):
        return GENESIS if length == 0 else head
    start = 0
    for file, seal in _files(path):
        end = read_seal(seal)[0] if seal is not None else total
        if length <= end:
            for number, line in enumerate(_read(file).split(b"\n")):
                if start + number == length - 1:
                    return loads(line, max_bytes=4096, max_depth=1)["hash"]
        start = end
    raise LogError(f"{path}: the log changed while it was being read")


def _fsync_dir(folder: Path) -> None:
    fd = os.open(folder, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _open_state(path: Path) -> Tuple[int, str, int]:
    """`(length, head, sealed segments)` checking only the newest sealed segment and the live file. Finishes a rotation
    interrupted between its seal and the move, if the live file ends exactly where that seal says."""
    path = Path(path)
    segments = _segments(path)
    if not segments:
        length, head = _verify_bytes(_read(path), path, 0, GENESIS)
        return length, head, 0
    before = read_seal(segments[-2][2]) if len(segments) > 1 else (0, GENESIS)
    if len(segments) > 1 and before[1] != head_of_file(segments[-2][1], before[0]):
        raise LogError(f"{segments[-2][1]}: its last entry is not the one its seal names")
    number, log, seal = segments[-1]
    if log is None:
        length, head = _verify_bytes(_read(path), path, *before)
        _check_seal(seal, length, head)
        target = segment_dir(path) / f"{number:06d}.log"
        try:
            os.rename(path, target)
            _fsync_dir(target.parent)
            _fsync_dir(path.parent)
        except OSError as exc:
            raise LogError(f"could not finish the interrupted rotation of {path}: {exc}") from None
        return length, head, number
    length, head = _verify_bytes(_read(log), log, *before)
    _check_seal(seal, length, head)
    length, head = _verify_bytes(_read(path), path, length, head)
    return length, head, number


def head_of_file(path: Path, length: int) -> str:
    """The `hash` of a segment file's last line, which must be entry `length - 1`."""
    lines = _read(path).split(b"\n")
    if len(lines) < 2 or lines[-1] != b"":
        raise LogError(f"{path}: an empty or torn segment")
    try:
        entry = loads(lines[-2], max_bytes=4096, max_depth=1)
    except FormatError as exc:
        raise LogError(f"{path}: its last line is not a log entry: {exc}") from None
    if entry.get("seq") != length - 1:
        raise LogError(f"{path}: its last entry is not entry {length - 1}")
    return entry["hash"]


class SignatureLog:
    """The open log. `append` writes one entry and syncs it before returning; it is safe to call from many threads.

    With `rotate_bytes` above 0 and a `seal` (length, head -> the seal file's bytes), the live file is sealed and
    moved into `segment_dir` before a write once it holds at least that many bytes. A rotation that fails leaves the
    log refusing every write (fail closed); start signet again, and the interrupted rotation is finished or refused."""

    def __init__(self, path: Path, rotate_bytes: int = 0,
                 seal: Optional[Callable[[int, str], bytes]] = None) -> None:
        self.path = Path(path)
        self.length, self.head, self._sealed = _open_state(self.path)
        self.rotate_bytes = rotate_bytes if seal is not None else 0
        self._seal = seal
        self._fd: Optional[int] = self._open()
        self._size = os.fstat(self._fd).st_size
        self._lock = threading.Lock()

    def _open(self) -> int:
        return os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)

    def _rotate(self) -> None:
        number = self._sealed + 1
        folder = segment_dir(self.path)
        seal_path, segment_path = folder / f"{number:06d}.seal.json", folder / f"{number:06d}.log"
        try:
            text = self._seal(self.length, self.head)  # type: ignore[misc]
            folder.mkdir(mode=0o700, exist_ok=True)
            temp = folder / f".{number:06d}.seal.tmp"
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(temp, seal_path)
            _fsync_dir(folder)
            os.close(self._fd)  # type: ignore[arg-type]
            self._fd = None
            os.rename(self.path, segment_path)
            _fsync_dir(folder)
            self._fd = self._open()
            _fsync_dir(self.path.parent)
        except Exception as exc:  # noqa: BLE001 - any failure leaves the log closed to writes
            if self._fd is not None:
                os.close(self._fd)
            self._fd = None
            raise LogError(f"the log rotation did not complete, so the log refuses writes until signet restarts: {exc}") \
                from None
        self._sealed, self._size = number, 0

    def append(self, *, outcome: str, code: str, purpose: str, key_id: str, uid: int, pid: int, data: bytes,
               signature: bytes, approvers: Sequence[str] = (), suppressed: int = 0) -> int:
        with self._lock:
            if self._fd is None:
                raise LogError("the log is closed to writes after a failed rotation; start signet again")
            if self.rotate_bytes and self._size >= self.rotate_bytes:
                self._rotate()
            fields = {"seq": self.length, "prev": self.head, "at_ms": time.time_ns() // 1_000_000,
                      "outcome": outcome, "code": code, "purpose": purpose, "key_id": key_id, "uid": uid, "pid": pid,
                      "data_sha256": hashlib.sha256(data).hexdigest(),
                      "signature_sha256": hashlib.sha256(signature).hexdigest() if signature else ""}
            if approvers:
                fields["approvers"] = ",".join(approvers)
            if suppressed:
                fields["suppressed"] = suppressed
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
            self._size += len(line)
            return seq

    def state(self) -> Tuple[int, str]:
        with self._lock:
            return self.length, self.head

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
