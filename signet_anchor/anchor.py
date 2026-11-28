"""The anchor directory: publish a registry or a checkpoint, and check the live log against everything published."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple

from signet.log import LogError, head_at, verify_file
from signet.registry import Registry, RegistryError, load_registry
from signet.trust import TrustError, TrustState
from signet.verify import CHECKPOINT_SCHEMA_2, Checkpoint, read_checkpoint

REGISTRIES = "registries"
CHECKPOINTS = "checkpoints"


class AnchorError(ValueError):
    """Something the anchor will not hold, or an anchor that does not check out."""


def _numbered(folder: Path) -> List[Tuple[int, Path]]:
    if not folder.exists():
        return []
    out = []
    for path in sorted(folder.iterdir()):
        stem, dot, ext = path.name.partition(".")
        if dot != "." or ext != "json" or len(stem) != 6 or not stem.isdigit():
            raise AnchorError(f"{path} is not a numbered anchor file (six digits, .json)")
        out.append((int(stem), path))
    return out


def _write_new(folder: Path, number: int, text: bytes) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{number:06d}.json"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        raise AnchorError(f"{path} already exists; the anchor never replaces a file") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _registries(anchor: Path, root_key: str) -> List[Registry]:
    """Every anchored registry, checked, oldest first. Versions must only go up and match the file names."""
    out: List[Registry] = []
    state = TrustState(root_key)
    for number, path in _numbered(anchor / REGISTRIES):
        try:
            registry = load_registry(path.read_bytes(), root_key)
        except RegistryError as exc:
            raise AnchorError(f"{path}: {exc}") from None
        if registry.version != number:
            raise AnchorError(f"{path} holds registry version {registry.version}, not {number}")
        if out and registry.version <= out[-1].version:
            raise AnchorError(f"{path}: registry versions must only go up")
        try:
            state = state.accept(registry)  # a revoked key stays revoked in every later anchored version
        except TrustError as exc:
            raise AnchorError(f"{path}: {exc}") from None
        out.append(registry)
    return out


def latest_registry(anchor: "str | Path", root_key: str) -> Registry:
    """The newest anchored registry, checked against the pinned root key. A checker holds this one."""
    registries = _registries(Path(anchor), root_key)
    if not registries:
        raise AnchorError("the anchor holds no registry yet")
    return registries[-1]


def publish_registry(anchor: "str | Path", text: "bytes | str", root_key: str) -> Path:
    """Add a registry to the anchor. It must verify under the pinned root and be newer than every anchored one."""
    anchor = Path(anchor)
    previous = _registries(anchor, root_key)
    floor = previous[-1].version + 1 if previous else 1
    raw = text.encode("utf-8") if isinstance(text, str) else text
    try:
        registry = load_registry(raw, root_key, min_version=floor)
        state = TrustState(root_key)
        for older in previous:
            state = state.accept(older)
        state.accept(registry)
    except RegistryError as exc:
        raise AnchorError(str(exc)) from None
    return _write_new(anchor / REGISTRIES, registry.version, raw)


def _head_at(log: Path, length: int) -> Tuple[int, Optional[str]]:
    """`(log length, head after `length` entries)`, or `(log length, None)` if the log is shorter than `length`.
    The whole log, every sealed segment included, is verified first, so every head read here is part of one unbroken
    chain."""
    try:
        total, _head = verify_file(log)
        if length > total:
            return total, None
        return total, head_at(log, length)
    except LogError as exc:
        raise AnchorError(f"the log does not verify: {exc}") from None


def _checkpoints(anchor: Path, registry: Registry) -> List[Tuple[Path, int, str]]:
    return [(path, cp.length, cp.head) for path, cp, _raw in _read_checkpoints(anchor, registry)]


def _read_checkpoints(anchor: Path, registry: Registry) -> List[Tuple[Path, Checkpoint, bytes]]:
    """Every anchored checkpoint, checked. Schema 2 ones must name the file before them (`previous`), never go back in
    time, and once one is schema 2 every later one is too (no downgrade to the unchained form)."""
    out: List[Tuple[Path, Checkpoint, bytes]] = []
    for number, path in _numbered(anchor / CHECKPOINTS):
        if number != len(out) + 1:
            raise AnchorError(f"{path}: checkpoints are numbered 1, 2, 3 ... with none missing")
        raw = path.read_bytes()
        try:
            cp = read_checkpoint(raw, registry)
        except ValueError as exc:
            raise AnchorError(f"{path}: {exc}") from None
        _check_link(path, cp, out)
        out.append((path, cp, raw))
    return out


def _check_link(where: "Path | str", cp: Checkpoint, before: List[Tuple[Path, Checkpoint, bytes]]) -> None:
    last = before[-1] if before else None
    if cp.schema != CHECKPOINT_SCHEMA_2:
        if last is not None and last[1].schema == CHECKPOINT_SCHEMA_2:
            raise AnchorError(f"{where}: an unchained checkpoint after a chained one (a downgrade)")
        return
    expected = hashlib.sha256(last[2]).hexdigest() if last is not None else ""
    if cp.previous != expected:
        raise AnchorError(f"{where}: does not name the checkpoint before it: one was removed, swapped or replaced")
    if last is not None and last[1].at_ms is not None and cp.at_ms < last[1].at_ms:
        raise AnchorError(f"{where}: signed at {cp.at_ms}, before the checkpoint it follows ({last[1].at_ms})")


def check(anchor: "str | Path", log: "str | Path", root_key: str, *, max_unanchored: Optional[int] = None,
          max_age_ms: Optional[int] = None, now_ms: Optional[int] = None) -> List[str]:
    """Every problem with the anchor, or with the live log against it. Empty means the log extends everything published.

    With `max_unanchored`, more than that many live log entries after the newest checkpoint is a problem; with
    `max_age_ms`, a newest checkpoint older than that (by its schema 2 `at_ms`) is one. Either names suppressed or
    stalled publishing, which the anchor otherwise cannot see."""
    anchor, log = Path(anchor), Path(log)
    try:
        registry = latest_registry(anchor, root_key)
        anchored = _checkpoints(anchor, registry)
    except AnchorError as exc:
        return [str(exc)]
    problems: List[str] = []
    seen = {}
    last = 0
    for path, length, head in anchored:
        if length < last:
            problems.append(f"{path.name}: a checkpoint of {length} entries after one of {last}: published history went "
                            "backwards")
        last = max(last, length)
        if seen.get(length, head) != head:
            problems.append(f"{path.name}: a second head for {length} entries: the log was forked")
        seen.setdefault(length, head)
        try:
            total, live = _head_at(log, length)
        except AnchorError as exc:
            return problems + [str(exc)]
        if live is None:
            problems.append(f"{path.name}: the log holds {total} entries, fewer than the {length} this checkpoint "
                            "covers: history was lost")
        elif live != head:
            problems.append(f"{path.name}: the log's entry {length} is not the one this checkpoint names: history was "
                            "rewritten")
    if max_unanchored is not None or max_age_ms is not None:
        problems += _staleness(anchor, log, registry, max_unanchored, max_age_ms, now_ms)
    return problems


def _staleness(anchor: Path, log: Path, registry: Registry, max_unanchored: Optional[int], max_age_ms: Optional[int],
               now_ms: Optional[int]) -> List[str]:
    try:
        total, _head = verify_file(log)
    except LogError as exc:
        return [f"the log does not verify: {exc}"]
    newest = _read_checkpoints(anchor, registry)
    covered = newest[-1][1].length if newest else 0
    out = []
    if max_unanchored is not None and total - covered > max_unanchored:
        out.append(f"stale: {total - covered} log entries are not covered by any anchored checkpoint (limit "
                   f"{max_unanchored}): publishing has stopped or is being held back")
    if max_age_ms is not None:
        now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
        if not newest or newest[-1][1].at_ms is None:
            out.append("stale: no chained (schema 2) checkpoint is anchored, so its age cannot be checked")
        elif now - newest[-1][1].at_ms > max_age_ms:
            out.append(f"stale: the newest anchored checkpoint is {now - newest[-1][1].at_ms} ms old (limit "
                       f"{max_age_ms})")
    return out


def publish_checkpoint(anchor: "str | Path", text: "bytes | str", log: "str | Path", root_key: str) -> Path:
    """Add a checkpoint. It must be signed by a log key the newest anchored registry trusts, cover at least as much as
    every anchored checkpoint, and match the live log, which must still match everything already anchored."""
    anchor = Path(anchor)
    raw = text.encode("utf-8") if isinstance(text, str) else text
    registry = latest_registry(anchor, root_key)
    try:
        cp = read_checkpoint(raw, registry)
    except ValueError as exc:
        raise AnchorError(str(exc)) from None
    length, head = cp.length, cp.head
    _check_link("this checkpoint", cp, _read_checkpoints(anchor, registry))
    problems = check(anchor, log, root_key)
    if problems:
        raise AnchorError("the anchor or the log already fails its check: " + "; ".join(problems))
    anchored = _checkpoints(anchor, registry)
    if anchored and length <= anchored[-1][1]:
        raise AnchorError(f"this checkpoint covers {length} entries; the anchor already covers {anchored[-1][1]}")
    _total, live = _head_at(Path(log), length)
    if live != head:
        raise AnchorError("the checkpoint does not match the live log")
    return _write_new(anchor / CHECKPOINTS, len(anchored) + 1, raw)
