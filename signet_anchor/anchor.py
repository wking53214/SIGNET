"""The anchor directory: publish a registry or a checkpoint, and check the live log against everything published."""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

from signet.log import GENESIS, LogError, verify_file
from signet.registry import Registry, RegistryError, load_registry
from signet.strict import FormatError, loads
from signet.verify import check_checkpoint

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
    for number, path in _numbered(anchor / REGISTRIES):
        try:
            registry = load_registry(path.read_bytes(), root_key)
        except RegistryError as exc:
            raise AnchorError(f"{path}: {exc}") from None
        if registry.version != number:
            raise AnchorError(f"{path} holds registry version {registry.version}, not {number}")
        if out and registry.version <= out[-1].version:
            raise AnchorError(f"{path}: registry versions must only go up")
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
    except RegistryError as exc:
        raise AnchorError(str(exc)) from None
    return _write_new(anchor / REGISTRIES, registry.version, raw)


def _head_at(log: Path, length: int) -> Tuple[int, Optional[str]]:
    """`(log length, head after `length` entries)`, or `(log length, None)` if the log is shorter than `length`.
    The whole log is verified first, so every head read here is part of one unbroken chain."""
    try:
        total, _head = verify_file(log)
    except LogError as exc:
        raise AnchorError(f"the log does not verify: {exc}") from None
    if length > total:
        return total, None
    if length == 0:
        return total, GENESIS
    with open(log, "rb") as handle:
        for number, line in enumerate(handle):
            if number == length - 1:
                try:
                    return total, loads(line.rstrip(b"\n"), max_bytes=4096, max_depth=1)["hash"]
                except (FormatError, KeyError):
                    raise AnchorError(f"line {length} of the log cannot be read") from None
    raise AnchorError("the log changed while it was being read")


def _checkpoints(anchor: Path, registry: Registry) -> List[Tuple[Path, int, str]]:
    out: List[Tuple[Path, int, str]] = []
    for number, path in _numbered(anchor / CHECKPOINTS):
        if number != len(out) + 1:
            raise AnchorError(f"{path}: checkpoints are numbered 1, 2, 3 ... with none missing")
        try:
            length, head = check_checkpoint(path.read_bytes(), registry)
        except ValueError as exc:
            raise AnchorError(f"{path}: {exc}") from None
        out.append((path, length, head))
    return out


def check(anchor: "str | Path", log: "str | Path", root_key: str) -> List[str]:
    """Every problem with the anchor, or with the live log against it. Empty means the log extends everything published."""
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
    return problems


def publish_checkpoint(anchor: "str | Path", text: "bytes | str", log: "str | Path", root_key: str) -> Path:
    """Add a checkpoint. It must be signed by a log key the newest anchored registry trusts, cover at least as much as
    every anchored checkpoint, and match the live log, which must still match everything already anchored."""
    anchor = Path(anchor)
    raw = text.encode("utf-8") if isinstance(text, str) else text
    registry = latest_registry(anchor, root_key)
    try:
        length, head = check_checkpoint(raw, registry)
    except ValueError as exc:
        raise AnchorError(str(exc)) from None
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
