"""strict: the one way signet reads JSON and the one way it writes the bytes it hashes or signs.

READING (`loads`). Every file and message signet reads (the config, the registry, a checkpoint, a request on the
socket, a log line) goes through here. A reader that is lenient is a reader an attacker can disagree with, so it
refuses, with `FormatError` naming why:

  - more than `max_bytes` bytes, or bytes that are not strict UTF-8;
  - a key twice in one object (Python's own reader keeps the last one silently, so one file could say two things);
  - a float, an exponent, NaN or Infinity (nothing signet reads is fractional, and floats round differently by reader);
  - an integer outside +/-(2**53 - 1), the range every common JSON reader agrees on;
  - nesting deeper than `max_depth`;
  - a top level that is not an object.

WRITING (`canonical`). The bytes signet hashes and signs are JSON with sorted keys, no spaces, ASCII only (anything
else escaped) and no NaN. It is the same canonical form delta and zeta use for their signing inputs. A string that
does not encode as strict UTF-8 (a lone surrogate) is refused: with ASCII escaping, an astral character and the
surrogate pair of its two halves would otherwise be written the same way.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Tuple

MAX_SAFE_INT = 2**53 - 1


class FormatError(ValueError):
    """Input that signet will not read, or a value it will not write canonically."""


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise FormatError(f"the key {key!r} appears twice in one object; the last would win silently")
        out[key] = value
    return out


def _no_float(text: str) -> Any:
    raise FormatError(f"a fractional or exponent number ({text}) is not accepted")


def _no_constant(text: str) -> Any:
    raise FormatError(f"{text} is not accepted")


def _bounded_int(text: str) -> int:
    value = int(text)
    if abs(value) > MAX_SAFE_INT:
        raise FormatError(f"the integer {text[:24]} is outside +/-(2**53 - 1)")
    return value


def _depth(value: Any, limit: int, level: int = 0) -> None:
    if level > limit:
        raise FormatError(f"nested deeper than {limit} levels")
    if isinstance(value, dict):
        for item in value.values():
            _depth(item, limit, level + 1)
    elif isinstance(value, list):
        for item in value:
            _depth(item, limit, level + 1)


def loads(data: "bytes | str", *, max_bytes: int = 1 << 20, max_depth: int = 16) -> Dict[str, Any]:
    """Read one JSON object strictly, or raise `FormatError`. See the module docstring for every refusal."""
    if isinstance(data, str):
        try:
            raw = data.encode("utf-8")
        except UnicodeEncodeError:
            raise FormatError("the text does not encode as strict UTF-8") from None
    elif type(data) is bytes:
        raw = data
    else:
        raise FormatError(f"expected bytes or str, got {type(data).__name__}")
    if len(raw) > max_bytes:
        raise FormatError(f"{len(raw)} bytes is more than the limit of {max_bytes}")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise FormatError("the bytes are not strict UTF-8") from None
    try:
        value = json.loads(text, object_pairs_hook=_no_duplicates, parse_float=_no_float,
                           parse_constant=_no_constant, parse_int=_bounded_int)
    except FormatError:
        raise
    except RecursionError:
        raise FormatError(f"nested deeper than {max_depth} levels") from None
    except ValueError as exc:
        raise FormatError(f"not valid JSON: {exc}") from None
    if type(value) is not dict:
        raise FormatError(f"the top level must be an object, not {type(value).__name__}")
    _depth(value, max_depth)
    return value


def _check_strings(value: Any, where: str) -> None:
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise FormatError(f"{where} does not encode as strict UTF-8 (a surrogate is not a character)") from None
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise FormatError(f"{where} has a key that is not an exact str")
            _check_strings(key, f"{where} key")
            _check_strings(item, f"{where}.{key}")
    elif type(value) is list:
        for i, item in enumerate(value):
            _check_strings(item, f"{where}[{i}]")
    elif type(value) is bool or value is None:
        return
    elif type(value) is int:
        if abs(value) > MAX_SAFE_INT:
            raise FormatError(f"{where} is outside +/-(2**53 - 1)")
    else:
        raise FormatError(f"{where} is a {type(value).__name__}; only exact str, int, bool, None, list and dict are written")


def canonical(value: Any) -> bytes:
    """The canonical bytes of a JSON value: sorted keys, no spaces, ASCII, exact builtin types only."""
    _check_strings(value, "value")
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
