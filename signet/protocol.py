"""protocol: one request and one answer per connection, over signet's local socket.

A FRAME is a 4-byte big-endian length, then that many bytes of strict JSON (`signet.strict`). A length over the limit
is refused before anything more is read, so a caller cannot make signet hold a large message.

    request   {"v": 1, "purpose": "zeta-lock-result", "data": "<hex of the bytes to sign>"}
              for a purpose with an approval rule, also "approvals": ["<approver key hex>:<signature hex>", ...]
              and "summary_sha256": "<64 hex>" (both or neither; see signet.approval)
    signed    {"v": 1, "ok": true, "seq": 41, "signature": "<hex of key_id:signature>"}
    refused   {"v": 1, "ok": false, "code": "wrong-label", "reason": "..."}

`seq` is the signature's line in signet's log. Refusal codes: `malformed`, `too-large`, `unknown-purpose`,
`not-allowed`, `wrong-label`, `not-approved`, `log-failed`, `internal`, `busy` (signet holds its most connections at
once; try again). Every one means no signature was made.

This module is imported by both the client and the server, and imports neither.
"""

from __future__ import annotations

import socket
import struct
from typing import Any, Dict

from .strict import canonical

VERSION = 1
MAX_FRAME = 1 << 20
REFUSAL_CODES = ("malformed", "too-large", "unknown-purpose", "not-allowed", "wrong-label", "not-approved", "log-failed",
                 "internal", "busy")
MAX_APPROVALS = 64
# The longest approval string: key hex, an approval time of up to 15 digits, signature hex, two colons.
MAX_APPROVAL_LEN = 64 + 1 + 15 + 1 + 128


class FrameError(Exception):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _read_exact(sock: socket.socket, count: int) -> bytes:
    chunks = []
    while count:
        chunk = sock.recv(min(count, 65536))
        if not chunk:
            raise FrameError("malformed", "the connection closed before the whole message arrived")
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def read_frame(sock: socket.socket, max_bytes: int = MAX_FRAME) -> bytes:
    (length,) = struct.unpack(">I", _read_exact(sock, 4))
    if length > max_bytes:
        raise FrameError("too-large", f"a message of {length} bytes is over the limit of {max_bytes}")
    return _read_exact(sock, length)


def write_frame(sock: socket.socket, message: Dict[str, Any]) -> None:
    body = canonical(message)
    sock.sendall(struct.pack(">I", len(body)) + body)
