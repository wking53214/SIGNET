"""client: what a program that needs signatures holds instead of a key.

`signer(socket_path, purpose)` returns a `sign(data) -> bytes` callable of the shape zeta (`LockEvaluator(signer=)`),
beta (`lock_result_signer=`) and delta (`sign_receipt(..., sign)`) already take. Plug it in where a private key's
`sign` used to go; the library does not change.

It FAILS CLOSED: if signet refuses, the callable raises `SignetRefused` (with the refusal code); if signet cannot be
reached or answers with anything but a well-formed reply, it raises `SignetUnavailable`. It never returns anything
but a signature. zeta and beta treat a raising signer as "no Decision" and put the lock state back.

This module never imports signet's key store, server, log or config (CLAUDE.md rule 3).
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import Callable, Optional, Tuple

from .names import check_name
from .protocol import REFUSAL_CODES, VERSION, FrameError, read_frame, write_frame
from .registry import split_signature
from .strict import FormatError, loads


class SignetError(Exception):
    """No signature was returned."""


class SignetRefused(SignetError):
    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"signet refused ({code}): {reason}")
        self.code = code
        self.reason = reason


class SignetUnavailable(SignetError):
    """signet could not be reached, or did not answer properly."""


def _server_uid(sock: socket.socket) -> int:
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)[1]


def request(socket_path: "str | Path", purpose: str, data: bytes, *, timeout: float = 10.0,
            expected_uid: Optional[int] = None) -> Tuple[bytes, int]:
    """Ask signet to sign `data` for `purpose`: `(signature, log seq)`, or `SignetRefused` / `SignetUnavailable`.

    With `expected_uid`, the account at the other end of the socket (as the kernel reports it) must be signet's, or
    nothing is sent: a program that took over the socket path never sees the bytes."""
    if type(data) is not bytes:
        raise TypeError(f"data must be exact bytes, got {type(data).__name__}")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(str(socket_path))
            if expected_uid is not None and _server_uid(sock) != expected_uid:
                raise SignetUnavailable(f"the program at {socket_path} runs as uid {_server_uid(sock)}, not signet's "
                                        f"uid {expected_uid}; nothing was sent")
            write_frame(sock, {"v": VERSION, "purpose": purpose, "data": data.hex()})
            raw = read_frame(sock, 64 * 1024)
        except (OSError, FrameError) as exc:
            raise SignetUnavailable(f"signet at {socket_path} did not answer: {exc}") from None
    finally:
        sock.close()
    try:
        answer = loads(raw, max_depth=2)
    except FormatError as exc:
        raise SignetUnavailable(f"signet's answer is not strict JSON: {exc}") from None
    if answer.get("v") != VERSION or type(answer.get("ok")) is not bool:
        raise SignetUnavailable("signet's answer is not a signet reply")
    if not answer["ok"]:
        if set(answer) != {"v", "ok", "code", "reason"} or answer["code"] not in REFUSAL_CODES \
                or type(answer["reason"]) is not str:
            raise SignetUnavailable("signet's refusal is not well formed")
        raise SignetRefused(answer["code"], answer["reason"])
    if set(answer) != {"v", "ok", "seq", "signature"} or type(answer["seq"]) is not int \
            or type(answer["signature"]) is not str:
        raise SignetUnavailable("signet's answer is not well formed")
    try:
        signature = bytes.fromhex(answer["signature"])
        split_signature(signature)
    except ValueError as exc:
        raise SignetUnavailable(f"signet's signature is not well formed: {exc}") from None
    return signature, answer["seq"]


def signer(socket_path: "str | Path", purpose: str, *, timeout: float = 10.0,
           expected_uid: Optional[int] = None) -> Callable[[bytes], bytes]:
    """A `sign(data) -> bytes` callable for one purpose, backed by the signet at `socket_path`. Pass `expected_uid`
    (signet's account number) in production, so a program squatting on the socket path is never sent anything."""
    check_name("purpose", purpose)
    if expected_uid is not None and (type(expected_uid) is not int or expected_uid < 0):
        raise ValueError("expected_uid is an account number")

    def sign(data: bytes) -> bytes:
        return request(socket_path, purpose, data, timeout=timeout, expected_uid=expected_uid)[0]

    return sign
