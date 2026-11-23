"""server: the signer program. Run it as its own account; nothing that asks it for a signature can read its keys.

WHAT ONE REQUEST GOES THROUGH, in order (each failure is a refusal, logged, and no signature):

  1. the frame is at most 1 MiB and strict JSON with exactly v, purpose and data (`malformed`, `too-large`);
  2. the purpose is one this instance signs (`unknown-purpose`; signet's own two purposes are never on this list);
  3. the caller's account, read from the kernel (SO_PEERCRED, which the caller cannot set), is allowed for that
     purpose (`not-allowed`);
  4. the bytes start with that purpose's label (`wrong-label`), so a key never signs bytes meant for another purpose;
  5. the bytes are signed with that purpose's key, the signature is written to the log and synced (`log-failed` if
     not), and only then is the signature sent back.

Requests run in parallel threads; the log serialises its own writes. One connection carries one request and is closed
after `request_timeout_ms` if the request has not arrived.

START is refused (exit 2, one line naming why) on: a platform without SO_PEERCRED (only Linux is claimed), a config
`signet.config` refuses, a key that `signet.keys` refuses, a log that does not verify, or a socket path held by a
running signet or by anything that is not a socket, or a socket directory that another account could write to. A socket file left by a signet that died is removed.
"""

from __future__ import annotations

import os
import signal
import socket
import socketserver
import stat
import struct
import sys
import threading
from typing import Any, Dict, Tuple

from . import keys as key_store
from .config import Config
from .log import LogError, SignatureLog
from .protocol import VERSION, FrameError, read_frame, write_frame
from .strict import FormatError, loads


class StartError(Exception):
    """signet will not start, and why."""


class Signer:
    """The decision for one request, without the socket, so it can be tested on its own."""

    def __init__(self, config: Config, log: SignatureLog) -> None:
        self.config = config
        self.log = log
        self.keys = {p.name: (p.key_id, key_store.load(config.keys_dir, p.key_id)) for p in config.purposes.values()}

    def _refuse(self, code: str, reason: str, *, purpose: str, uid: int, pid: int, data: bytes) -> Dict[str, Any]:
        try:
            self.log.append(outcome="refused", code=code, purpose=purpose, key_id="", uid=uid, pid=pid, data=data,
                            signature=b"")
        except LogError:
            pass  # the request is refused either way; the refusal is also printed by the handler
        return {"v": VERSION, "ok": False, "code": code, "reason": reason}

    def handle(self, raw: bytes, uid: int, pid: int) -> Dict[str, Any]:
        try:
            request = loads(raw, max_depth=2)
        except FormatError as exc:
            return self._refuse("malformed", str(exc), purpose="", uid=uid, pid=pid, data=raw)
        if set(request) != {"v", "purpose", "data"} or request["v"] != VERSION or type(request["purpose"]) is not str \
                or type(request["data"]) is not str:
            return self._refuse("malformed", "a request has exactly v (1), purpose and data (hex)", purpose="", uid=uid,
                                pid=pid, data=raw)
        purpose_name = request["purpose"]
        try:
            if request["data"] != request["data"].lower():
                raise ValueError
            data = bytes.fromhex(request["data"])
        except ValueError:
            return self._refuse("malformed", "data is lowercase hex", purpose="", uid=uid, pid=pid, data=raw)
        purpose = self.config.purposes.get(purpose_name)
        if purpose is None:
            return self._refuse("unknown-purpose", f"this signet does not sign {purpose_name[:64]!r}", purpose="",
                                uid=uid, pid=pid, data=data)
        if uid not in purpose.allowed_uids:
            return self._refuse("not-allowed", f"account {uid} may not ask for {purpose.name!r} signatures",
                                purpose=purpose.name, uid=uid, pid=pid, data=data)
        if not data.startswith(purpose.label):
            return self._refuse("wrong-label", f"{purpose.name!r} signs only bytes that start with its label",
                                purpose=purpose.name, uid=uid, pid=pid, data=data)
        key_id, key = self.keys[purpose.name]
        signature = key_id.encode("ascii") + b":" + key.sign(data)
        try:
            seq = self.log.append(outcome="signed", code="", purpose=purpose.name, key_id=key_id, uid=uid, pid=pid,
                                  data=data, signature=signature)
        except LogError as exc:
            return {"v": VERSION, "ok": False, "code": "log-failed", "reason": f"not released: {exc}"}
        return {"v": VERSION, "ok": True, "seq": seq, "signature": signature.hex()}


def peer(sock: socket.socket) -> Tuple[int, int]:
    """(uid, pid) of the process at the other end, as the kernel reports it."""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, _gid = struct.unpack("3i", raw)
    return uid, pid


def _check_socket_dir(path: Any) -> None:
    """The socket's directory must belong to signet's account (or root) and be writable by no one else. Otherwise
    another account could remove signet's socket and put its own in its place, and callers would hand their bytes to
    it (a checker would still refuse its signatures, but the bytes would have gone to the wrong program)."""
    parent = os.path.dirname(os.path.abspath(path))
    info = os.lstat(parent)
    if not stat.S_ISDIR(info.st_mode):
        raise StartError(f"{parent} is not a directory (a link is refused)")
    if info.st_uid not in (os.geteuid(), 0):
        raise StartError(f"{parent} is owned by uid {info.st_uid}; the socket's directory must be signet's or root's")
    if info.st_mode & 0o022:
        raise StartError(f"{parent} has mode {stat.S_IMODE(info.st_mode):o}; no one but its owner may write to the "
                         "socket's directory")


def _claim_socket(path: Any) -> None:
    _check_socket_dir(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise StartError(f"{path} exists and is not a socket; signet will not replace it")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(path))
    except (ConnectionRefusedError, FileNotFoundError):
        os.unlink(path)  # left by a signet that is no longer running
        return
    finally:
        probe.close()
    raise StartError(f"another signet is already serving on {path}")


def build(config: Config) -> Tuple[socketserver.ThreadingUnixStreamServer, SignatureLog]:
    if not hasattr(socket, "SO_PEERCRED") or not sys.platform.startswith("linux"):
        raise StartError("signet reads the caller's account with SO_PEERCRED, which only Linux is claimed to provide")
    try:
        log = SignatureLog(config.log)
    except LogError as exc:
        raise StartError(str(exc)) from None
    try:
        signer = Signer(config, log)
    except key_store.KeyStoreError as exc:
        log.close()
        raise StartError(str(exc)) from None
    _claim_socket(config.socket)
    timeout = config.request_timeout_ms / 1000

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            sock: socket.socket = self.request
            sock.settimeout(timeout)
            uid, pid = peer(sock)
            try:
                raw = read_frame(sock)
            except FrameError as exc:
                answer = signer._refuse(exc.code, exc.reason, purpose="", uid=uid, pid=pid, data=b"")
            except (socket.timeout, OSError):
                signer._refuse("malformed", "no complete request before the timeout", purpose="", uid=uid, pid=pid,
                               data=b"")
                return
            else:
                try:
                    answer = signer.handle(raw, uid, pid)
                except Exception as exc:  # noqa: BLE001 - one bad request must not stop the signer; it is refused
                    answer = {"v": VERSION, "ok": False, "code": "internal", "reason": type(exc).__name__}
            if not answer["ok"]:
                try:
                    print(f"signet: refused uid {uid} pid {pid}: {answer['code']}: {answer['reason']}",
                          file=sys.stderr, flush=True)
                except OSError:
                    pass  # stderr is gone (its reader exited); the refusal is in the log, and the caller still hears it
            try:
                write_frame(sock, answer)
            except OSError:
                pass  # the caller left; a signature it did not receive is still in the log

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        request_queue_size = 128  # the default of 5 refused callers in a burst (found by the 32-caller test)

    old = os.umask(0o111)
    try:
        server = Server(str(config.socket), Handler)
    finally:
        os.umask(old)
    # Anyone on the machine may connect; who may get a signature is decided per purpose from the kernel's account.
    os.chmod(config.socket, 0o666)
    return server, log


def serve(config: Config) -> int:
    server, log = build(config)
    stop = threading.Event()

    def on_signal(_signum: int, _frame: Any) -> None:
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    length, _head = log.state()
    print(f"signet: serving {len(config.purposes)} purpose(s) on {config.socket}; log {config.log} at {length} "
          "entries", file=sys.stderr, flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        try:
            os.unlink(config.socket)
        except FileNotFoundError:
            pass
        log.close()
    return 0
