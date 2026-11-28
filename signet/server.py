"""server: the signer program. Run it as its own account; nothing that asks it for a signature can read its keys.

WHAT ONE REQUEST GOES THROUGH, in order (each failure is a refusal, logged, and no signature):

  1. the frame is at most 1 MiB and strict JSON with exactly v, purpose and data, and optionally approvals with
     summary_sha256 (`malformed`, `too-large`);
  2. the purpose is one this instance signs (`unknown-purpose`; signet's own two purposes are never on this list);
  3. the caller's account, read from the kernel (SO_PEERCRED, which the caller cannot set), is allowed for that
     purpose (`not-allowed`);
  4. the bytes start with that purpose's label (`wrong-label`), so a key never signs bytes meant for another purpose;
  4a. for a purpose with an approval rule (`signet.approval`), at least its quorum of distinct listed approvers signed
     these exact bytes and the summary digest sent with them (`not-approved`); a purpose without a rule takes no
     approvals (`malformed`);
  5. the bytes are signed with that purpose's key, the signature is written to the log and synced (`log-failed` if
     not), and only then is the signature sent back.

Requests run in parallel threads; the log serialises its own writes. One connection carries one request and is closed
after `request_timeout_ms` if the request has not arrived.

FLOOD LIMITS (the config's optional `max_connections`, `refusal_budget`, `min_free_bytes`). Any account on the machine
may connect, so any account could otherwise hold a thread per connection or fill the disk with refusal lines:

  - at most `max_connections` connections are served at once; one more is answered `busy` at once, by the listening
    thread, and closed, so no thread is made for it;
  - each account may have `per_account` refusals written one by one per `window_ms`; further refusals in that window
    are still refused and answered, but only counted, and written as one `suppressed` summary line per account when
    the window ends (or when signet stops);
  - when the log's disk has less than `min_free_bytes` free, refusals are only counted, the same way.

A signature is never suppressed: it is written and synced before it is released, whatever the limits say.

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
import shutil
import threading
import time
from typing import Any, Dict, Tuple

from . import keys as key_store
from .config import Config
from .log import LogError, SignatureLog
from .approval import counted
from .protocol import MAX_APPROVAL_LEN, MAX_APPROVALS, VERSION, FrameError, read_frame, write_frame
from .strict import FormatError, canonical, loads
from .verify import CHECKPOINT_SCHEMA, checkpoint_signing_input


class StartError(Exception):
    """signet will not start, and why."""


class RefusalBudget:
    """How many refusals each account may have written one by one per window, and the count of the rest."""

    def __init__(self, per_account: int, window_ms: int, clock=time.monotonic) -> None:
        self.per_account, self.window = per_account, window_ms / 1000
        self.clock = clock
        self._lock = threading.Lock()
        self._windows: Dict[int, list] = {}  # uid -> [window start, written, suppressed]

    def allow(self, uid: int) -> bool:
        """True if this refusal may be written; False means it was counted instead."""
        with self._lock:
            now = self.clock()
            w = self._windows.get(uid)
            if w is None or now - w[0] >= self.window:
                if w is not None and w[2]:
                    return self._count(uid)  # the old window's count is flushed before a new one starts
                self._windows[uid] = [now, 1, 0]
                return True
            if w[1] < self.per_account:
                w[1] += 1
                return True
            w[2] += 1
            return False

    def _count(self, uid: int) -> bool:
        self._windows[uid][2] += 1
        return False

    def count(self, uid: int) -> None:
        """Count a refusal that is not written for another reason (the disk floor)."""
        with self._lock:
            w = self._windows.setdefault(uid, [self.clock(), 0, 0])
            w[2] += 1

    def due(self, *, everything: bool = False) -> Dict[int, int]:
        """{uid: suppressed} for windows that have ended (or all of them), each taken once."""
        with self._lock:
            now, out = self.clock(), {}
            for uid, w in list(self._windows.items()):
                if w[2] and (everything or now - w[0] >= self.window):
                    out[uid] = w[2]
                    del self._windows[uid]
            return out


class Signer:
    """The decision for one request, without the socket, so it can be tested on its own."""

    def __init__(self, config: Config, log: SignatureLog) -> None:
        self.config = config
        self.log = log
        self.keys = {p.name: (p.key_id, key_store.load(config.keys_dir, p.key_id)) for p in config.purposes.values()}
        self.budget = RefusalBudget(config.refusal_per_account, config.refusal_window_ms)
        self._log_dir = os.path.dirname(os.path.abspath(config.log))

    def _disk_low(self) -> bool:
        if not self.config.min_free_bytes:
            return False
        try:
            return shutil.disk_usage(self._log_dir).free < self.config.min_free_bytes
        except OSError:
            return True

    def _refuse(self, code: str, reason: str, *, purpose: str, uid: int, pid: int, data: bytes) -> Dict[str, Any]:
        answer = {"v": VERSION, "ok": False, "code": code, "reason": reason}
        if self._disk_low():
            self.budget.count(uid)
            answer["_quiet"] = True
            return answer
        if not self.budget.allow(uid):
            answer["_quiet"] = True
            return answer
        try:
            self.log.append(outcome="refused", code=code, purpose=purpose, key_id="", uid=uid, pid=pid, data=data,
                            signature=b"")
        except LogError:
            pass  # the request is refused either way; the refusal is also printed by the handler
        return answer

    def flush_suppressed(self, *, everything: bool = False) -> int:
        """Write one `suppressed` summary line per account whose window ended. Returns how many lines."""
        lines = 0
        for uid, count in sorted(self.budget.due(everything=everything).items()):
            try:
                self.log.append(outcome="refused", code="suppressed", purpose="", key_id="", uid=uid, pid=0, data=b"",
                                signature=b"", suppressed=count)
                lines += 1
            except LogError:
                pass  # the disk is still full; the count is lost, and the stop line on stderr names it
        return lines

    def handle(self, raw: bytes, uid: int, pid: int) -> Dict[str, Any]:
        try:
            request = loads(raw, max_depth=2)
        except FormatError as exc:
            return self._refuse("malformed", str(exc), purpose="", uid=uid, pid=pid, data=raw)
        keys = set(request)
        if keys not in ({"v", "purpose", "data"}, {"v", "purpose", "data", "approvals", "summary_sha256"}) \
                or request["v"] != VERSION or type(request["purpose"]) is not str or type(request["data"]) is not str:
            return self._refuse("malformed", "a request has exactly v (1), purpose and data (hex), and optionally "
                                "approvals with summary_sha256", purpose="", uid=uid, pid=pid, data=raw)
        approvals = request.get("approvals")
        summary = request.get("summary_sha256")
        if approvals is not None and (
                type(approvals) is not list or len(approvals) > MAX_APPROVALS
                or any(type(a) is not str or len(a) > MAX_APPROVAL_LEN for a in approvals)
                or type(summary) is not str or len(summary) != 64 or any(c not in "0123456789abcdef" for c in summary)):
            return self._refuse("malformed", f"approvals is a list of at most {MAX_APPROVALS} strings and "
                                "summary_sha256 is 64 lowercase hex", purpose="", uid=uid, pid=pid, data=raw)
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
        approvers: list = []
        if purpose.approval is None and approvals is not None:
            return self._refuse("malformed", f"{purpose.name!r} has no approval rule and takes no approvals",
                                purpose=purpose.name, uid=uid, pid=pid, data=data)
        if purpose.approval is not None:
            if approvals is None:
                return self._refuse("not-approved", f"{purpose.name!r} is signed only with approvals",
                                    purpose=purpose.name, uid=uid, pid=pid, data=data)
            approvers = counted(purpose.approval, data, bytes.fromhex(summary), approvals,
                                now_ms=int(time.time() * 1000))
            if len(approvers) < purpose.approval.quorum:
                return self._refuse("not-approved", f"{len(approvers)} listed approver(s) signed these bytes; "
                                    f"{purpose.name!r} needs {purpose.approval.quorum}",
                                    purpose=purpose.name, uid=uid, pid=pid, data=data)
        key_id, key = self.keys[purpose.name]
        signature = key_id.encode("ascii") + b":" + key.sign(data)
        try:
            seq = self.log.append(outcome="signed", code="", purpose=purpose.name, key_id=key_id, uid=uid, pid=pid,
                                  data=data, signature=signature, approvers=approvers)
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
    seal = None
    if config.rotate_bytes:
        try:
            log_key = key_store.load(config.keys_dir, config.log_key_id)
        except key_store.KeyStoreError as exc:
            raise StartError(str(exc)) from None

        def seal(length: int, head: str) -> bytes:
            """A segment's seal: a schema 1 checkpoint signed with the log key, checkable by `signet check-checkpoint`."""
            signature = config.log_key_id.encode("ascii") + b":" + log_key.sign(checkpoint_signing_input(length, head))
            return canonical({"schema": CHECKPOINT_SCHEMA, "length": length, "head": head,
                              "signature": signature.hex()}) + b"\n"
    try:
        log = SignatureLog(config.log, rotate_bytes=config.rotate_bytes, seal=seal)
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
            quiet = answer.pop("_quiet", False)
            if not answer["ok"] and not quiet:
                try:
                    print(f"signet: refused uid {uid} pid {pid}: {answer['code']}: {answer['reason']}",
                          file=sys.stderr, flush=True)
                except OSError:
                    pass  # stderr is gone (its reader exited); the refusal is in the log, and the caller still hears it
            try:
                write_frame(sock, answer)
            except OSError:
                pass  # the caller left; a signature it did not receive is still in the log

    slots = threading.BoundedSemaphore(config.max_connections)
    busy = {"count": 0}

    class Server(socketserver.ThreadingUnixStreamServer):
        daemon_threads = True
        request_queue_size = 128  # the default of 5 refused callers in a burst (found by the 32-caller test)

        def process_request(self, request: Any, client_address: Any) -> None:
            if not slots.acquire(blocking=False):
                busy["count"] += 1
                try:
                    uid, _pid = peer(request)
                except OSError:
                    uid = -1
                try:
                    request.settimeout(0.05)
                    write_frame(request, {"v": VERSION, "ok": False, "code": "busy",
                                          "reason": f"signet is serving its most connections ({config.max_connections}); "
                                                    "try again"})
                except OSError:
                    pass
                self.shutdown_request(request)
                if uid >= 0:
                    signer.budget.count(uid)
                return
            super().process_request(request, client_address)

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            try:
                super().process_request_thread(request, client_address)
            finally:
                slots.release()

    old = os.umask(0o111)
    try:
        server = Server(str(config.socket), Handler)
    finally:
        os.umask(old)
    # Anyone on the machine may connect; who may get a signature is decided per purpose from the kernel's account.
    os.chmod(config.socket, 0o666)
    server.signer = signer  # type: ignore[attr-defined]
    return server, log


def shared_account_purposes(config: Config, euid: int) -> list:
    """Purposes whose callers include the account signet itself runs as.

    A caller in that account can open the key files directly, so the separate signer protects nothing for it.
    """
    return [name for name, purpose in config.purposes.items() if euid in purpose.allowed_uids]


def serve(config: Config) -> int:
    server, log = build(config)
    stop = threading.Event()

    def on_signal(_signum: int, _frame: Any) -> None:
        if not stop.is_set():
            stop.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    signer: Signer = server.signer  # type: ignore[attr-defined]

    def flusher() -> None:
        while not stop.wait(min(config.refusal_window_ms / 1000, 5.0)):
            signer.flush_suppressed()

    threading.Thread(target=flusher, daemon=True).start()
    length, _head = log.state()
    print(f"signet: serving {len(config.purposes)} purpose(s) on {config.socket}; log {config.log} at {length} "
          "entries", file=sys.stderr, flush=True)
    # After the serving line, so a supervisor that waits for that line still sees it first.
    for name in shared_account_purposes(config, os.geteuid()):
        print(f"signet: WARNING purpose {name!r} allows uid {os.geteuid()}, the account signet runs as; a caller there "
              "can read the private keys directly, so the separation protects nothing. Run signet under its own "
              "account or container (see README, Running it)", file=sys.stderr, flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        signer.flush_suppressed(everything=True)
        try:
            os.unlink(config.socket)
        except FileNotFoundError:
            pass
        log.close()
    return 0
