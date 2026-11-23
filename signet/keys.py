"""keys: where signet's private keys live on disk, and the checks before one is used.

A key is one file, `<keys_dir>/<key_id>.key`, holding the line `signet-key/1` and then the 32-byte Ed25519 seed in
hex. Only signet's own account should ever read it. signet does not trust the operator to have set that up, so it
REFUSES (`KeyStoreError`, naming the file and the reason) to read a key unless:

  - the directory is a real directory (not a symbolic link), owned by the account signet runs as, with no access for
    group or others (mode 0700 or stricter);
  - the key file is a regular file (not a link), owned by that account, with no access for group or others (0600 or
    stricter), and exactly the format above.

`generate` writes a new key with those permissions and never overwrites an existing file (it opens with O_EXCL), so a
second `keygen` with the same id is an error, not a silent replacement of a key whose signatures are already out.

WHAT THIS DOES NOT DO. A file the operating system protects is readable by root and by anyone who takes over signet's
account. Holding the key in a device that cannot export it (a hardware key, a TPM, a cloud KMS) is the next step and
is not here; see README, "Limits".
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .names import check_name
from .registry import public_key_hex

HEADER = "signet-key/1"


class KeyStoreError(Exception):
    """A key that will not be read or written, with the reason."""


def _check_private(path: Path, *, want_dir: bool) -> None:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise KeyStoreError(f"{path} does not exist") from None
    kind_ok = stat.S_ISDIR(info.st_mode) if want_dir else stat.S_ISREG(info.st_mode)
    if not kind_ok:
        raise KeyStoreError(f"{path} is not a {'directory' if want_dir else 'regular file'} (a link is refused)")
    if info.st_uid != os.geteuid():
        raise KeyStoreError(f"{path} is owned by uid {info.st_uid}, not by uid {os.geteuid()} that signet runs as")
    if info.st_mode & 0o077:
        raise KeyStoreError(f"{path} has mode {stat.S_IMODE(info.st_mode):o}; group and others must have no access")


def key_path(keys_dir: Path, key_id: str) -> Path:
    return Path(keys_dir) / f"{check_name('key id', key_id)}.key"


def generate(keys_dir: Path, key_id: str) -> str:
    """Write a new key and return its public key (64 hex). Refuses if the file exists or the directory is not private."""
    _check_private(Path(keys_dir), want_dir=True)
    path = key_path(keys_dir, key_id)
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        raise KeyStoreError(f"{path} already exists; a key id names one key forever, choose a new id") from None
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(f"{HEADER}\n{seed.hex()}\n")
        handle.flush()
        os.fsync(handle.fileno())
    return public_key_hex(key)


def load(keys_dir: Path, key_id: str) -> Ed25519PrivateKey:
    """The private key for `key_id`, after every check in the module docstring, or `KeyStoreError`."""
    _check_private(Path(keys_dir), want_dir=True)
    path = key_path(keys_dir, key_id)
    _check_private(path, want_dir=False)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "r", encoding="ascii") as handle:
        try:
            text = handle.read(200)
        except UnicodeDecodeError:
            raise KeyStoreError(f"{path} is not a signet key file") from None
    lines = text.split("\n")
    if len(lines) != 3 or lines[0] != HEADER or lines[2] != "" or len(lines[1]) != 64:
        raise KeyStoreError(f"{path} is not a signet key file ({HEADER}, then 64 hex characters)")
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(lines[1]))
    except ValueError:
        raise KeyStoreError(f"{path} does not hold a valid Ed25519 seed") from None
