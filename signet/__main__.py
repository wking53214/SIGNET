"""The signet command. Exit 0: done. Exit 1: a check that failed (a log, a registry or a checkpoint that does not
verify). Exit 2: signet would not do it (bad arguments, a config or key it refuses, a file it will not overwrite).

    signet keygen --keys-dir DIR KEY_ID          write a new private key, print its public key
    signet serve --config FILE                   run the signer
    signet registry --config FILE --out FILE [--previous FILE --root-key HEX] [--revoke KEY_ID ...]
                                                 write the next signed registry from the config's current keys
    signet checkpoint --config FILE --out FILE   sign the log's current length and head with the log key
    signet verify-log --log FILE                 check the whole log chain, print its length and head
    signet check-checkpoint --registry FILE --root-key HEX --checkpoint FILE [--min-version N]
                                                 check a checkpoint against a registry and the pinned root key

`registry`, `checkpoint` and `keygen` read private keys, so they run as signet's own account, like `serve`. Every file
signet writes is written whole (a temporary file, synced, then renamed) and an existing output is never replaced.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import config as config_mod
from . import keys as key_store
from .log import LogError, verify_file
from .names import CHECKPOINT_LABEL, LOG_PURPOSE, REGISTRY_LABEL, REGISTRY_PURPOSE
from .registry import RegistryError, load_registry, next_body, public_key_hex, sign_registry
from .strict import canonical
from .verify import CHECKPOINT_SCHEMA, check_checkpoint, checkpoint_signing_input


class Refusal(Exception):
    pass


def _write_new(path: Path, text: str) -> None:
    if path.exists() or path.is_symlink():
        raise Refusal(f"{path} already exists; signet does not replace an output")
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(tmp, path)  # fails if path appeared meanwhile, so nothing is ever replaced
    except FileExistsError:
        raise Refusal(f"{path} already exists; signet does not replace an output") from None
    finally:
        os.unlink(tmp)


def _registry(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    root = key_store.load(cfg.keys_dir, cfg.registry_key_id)
    log_key = key_store.load(cfg.keys_dir, cfg.log_key_id)
    previous = None
    if args.previous:
        if not args.root_key:
            raise Refusal("--previous needs --root-key, the pinned root public key it is checked against")
        previous = load_registry(Path(args.previous).read_bytes(), args.root_key)
    current = {REGISTRY_PURPOSE: (cfg.registry_key_id, public_key_hex(root)),
               LOG_PURPOSE: (cfg.log_key_id, public_key_hex(log_key))}
    labels = {REGISTRY_PURPOSE: REGISTRY_LABEL, LOG_PURPOSE: CHECKPOINT_LABEL}
    for p in cfg.purposes.values():
        current[p.name] = (p.key_id, public_key_hex(key_store.load(cfg.keys_dir, p.key_id)))
        labels[p.name] = p.label
    body = next_body(previous, labels, current, revoke=args.revoke or [])
    _write_new(Path(args.out), sign_registry(body, root, cfg.registry_key_id))
    print(f"signet: registry version {body['version']} written to {args.out}; root public key {public_key_hex(root)}")
    return 0


def _checkpoint(args: argparse.Namespace) -> int:
    cfg = config_mod.load(args.config)
    key = key_store.load(cfg.keys_dir, cfg.log_key_id)
    length, head = verify_file(cfg.log)
    signature = cfg.log_key_id.encode("ascii") + b":" + key.sign(checkpoint_signing_input(length, head))
    doc = {"schema": CHECKPOINT_SCHEMA, "length": length, "head": head, "signature": signature.hex()}
    _write_new(Path(args.out), canonical(doc).decode("ascii") + "\n")
    print(f"signet: checkpoint of {length} entries, head {head}, written to {args.out}")
    return 0


def _check_checkpoint(args: argparse.Namespace) -> int:
    registry = load_registry(Path(args.registry).read_bytes(), args.root_key, min_version=args.min_version)
    try:
        length, head = check_checkpoint(Path(args.checkpoint).read_bytes(), registry)
    except ValueError as exc:
        print(f"signet: {exc}", file=sys.stderr)
        return 1
    print(f"signet: checkpoint verifies: {length} entries, head {head}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="signet", description="The keyholder: a separate signer program.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("keygen")
    p.add_argument("--keys-dir", required=True, type=Path)
    p.add_argument("key_id")
    p = sub.add_parser("serve")
    p.add_argument("--config", required=True, type=Path)
    p = sub.add_parser("registry")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--out", required=True)
    p.add_argument("--previous")
    p.add_argument("--root-key")
    p.add_argument("--revoke", action="append")
    p = sub.add_parser("checkpoint")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--out", required=True)
    p = sub.add_parser("verify-log")
    p.add_argument("--log", required=True, type=Path)
    p = sub.add_parser("check-checkpoint")
    p.add_argument("--registry", required=True)
    p.add_argument("--root-key", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--min-version", type=int, default=1)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            print(key_store.generate(args.keys_dir, args.key_id))
            return 0
        if args.command == "serve":
            from .server import StartError, serve
            try:
                return serve(config_mod.load(args.config))
            except StartError as exc:
                raise Refusal(str(exc)) from None
        if args.command == "registry":
            return _registry(args)
        if args.command == "checkpoint":
            return _checkpoint(args)
        if args.command == "verify-log":
            try:
                length, head = verify_file(args.log)
            except LogError as exc:
                print(f"signet: {exc}", file=sys.stderr)
                return 1
            print(f"signet: log verifies: {length} entries, head {head}")
            return 0
        if args.command == "check-checkpoint":
            try:
                return _check_checkpoint(args)
            except RegistryError as exc:
                print(f"signet: {exc}", file=sys.stderr)
                return 1
    except (Refusal, config_mod.ConfigError, key_store.KeyStoreError, RegistryError, LogError, ValueError,
            OSError) as exc:
        print(f"signet: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
