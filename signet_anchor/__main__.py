"""python -m signet_anchor: publish to the outside anchor, and check the live log against it.

    publish-registry   --anchor DIR --root-key HEX --registry FILE
    publish-checkpoint --anchor DIR --root-key HEX --checkpoint FILE --log FILE
    check              --anchor DIR --root-key HEX --log FILE

Exit 0: done or holds. 1: refused, or a problem found (each named on stderr). 2: the command was wrong.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from .anchor import AnchorError, check, latest_registry, publish_checkpoint, publish_registry


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="signet_anchor")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("publish-registry", "publish-checkpoint", "check"):
        p = sub.add_parser(name)
        p.add_argument("--anchor", required=True, type=Path)
        p.add_argument("--root-key", required=True)
        if name == "publish-registry":
            p.add_argument("--registry", required=True, type=Path)
        if name == "publish-checkpoint":
            p.add_argument("--checkpoint", required=True, type=Path)
        if name != "publish-registry":
            p.add_argument("--log", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "publish-registry":
            print(f"signet_anchor: published {publish_registry(args.anchor, args.registry.read_bytes(), args.root_key)}")
        elif args.command == "publish-checkpoint":
            path = publish_checkpoint(args.anchor, args.checkpoint.read_bytes(), args.log, args.root_key)
            print(f"signet_anchor: published {path}")
        else:
            problems = check(args.anchor, args.log, args.root_key)
            for problem in problems:
                print(f"signet_anchor: {problem}", file=sys.stderr)
            if problems:
                return 1
            print(f"signet_anchor: the log extends everything anchored; newest registry version "
                  f"{latest_registry(args.anchor, args.root_key).version}")
    except (AnchorError, OSError) as exc:
        print(f"signet_anchor: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
