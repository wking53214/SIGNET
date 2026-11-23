"""signet_anchor: the outside anchor for signet's registry and log checkpoints.

WHY IT EXISTS

signet's log is hash-chained, so an edited, removed or reordered line shows. A rewrite of the WHOLE file does not:
whoever controls signet's account can write a new, consistent chain. And a checker refuses an older registry only if
it remembers the newest version it accepted. Both limits close the same way: copies kept somewhere signet's operator
cannot rewrite. That place is the anchor, a directory that only ever grows:

    <anchor>/registries/000003.json    one file per published registry version, named by its version
    <anchor>/checkpoints/000001.json   one file per published log checkpoint, numbered in publish order

A file, once written, is never replaced (the write refuses an existing name). In production the directory is the
working copy of a PROTECTED repository (docs/OUTSIDE_ANCHOR_v1.md says what protected means); until that repository
exists, it is any directory, which shows the mechanism and protects nothing by itself.

WHAT IT CHECKS (`check`)

  - every registry verifies under the pinned root key, its file name is its version, and versions only go up; the
    newest is the one a checker should hold (`latest_registry`), so the anchor is the checker's memory;
  - every checkpoint is signed by a `signet-log` key the newest registry trusts;
  - checkpoints never go backwards, and two with one length name one head (otherwise: a fork);
  - the live log verifies, is at least as long as every checkpoint (otherwise: lost history), and its entry at each
    checkpoint's length is that checkpoint's head (otherwise: rewritten).

`publish_registry` and `publish_checkpoint` run the same checks before they add a file, so the anchor never holds
something the check would refuse.

PORTABLE BY DESIGN

This package imports signet's caller-side modules (`signet.registry`, `signet.verify`, `signet.strict`) and the
read-only log check (`signet.log.verify_file`), never signet's key store, server or config, and nothing in `signet`
imports it. Moving it to its own repository is moving this folder, `tests/test_anchor.py` and the doc; the list is in
docs/OUTSIDE_ANCHOR_v1.md.
"""

from .anchor import AnchorError, check, latest_registry, publish_checkpoint, publish_registry

__all__ = ["AnchorError", "check", "latest_registry", "publish_checkpoint", "publish_registry"]
