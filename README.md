# signet outside anchor

This branch is the outside anchor for signet (see `docs/OUTSIDE_ANCHOR_v1.md` on main). It holds published
registries in `registries/` and signed log checkpoints in `checkpoints/`, numbered `000001.json`, `000002.json`, and
so on. Files are only ever added.

Protection: a ruleset on this branch blocks force pushes and deletion, with no bypass. This is the one-account setup
(🟡): it stops a stolen publishing token from rewriting history, not a takeover of the owning account.

Publish with a fine-grained token limited to this repository, with contents write only and no admin rights.
