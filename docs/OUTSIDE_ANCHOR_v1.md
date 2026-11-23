# The outside anchor (v1)

Status, 2026-11-23: the mechanism is built here (`signet_anchor/`, 13 tests in `tests/test_anchor.py`). The protected
repository it is meant to live in does **not** exist yet, by the owner's decision. Until it does, an anchor directory
shows the mechanism and protects nothing by itself, because whoever controls signet's side can also rewrite it.

## Why an anchor

signet's log is hash-chained, so an edited, removed or reordered line shows. A rewrite of the whole file does not:
whoever controls signet's account can write a new chain that is consistent on its own. A **checkpoint** is a small
signed note: "the log was N entries long and ended with this fingerprint." Kept somewhere signet's side cannot touch,
it exposes any later log that does not match it. The same place keeps every published **registry**, so it also
remembers the newest registry version, which a checker otherwise has to remember for itself.

## What "protected" means

A repository where history can only be added to: nobody can rewrite it, delete it, or force-push over it, not even
the account whose job is to write to it.

On GitHub that takes three things:

1. **Rules on the main branch** (branch protection or a ruleset): block force pushes, block deleting the branch, and
   do not let administrators bypass them.
2. **A writer that is not an admin.** The account or token that publishes checkpoints can add commits and cannot turn
   the rules off.
3. **Someone other than the writer controls the rules.** A second account or person, or an organization in which the
   writer is not an owner.

**The catch:** if one account owns both signet and the anchor repository, that account can switch the rules off.
Rules alone stop mistakes and a stolen limited token; they do not stop someone who takes over that account. That is
why point 3 matters.

## How strong each setup is

| Setup | Stops | Does not stop |
|---|---|---|
| 🟡 One account, rules on | Mistakes, a stolen write-only token | Someone who takes over that account |
| 🟢 Organization owned by a second account, the writer has write access only | The above, plus the writer's account being taken over | Both accounts taken over |
| 🥇 Either of the above, plus outside copies (a public repository others mirror, or a public timestamp service) | Nearly everything short of rewriting every copy at once | Little that matters at this scale |

**Recommendation:** the 🟢 row. A free GitHub organization owned by a second account, the anchor repository inside
it, and the publishing account with write access only.

## What is built (`signet_anchor/`)

An anchor is a directory that only grows:

```text
<anchor>/registries/000003.json    one file per registry version, named by its version
<anchor>/checkpoints/000001.json   one file per checkpoint, numbered in publish order
```

| Command | What it does | What it refuses |
|---|---|---|
| `python -m signet_anchor publish-registry` | adds a registry | one under another root key, or not newer than the newest anchored |
| `python -m signet_anchor publish-checkpoint` | adds a checkpoint | one not signed by a log key the newest registry trusts, one covering no more than what is anchored, one that does not match the live log, or any when the log already fails the check |
| `python -m signet_anchor check` | checks the live log against everything anchored | names each problem: **rewritten** (the log's entry at a checkpoint is another one), **lost** (the log is shorter than a checkpoint), **forked** (two checkpoints, one length, two heads), **went backwards** (a later checkpoint covers less) |

No file is ever replaced. Each check is tested against a real signet (`tests/test_anchor.py`); the whole-rewrite case
is the one `tests/test_keys_and_log.py::test_a_rewritten_chain_is_not_found_by_the_log_alone` shows the log alone
cannot catch.

What it does not do: decide when to publish (an operator or a scheduled job runs the commands), push to a repository
(that is a `git commit` and `git push` of the anchor directory), or protect anything while the directory sits where
signet's operator can rewrite it.

## Moving it to the new repository

`signet_anchor` imports only signet's caller-side modules (`signet.registry`, `signet.verify`, `signet.strict`) and
the read-only log check (`signet.log.verify_file`). It never imports signet's key store, server or config, and nothing
in `signet` imports it. Both are held by tests. To move it:

1. Copy `signet_anchor/`, `tests/test_anchor.py`, `tests/instance.py` (the test helper it uses) and this file into the
   new repository. Add `signet` (this repository, pinned to a commit) as its dependency.
2. In this repository, delete `signet_anchor/` and `tests/test_anchor.py`, remove `"signet_anchor", "signet_anchor.*"`
   from `[tool.setuptools.packages.find]` in `pyproject.toml`, and point the README's anchor lines at the new home.
3. Run both test suites. Nothing in signet should change behaviour; if a signet test fails, something depended on the
   anchor that should not have.

To remove it without moving: step 2 alone.

## Setting up the protected repository (when the owner decides to)

1. Create a second GitHub account (or use a trusted second person's), and with it a free organization.
2. In the organization, create the anchor repository. Public, if outside copies are wanted.
3. Add a ruleset on `main`: block force pushes, block deletion, no bypass for anyone.
4. Invite the publishing account with **write** access only (not maintain, not admin).
5. Clone it where the publishing job runs, and use that working copy as `--anchor`. After each publish, commit and
   push.
6. Test the protection once: as the publishing account, try a force push and a branch deletion. Both must be refused.
7. Then: CNS's CI runs `python -m signet_anchor check` against the anchor and fails on lost or forked history
   (phase 3's second half, not built).
