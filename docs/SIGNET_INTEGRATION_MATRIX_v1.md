# SIGNET integration matrix, v1

Date: 2026-11-27. Which ≡TACK components use SIGNET, how, and what has been exercised end to end. Evidence tags as in
`SIGNET_BASELINE_v1.md`. CNS stays the interchange layer; nothing here adds a dependency between repositories.

## The ten-step path, per consumer

Steps: 1 asks, 2 identity, 3 purpose, 4 approvals, 5 right key, 6 logged, 7 log independently checkable, 8 checked
against the registry, 9 revocation stops acceptance, 10 history still checks.

| Consumer | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | Exercised where |
|---|---|---|---|---|---|---|---|---|---|---|---|
| zeta (lock results) | 🟢 | 🟢 | 🟢 | n/a | 🟢 | 🟢 | 🟢 | 🟢 via beta | 🟢 | 🟢 | SIGNET `test_interop.py` (EXECUTED), CNS spine scenarios (INSPECTED) |
| beta (checks lock results) | n/a | n/a | n/a | n/a | n/a | n/a | n/a | 🟢 | 🟢 | 🟢 | same |
| delta (receipts) | 🟢 | 🟢 | 🟢 | n/a | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | same |
| delta (its own ledger checkpoints) | 🔴 | | | | | | | | | | delta signs those with its own anchor code, not SIGNET (INSPECTED) |
| CNS spine runner | 🟢 | 🟡 one account | 🟢 | n/a | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | CNS `chains/signet_live.py`, six scenarios (INSPECTED, not run here) |
| HUMANITY issuer | 🟢 | 🟢 `expected_uid` | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🔴 | 🔴 | 🔴 | HUMANITY `issuer/tests/signet.rs` (INSPECTED, not run here) |
| HERALD | 🔴 | | | | | | | | | | no reference to SIGNET (EXECUTED search) |

Step 7 ("the audit record is independently checkable") is now 🟢 for every row that reaches step 6: the log's
checkpoints can be anchored, witnessed in Rekor and checked by `signet_anchor` and `rust/signet-verify`.

## Changes needed outside SIGNET (identified, not made)

| Repo | Change | Consequence | Why not made here |
|---|---|---|---|
| HUMANITY | Kernel checks slips through SIGNET's registry (`signet.verify` in Python, `rust/signet-verify` in Rust) instead of a pinned purpose key; pin only the root | Revoking the issuer's key in SIGNET stops slips at the kernel. Adds a registry file to the kernel's start-up; a production build without one refuses to start (fits decision 4 in HUMANITY's `DECISIONS_v2.md`) | Changes another repository's security contract; needs the owner's approval |
| HUMANITY | Move the `signet-client` pin from `0a83577` to this branch's merge commit | Picks up the `busy` refusal code (today it would read as "unavailable", still fail closed) | Same |
| CNS | `signet_live` loads its registries through `signet.trust.TrustStore` and adds a scenario where a replayed or forked registry is refused | Rollback and fork protection proven on the spine | Same; CNS is read-only in this session |
| CNS | CI runs `python -m signet_anchor check` and `check-witness` against the `anchor` branch | The "CNS CI fails on lost or forked history" item from SIGNET's roadmap | Needs the production witness running first |
| HERALD | Sign its export through SIGNET with its own purpose and label | HERALD's export becomes checkable through the registry | HERALD has no signing slot wired today; a design decision first |
