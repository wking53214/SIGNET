# SIGNET integration matrix, v3

Date: 2026-11-27 (v3: the HUMANITY row after RACE 9.6, corrected). Which ≡TACK components use SIGNET, how, and what has been exercised end to end. Evidence tags as in
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
| HUMANITY issuer | 🟢 | 🟢 `expected_uid` | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 | 🟢 at start, signer side | 🟡 within one window, if the host builds the kernel's trust from the check | 🟡 current key only | HUMANITY `issuer/tests/signet.rs` and `issuer/tests/signet_trust.rs`, real kernel included (EXECUTED, HUMANITY main after PR #20) |
| HERALD | 🔴 | | | | | | | | | | no reference to SIGNET (EXECUTED search) |

HUMANITY, steps 8 to 10: at start the slip key is taken from SIGNET's signed registry through `rust/signet-verify`'s
trust memory (rollback, fork and resurrection refused; a missing memory refuses), and the kernel's trust anchor ends
after a window (default 1 hour). A revocation reaches the kernel by the next check, not at once (asserted as a gap), and only if the host builds the
kernel's trust set from the check: the kernel takes any trust set it is given (asserted as a gap).
Only the current key is trusted, so a slip caught by a rotation is issued again.

Step 7 ("the audit record is independently checkable") is now 🟢 for every row that reaches step 6: the log's
checkpoints can be anchored, witnessed in Rekor and checked by `signet_anchor` and `rust/signet-verify`.

## Changes needed outside SIGNET (identified, not made)

| Repo | Change | Consequence | Why not made here |
|---|---|---|---|
| HUMANITY | Done, merged in HUMANITY PR #20 (decision 5 in HUMANITY's `DECISIONS_v4.md`): the slip key from SIGNET's registry at start, a trust anchor that ends after a window, both pins moved to SIGNET `93bcf31` | Revocation reaches the kernel within one window; a production build with no registry check refuses to start | Approved by the owner 2026-11-27; merged |
| stack-kernel | Production builds refuse trust anchors with no end or a window past a limit; later, stack-authority checks every slip against the whole registry, with a staleness limit and log-based proof for retired keys | The first binds the kernel to the window; the second gives revocation at once and safe retired keys | The long-term design; a third repository; not approved |
| CNS | `signet_live` loads its registries through `signet.trust.TrustStore` and adds a scenario where a replayed or forked registry is refused | Rollback and fork protection proven on the spine | Same; CNS is read-only in this session |
| CNS | CI runs `python -m signet_anchor check` and `check-witness` against the `anchor` branch | The "CNS CI fails on lost or forked history" item from SIGNET's roadmap | Needs the production witness running first |
| HERALD | Sign its export through SIGNET with its own purpose and label | HERALD's export becomes checkable through the registry | HERALD has no signing slot wired today; a design decision first |
