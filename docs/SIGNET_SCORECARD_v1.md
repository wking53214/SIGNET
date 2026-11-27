# SIGNET scorecard, v1 (RACE 9.5, final for this run)

Date: 2026-11-27. Branch `signet/race-9.5`, from baseline `213c5a6`. Scored on demonstrated properties only.

## Result

**Baseline 7.2. Final 8.4.** Not 9.5. What separates 8.4 from 9.5 is listed under "Production blockers" below, and
none of it is a matter of more tests or more documentation.

| Dimension | Baseline | Final | Evidence for the final score |
|---|---|---|---|
| Architecture | 9.0 | 9.3 | Checker memory, witness and second verifier added as separate modules; boundary rule held by tests for the new caller-side module |
| Cryptographic correctness | 8.5 | 9.2 | Two independent implementations agree on 45 vectors and 3,000 generated canonical encodings; chained checkpoints. No Ed25519 edge-case vectors yet |
| Key custody | 6.0 | 6.0 | Unchanged: keys are files read into Python memory. No hardware provider |
| Identity enforcement | 8.0 | 9.0 | Three real Linux accounts in CI, six claims held, including "the caller cannot read the keys"; systemd unit proven |
| Purpose isolation | 9.5 | 9.5 | Unchanged, re-held by vectors in a second implementation |
| Registry integrity | 6.5 | 9.0 | `signet.trust` refuses rollback, forks, resurrection and (optionally) jumps, locked and fail closed; property and race tests. No consumer uses it yet |
| Revocation | 6.5 | 8.0 | Revocation is now monotonic for checkers with memory and in the anchor. HUMANITY's kernel still bypasses the registry |
| Approval integrity | 8.0 | 8.0 | Unchanged: no expiry or nonce on approvals; approver removal needs a restart |
| Audit integrity | 7.5 | 8.8 | Refusal floods bounded with summary lines, disk floor, chained checkpoints. No log rotation |
| External anchoring | 2.5 | 8.0 | Real Rekor witness: 6 entries made by 2 CI runs, 5 of 5 attacks caught each run. Production witness workflow not yet running (needs merge, the root-key variable and a first real checkpoint); the signing identity is in the owner's own repository |
| Failure handling | 8.5 | 9.0 | `busy`, suppressed counts, missing trust memory stops the checker, missing `sigstore` fails closed |
| Independent verification | 5.0 | 9.0 | `rust/signet-verify`: another language, JSON reader and Ed25519 library, CLI for outside reviewers, in CI |
| Integration | 6.0 | 6.0 | Unchanged: consumers not yet moved to the trust memory; HUMANITY bypass; HERALD absent |
| Testing | 8.5 | 9.3 | 249 Python (baseline 145), 17 Rust (baseline 12), property, differential, two CI drills against real systems, no skips |
| Operational readiness | 4.5 | 7.5 | `signet status`, hardened systemd unit proven under systemd, separate-account CI. No rotation, no alert wiring, no deployed instance |
| Documentation | 9.0 | 9.2 | Evidence-tagged deliverables; README updated |
| Maintainability | 8.5 | 8.7 | Additive changes, one runtime dependency still; two new dev-only dependencies (hypothesis; sigstore in CI only) |
| **Mean** | **7.2** | **8.4** | |

## Production blockers (must close before calling SIGNET production-grade trust infrastructure)

1. 🔴 **Keys are files.** No non-exporting device. The mission's own rule: do not claim hardware security when only an
   interface exists, so none is claimed.
2. 🔴 **Consumers do not use the new checker memory.** CNS and HUMANITY must load registries through `signet.trust`
   (or an equivalent) for rollback and fork protection to reach them.
3. 🔴 **HUMANITY's kernel trusts a pinned key, not the registry,** so revocation does not reach the thing that runs
   capabilities. A change in HUMANITY, made only with the owner's approval.
4. 🔴 **The production witness is not running yet.** It needs: merge to main, the `SIGNET_ROOT_KEY` repository
   variable, a real signet publishing checkpoints to the `anchor` branch, and the anchor branch's protection confirmed
   (the rules API lists none today).
5. 🔴 **No real deployment.** The only owner machine is a one-account Chromebook container; the separation is proven
   in CI, not in use.

## Remaining weaknesses (not blockers, needed for 9.5)

- Approvals never expire; the same approvals re-sign the same bytes.
- Approver removal needs a restart.
- No log rotation; start-up reads the whole log.
- Any local account can hold every connection slot (availability).
- An allowed caller can sign without a rate limit.
- No Ed25519 edge-case vectors.
- The owner can witness a forked chain; only outside copies make that conflict found.
- No review yet by a person who did not write the fixes.

## What would make 9.5 defensible

Blockers 1 to 5 closed (a PKCS#11 or TPM key provider tested against a real device, CNS and HUMANITY on the checker
memory and the registry, the witness running from main against real checkpoints, one deployment under separate
accounts), approval expiry, and log rotation. With those, the low dimensions move to about: key custody 8.5,
integration 8.5, approval 9.0, audit 9.3, anchoring 9.0, operations 8.8, which brings the mean to about 9.3, and an
outside review is what would earn the rest.
