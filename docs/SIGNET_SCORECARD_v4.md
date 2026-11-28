# SIGNET scorecard, v4 (RACE 9.7, Step 13)

Date: 2026-11-27. Branch `signet/race-9.6` from `cd70204` (main after PR #8), with HUMANITY main after PR #20
and branch `humanity/kernel-trust-gap`. Scored on demonstrated properties only. v1 is the RACE 9.5 result. v4 adds Step 13 (approval expiry) to v3. v3 corrected v2, which scored 8.6: v2
scored revocation as reaching HUMANITY's kernel, but the kernel takes any trust set its host gives it, so the check
binds only the issuer's signer (now an asserted gap in HUMANITY).

## Result

**Baseline 7.2. RACE 9.5: 8.4. RACE 9.6: 8.5. Now 8.6 (8.56).** Not 9.5. What separates 8.6 from 9.5 is listed under "Production blockers" below, and
none of it is a matter of more tests or more documentation.

| Dimension | Baseline | 9.5 | Now | Evidence for the current score |
|---|---|---|---|---|
| Architecture | 9.0 | 9.3 | 9.3 | Checker memory, witness and second verifier added as separate modules; boundary rule held by tests for the new caller-side module |
| Cryptographic correctness | 8.5 | 9.2 | 9.2 | Two independent implementations agree on 45 vectors and 3,000 generated canonical encodings; chained checkpoints. No Ed25519 edge-case vectors yet |
| Key custody | 6.0 | 6.0 | 6.0 | Unchanged: keys are files read into Python memory. No hardware provider |
| Identity enforcement | 8.0 | 9.0 | 9.0 | Three real Linux accounts in CI, six claims held, including "the caller cannot read the keys"; systemd unit proven |
| Purpose isolation | 9.5 | 9.5 | 9.5 | Unchanged, re-held by vectors in a second implementation |
| Registry integrity | 6.5 | 9.0 | 9.2 | `signet.trust` refuses rollback, forks, resurrection and (optionally) jumps; a second implementation in `rust/signet-verify` gives the same answer and state bytes on every step of signet's own sequences, and the two read each other's memory file. One consumer (HUMANITY) uses it |
| Revocation | 6.5 | 8.0 | 8.2 | HUMANITY's issuer takes its slip key from the registry at start, and a kernel built from that check stops trusting it after a window, shown against the real kernel. Not enforced on the kernel: a hand-built trust set keeps a revoked key (asserted). Not at once: up to one window (asserted) |
| Approval integrity | 8.0 | 8.0 | 8.4 | A rule may set `max_age_ms`: approvals carry a signed time and stop counting once stale, shown against a running signet from Python and from the Rust client. Not yet used by HUMANITY; rules without it never expire; approver removal needs a restart |
| Audit integrity | 7.5 | 8.8 | 8.8 | Refusal floods bounded with summary lines, disk floor, chained checkpoints. No log rotation |
| External anchoring | 2.5 | 8.0 | 8.0 | Real Rekor witness: 6 entries made by 2 CI runs, 5 of 5 attacks caught each run. Production witness merged to main and scheduled; not confirmed running (needs the root-key variable and a first real checkpoint); the signing identity is in the owner's own repository |
| Failure handling | 8.5 | 9.0 | 9.0 | `busy`, suppressed counts, missing trust memory stops the checker, missing `sigstore` fails closed |
| Independent verification | 5.0 | 9.0 | 9.2 | `rust/signet-verify`: another language, JSON reader and Ed25519 library, CLI for outside reviewers, in CI; now also the trust memory |
| Integration | 6.0 | 6.0 | 7.0 | HUMANITY on the registry and the trust memory (merged, HUMANITY PR #20). CNS not yet on the trust memory; HERALD absent |
| Testing | 8.5 | 9.3 | 9.4 | 249 Python, 20 Rust here (3 new trust tests, differential against signet's Python, approval rules included); 16 new HUMANITY tests, two mutations of the check each caught; no skips |
| Operational readiness | 4.5 | 7.5 | 7.5 | `signet status`, hardened systemd unit proven under systemd, separate-account CI. No rotation, no alert wiring, no deployed instance |
| Documentation | 9.0 | 9.2 | 9.2 | Evidence-tagged deliverables; README updated |
| Maintainability | 8.5 | 8.7 | 8.7 | Additive changes, one runtime dependency still; two new dev-only dependencies (hypothesis; sigstore in CI only) |
| **Mean** | **7.2** | **8.4** | **8.6** | 8.56 exactly |

## Production blockers (must close before calling SIGNET production-grade trust infrastructure)

1. 🔴 **Keys are files.** No non-exporting device. The mission's own rule: do not claim hardware security when only an
   interface exists, so none is claimed.
2. 🟠 **CNS does not use the new checker memory.** HUMANITY now does, through `rust/signet-verify` (merged,
   HUMANITY PR #20). CNS's `signet_live` still needs `signet.trust`, with the owner's approval.
3. 🔴 **HUMANITY's kernel takes any trust set its host gives it.** The startup check binds the issuer's signer, not the
   kernel; a hand-built trust set keeps trusting a key SIGNET revoked (asserted in HUMANITY). No production host exists
   yet. Closing it is a stack-kernel change: refuse anchors with no end or a window past the limit, or check every slip
   against the registry.
4. 🟡 **Revocation reaches a correctly built kernel only within a window** (default 1 hour), and a host handed a frozen
   registry copy is not told (both asserted as gaps in HUMANITY). No restart loop exists, so a host that is not
   restarted within the window refuses every slip. Closing it fully is the stack-kernel design: every slip checked
   against the registry, with a staleness limit.
5. 🔴 **The production witness is not confirmed running.** Merged to main (PR #8, 2026-11-27); scheduled hourly. Still
   needs: the `SIGNET_ROOT_KEY` repository variable (not readable from this session), a real signet publishing checkpoints to the `anchor` branch, and the anchor branch's protection confirmed
   (the rules API lists none today).
6. 🔴 **No real deployment.** The only owner machine is a one-account Chromebook container; the separation is proven
   in CI, not in use.

## Remaining weaknesses (not blockers, needed for 9.5)

- HUMANITY does not set `max_age_ms` yet, and a rule without it never expires (asserted).
- Approver removal needs a restart.
- No log rotation; start-up reads the whole log.
- Any local account can hold every connection slot (availability).
- An allowed caller can sign without a rate limit.
- No Ed25519 edge-case vectors.
- The owner can witness a forked chain; only outside copies make that conflict found.
- No review yet by a person who did not write the fixes.

## What would make 9.5 defensible

Blockers 1 to 6 closed (a PKCS#11 or TPM key provider tested against a real device, CNS and HUMANITY on the checker
memory and the registry, the witness running from main against real checkpoints, one deployment under separate
accounts), approval expiry, and log rotation. With those, the low dimensions move to about: key custody 8.5,
integration 8.5, approval 9.0, audit 9.3, anchoring 9.0, operations 8.8, which brings the mean to about 9.3, and an
outside review is what would earn the rest.
