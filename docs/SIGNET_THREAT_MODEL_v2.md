# SIGNET threat model, v2

Date: 2026-11-27. v1 (`SIGNET_THREAT_MODEL_v1.md`) is the initial assessment this run was planned from; v2 gives each
finding's status after Steps 2 to 7. Attackers A1 to A6 are defined in v1.

| # | Finding | Status | Held by |
|---|---|---|---|
| T1 | No independent anchor in operation | 🟡 Witness built and proven against real Rekor (drill, 5 of 5 attacks); production run starts on merge, needs `SIGNET_ROOT_KEY` and real checkpoints | `witness-drill.yml`, `witness.yml`, `test_witness.py` |
| T2 | Checkpoints not chained or timed | 🟢 Schema 2: `at_ms`, `previous`; no downgrade, no time going back | `test_anchor_chain.py` |
| T3 | Suppressed publishing invisible | 🟢 `check --max-unanchored / --max-age-ms`; missing witness named | `test_stalled_publishing_is_named`, witness tests |
| T4 | Fork, resurrection, jumps accepted by checkers | 🟢 for checkers using `signet.trust`; 🔴 until CNS and HUMANITY use it | `test_trust.py` |
| T5 | Anchor did not check revocation monotonicity | 🟢 | `test_an_anchored_registry_cannot_bring_a_revoked_key_back` |
| T6 | HUMANITY kernel bypasses the registry | 🔴 Identified, needs the owner's approval (`SIGNET_INTEGRATION_MATRIX_v1.md`) | none |
| T7 | Root rotation is a hand re-pin | 🔴 Unchanged, documented | runbook tests |
| T8 | Keys are files in Python memory | 🔴 Unchanged; no seam added without a device to test against | none |
| T9 | Key generation races | 🟢 (O_EXCL, unchanged) | key tests |
| T10 | Approvals never expire | 🔴 Recorded gap | `test_baseline_gaps.py` |
| T11 | Approver removal needs a restart | 🟡 Unchanged, documented | existing test |
| T12 | Summary honesty | 🔴 Residual by design | README threat 21 |
| T13 | Refusal flooding fills the disk | 🟢 Budget, summary lines, disk floor | `test_flood.py` |
| T14 | No log rotation | 🔴 Open | none |
| T15 | `at_ms` is signet's clock | 🟢 for witnessed checkpoints (Rekor's time is checked against it) | witness tests |
| T16 | One thread per connection | 🟢 Cap, `busy` | `test_flood.py` |
| T17 | No deployment recipe | 🟢 `deploy/signet.service`, run under systemd in CI | CI `separate accounts` |
| T18 | No monitoring | 🟡 `signet status`; alert wiring is the operator's | `test_status_reports_health_for_monitoring` |
| T19 | Every real run one account | 🟢 in CI (three accounts, six claims); 🔴 in any real deployment | `tools/two_accounts.py` |
| T20 | One verifier implementation | 🟢 `rust/signet-verify`, vectors, differential | CI `independent verifier` |

## New findings from this run

| # | Finding | Status |
|---|---|---|
| T21 | Any local account can hold every connection slot so others get `busy` | 🔴 Open (availability; fails closed). Fix: a per-account share of the slots |
| T22 | An allowed caller can sign without a rate limit, growing the log | 🔴 Open. Fix: a per-purpose signing rate |
| T23 | The owner can witness a forked chain | 🟡 Permanently visible in Rekor; found only if an outside party keeps copies |
| T24 | Suppressed-refusal counts are lost on SIGKILL | 🟡 Accepted: no signature is involved |
| T25 | Ed25519 edge-case agreement between OpenSSL and dalek untested | 🟡 The Rust side is the stricter one, so a disagreement refuses |
| T26 | Anchor branch protection claimed in its README, not visible in GitHub's rules API | UNKNOWN, owner to check |
