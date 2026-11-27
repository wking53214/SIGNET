# SIGNET security assessment, v1 (RACE 9.5, Phase Five)

Date: 2026-11-27. Branch `signet/race-9.5` after Step 7. Evidence tags as in `SIGNET_BASELINE_v1.md`.

**Independence, stated plainly.** The three passes below were run one after another by the same investigator who
built the fixes, each from its own attacker's position and without reusing the others' conclusions. That is
separation of viewpoint, not of person. A review by someone who did not write this code is still outstanding and is
listed as a remaining weakness, not claimed.

## Pass A: security reviewer (attacker controls an allowed caller)

| Attempt | Result | Evidence |
|---|---|---|
| Get a signature for another purpose | Refused: label check at signet and again at the checker | tests, vectors (EXECUTED) |
| Get a capability without approvers | Refused below the quorum floor of 2 | approval tests (EXECUTED) |
| Re-send real approvals for the same bytes | **Signed again**, a second log line; same signature bytes (Ed25519 is deterministic) | gap test (EXECUTED). The HUMANITY kernel's one-use store is what stops the second use (INFERRED from its design) |
| Fill the disk with refusals | Bounded: per-account budget, summary lines, disk floor | `test_flood.py` (EXECUTED) |
| Fill the disk with **signatures** | **Not bounded.** An allowed caller can ask for signatures without limit, each logged (~400 bytes). Dropping a signature's log line is never acceptable, so the fix is a per-purpose signing rate, not built | INSPECTED |
| Exhaust threads | Bounded by `max_connections` | `test_flood.py` (EXECUTED) |
| Hold every connection slot so others get `busy` | **Works for any local account** (availability only; fails closed). A per-account connection share is the fix, not built | INFERRED from the implementation |
| Falsify the audit history | The account cannot reach the log; signet's own account could, and the witness then shows it (Pass B) | drill (EXECUTED) |

## Pass B: cryptographic reviewer (attacker can edit files, replay and substitute)

| Attempt | Result | Evidence |
|---|---|---|
| Replay an older registry, a forked one, or one that un-revokes | Refused by any checker that uses `signet.trust`; the anchor walks its registries through it too | `test_trust.py`, `test_anchor_chain.py` (EXECUTED) |
| Two readers, two meanings (duplicate keys, escapes, floats, big ints, surrogates, trailing bytes) | Refused by both implementations, same answer on all 45 vectors | vectors (EXECUTED) |
| Serialization differences between implementations | One found (DEL escaping) and fixed in the new verifier; 3,000 generated objects now agree byte for byte | differential test (EXECUTED) |
| Ed25519 edge cases (non-canonical encodings, small-order keys) | **Not covered by the vectors.** The Rust verifier uses `verify_strict`, which is at least as strict as OpenSSL, so a disagreement would refuse, not accept. Adding Wycheproof-style vectors is the fix | INFERRED |
| Rewrite the whole log and checkpoint it again with the real log key | Found: the old Rekor records do not match the new checkpoints; the live log does not match the old anchor | drill attack 1 against real Rekor (EXECUTED) |
| Backdate a checkpoint | Found when `--max-delay-ms` is set: Rekor's time is far after `at_ms` | `test_an_old_time_on_a_late_checkpoint_is_named` (EXECUTED) |
| Swap, delete or replace witness records | Found | drill attacks 2 and 3, witness tests (EXECUTED) |
| Owner witnesses a second, forked chain | **Possible.** Both chains stay in Rekor for good, and a checker holding either sees the conflict, but nothing finds it automatically unless an outside party keeps copies. The signing identity is a workflow in signet's own repository | INFERRED from Sigstore's model |
| Checkpoint replay across instances | A checkpoint checks only under that registry's log keys; schema 2 also chains | vectors (EXECUTED) |

## Pass C: production operator (years of operation)

| Concern | State | Evidence |
|---|---|---|
| Runs under its own account | Proven in CI with three real accounts and the shipped systemd unit | CI `separate accounts` (EXECUTED) |
| Monitoring | `signet status` gives a JSON health line and exit code; nothing wires it to an alert yet | test (EXECUTED) |
| Witness keeps running | `.github/workflows/witness.yml` runs hourly **once merged to main** and once the repository variable `SIGNET_ROOT_KEY` is set. Not yet running | INSPECTED |
| Anchor branch protection | UNKNOWN (rules API lists none) | probe P7 |
| Log growth over years | **No rotation.** `verify_file` reads the whole log at start, so start time and memory grow with history | INSPECTED |
| Suppressed-refusal counts | Lost if signet is killed with SIGKILL before the window ends (the refusals themselves were never signatures) | INSPECTED |
| Key loss and compromise | Runbook rehearsed by tests; root still a hand re-pin; keys still files | `test_key_recovery.py` (EXECUTED) |
| Removing an approver | Needs a restart | test (EXECUTED) |
| Upgrades | All new formats are additive: schema 1 checkpoints, configs without limits, logs without the new field all still read | existing tests unchanged and passing (EXECUTED) |
| Real deployment | None. The owner's machine is a one-account Chromebook container | baseline |

## Aggregate

Disagreements between the passes were resolved by evidence: Pass A rated the flood work "closed", Pass C noted the
slot-holding variant still works, and the implementation confirms Pass C, so it is listed as open. Final scores are
in `SIGNET_SCORECARD_v1.md`.
