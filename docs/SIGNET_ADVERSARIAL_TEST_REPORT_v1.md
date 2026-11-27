# SIGNET adversarial test report, v1 (RACE 9.5)

Date: 2026-11-27. Branch `signet/race-9.5`, baseline `213c5a6`. Evidence tags as in `SIGNET_BASELINE_v1.md`.

## Commands, exit codes and counts (final)

| Command | Where | Exit | Result | Tag |
|---|---|---|---|---|
| `python -m pytest -q` | this workspace, Python 3.13 | 0 | 249 passed, 0 skipped (baseline: 145) | EXECUTED |
| `python -m ruff check .` | this workspace | 0 | clean | EXECUTED |
| `cargo test --locked` in `rust/signet-client` | this workspace | 0 | 12 passed | EXECUTED |
| `cargo test --locked` in `rust/signet-verify` | this workspace | 0 | 5 passed (4 vector/canonical, 1 differential over 3,000 objects) | EXECUTED |
| `cargo clippy -D warnings`, `cargo fmt --check` (both crates) | this workspace | 0 | clean | EXECUTED |
| CI `ci` (py3.10 to 3.13, rust client, independent verifier, separate accounts) | GitHub Actions, run 46043819029 | success | all 7 jobs green | EXECUTED (read via the API) |
| CI `witness-drill` | GitHub Actions, run 46043819091 | success | 3 real Rekor entries (log indexes 4150661093, 4150661154, 4150661239), 5 of 5 attacks caught | EXECUTED (read via the API) |

Earlier drill run 46042291028 made Rekor entries 4150630982, 4150631277 and 4150631426. Anyone can look them up at
`https://search.sigstore.dev/?logIndex=N`.

## The required test list, and where each is held

| Required | Held by | Result |
|---|---|---|
| Positive signing and verification | `test_server.py::test_a_signature_checks_under_the_registry`, `test_interop.py`, vectors | 🟢 |
| Unauthorized callers | `test_an_account_not_allowed_is_refused`; with real accounts, `tools/two_accounts.py` claim 4 (CI) | 🟢 |
| Wrong-purpose signing | `test_the_zeta_key_cannot_sign_a_delta_receipt`, wrong-label tests, vector "a zeta signature checked as delta" | 🟢 |
| Wrong-key verification | vectors "a stranger's signature under a listed id", "the root key signing for zeta" | 🟢 |
| Registry rollback | `test_trust.py::test_rollback_is_refused_without_the_checker_passing_any_number` | 🟢 |
| Registry forks | `test_fork_two_registries_with_one_version`, `test_two_checkers_sharing_a_memory_cannot_both_accept_a_fork` | 🟢 |
| Revoked-key resurrection | `test_resurrection_of_a_revoked_key`, `..._under_a_new_id_...`, `test_an_anchored_registry_cannot_bring_a_revoked_key_back` | 🟢 |
| Approval quorum bypass | `test_one_approver_is_not_enough`, `test_no_approvals_at_all_is_refused` | 🟢 |
| Duplicate approvers | `test_the_same_approver_twice_counts_once` | 🟢 |
| Approval replay | `test_approvals_reused_for_another_capability_do_not_count` (closed); same bytes re-sent: `test_baseline_gaps.py::test_gap_the_same_approvals_get_a_second_signature` | 🟡 recorded gap |
| Misleading approval context | not testable in signet (it sees only the summary digest) | 🔴 residual by design |
| Log tampering | `test_an_edited_line_is_found`, `test_reordered_lines_are_found`, `test_an_edited_log_stops_the_start` | 🟢 |
| Log truncation | `test_lost_history_is_found`; whole rewrite: `test_a_whole_rewrite_the_log_alone_cannot_see_is_found`, drill attack 1 against Rekor | 🟢 |
| Anchor rollback | `test_published_history_going_backwards_is_found`, `test_a_removed_middle_checkpoint_shows`, `test_swapped_checkpoints_show`, downgrade test | 🟢 |
| Anchor unavailability | `test_stalled_publishing_is_named`, `test_an_unwitnessed_checkpoint_is_named...`, drill attack 3 | 🟢 |
| Concurrent requests | `test_many_callers_at_once_get_distinct_logged_signatures`, trust-store race test | 🟢 |
| Process termination | `test_sigkill_then_restart_keeps_one_verified_history`, torn-line test | 🟢 |
| Disk exhaustion | `test_below_the_disk_floor_refusals_are_counted_and_signatures_still_written`, `test_a_log_that_cannot_be_written_releases_no_signature` | 🟢 |
| Key rotation | `test_rotation_keeps_the_old_key_verifying_and_revocation_ends_it`, recovery cases 1 and 2 | 🟢 |
| Recovery after compromise | `test_key_recovery.py` cases 2 and 4 | 🟢 |
| Consumer integration | `test_interop.py` (zeta, beta, delta); CNS and HUMANITY in their own repos (INSPECTED, not run here) | 🟡 |
| Property-based | `test_property_the_memory_never_accepts_a_non_monotonic_history` (hypothesis) | 🟢 |
| Fuzz / differential | `rust/signet-verify/tests/differential.rs` (3,000 generated objects), 45 shared vectors | 🟢 |

## What the adversarial work found that tests alone had not

| Finding | How found | Now |
|---|---|---|
| A checker accepts two different registries of one version, a resurrected revoked key, any version jump | baseline probes P1 to P3 | closed by `signet.trust` (Step 2) |
| 36 GiB/day of refusal lines from one local account; one thread per connection, unbounded | probes P5, P6 | closed by the flood limits (Step 5) |
| The anchor branch README says a ruleset protects it; GitHub's rules API lists none | probe P7 | UNKNOWN, owner to check |
| signet's canonical writer escapes DEL (0x7f); a second implementation written from the docs did not | the differential test (Step 7) | fixed in the new verifier; no signet format allows DEL in a signed string today |
| `two_accounts.py` used a non-blocking read on a text stream | the first CI run of the job | fixed (Step 6 fix commit) |
