# Changelog

## Unreleased: RACE 9.7 run (branch `signet/race-9.7`, 2026-11-27)

From `e0d7c60`. No pre-existing test was edited.

- Approval expiry (T10): an approval rule may set `max_age_ms` (1 ms to 24 hours). Approvers then sign the time they
  approved (`domain || SHA-256(bytes) || summary_sha256 || approved_at_ms`, sent as `key:approved_at_ms:signature`),
  and signet counts an approval only from that time until `max_age_ms` later, with a minute of clock drift allowed,
  on its own clock. Rules without it are unchanged. The request limit per approval string grows to 209 characters.
  `rust/signet-verify` reads the field; `rust/signet-client` gains `sign_approved_at`. (Step 13)
- Docs: `SIGNET_THREAT_MODEL_v3`, `SIGNET_SCORECARD_v4` (8.5 to 8.6). (Step 14)
- `rust/signet-verify` `Registry::approval_max_age_ms`: each purpose's approval age from the signed registry, so a
  consumer (HUMANITY) can refuse to start when its own setting differs from signet's. (Step 15)

## Unreleased: RACE 9.6 run (branch `signet/race-9.6`, 2026-11-27)

From `cd70204` (main after PR #8). No pre-existing test was edited.

### Added

- `rust/signet-verify` `trust`: the checker's memory (`TrustState`, `TrustStore`) in Rust, written from
  `signet.trust`'s rules, same state file format. `Registry::digest` and `Registry::current(purpose)`.
  `tests/trust.rs` replays registry sequences made by `signet.trust` (`tests/trust_scenarios.py`) and must give the
  same answer and the same state bytes at every step; signet's Python reads the file the Rust store writes. For
  HUMANITY's startup check, which is Rust. (Step 9)
- Docs: `SIGNET_SCORECARD_v2` (8.4 to 8.6) and `SIGNET_INTEGRATION_MATRIX_v2` (the HUMANITY row: the slip key from
  the registry at start, trust that ends after a window, on HUMANITY branch `humanity/signet-trust`). (Step 10)
- The trust differential sequences carry an approval rule in every registry. (Step 11)
- Docs: `SIGNET_SCORECARD_v3` corrects v2 (8.6 to 8.5: HUMANITY's kernel takes any trust set its host gives it, so
  the check binds the issuer's signer only) and `SIGNET_INTEGRATION_MATRIX_v3`. (Step 12)

## Unreleased: RACE 9.5 run (branch `signet/race-9.5`, 2026-11-27)

From baseline `213c5a6`. Every format change is additive: old configs, logs, checkpoints and registries read as
before. No pre-existing test was edited except as listed.

### Added

- `signet.trust`: a checker's memory of accepted registries (`TrustState`, `TrustStore`); refuses rollback, forks,
  resurrection of revoked keys or public keys, and optional version jumps. (Step 2)
- Chained log checkpoints, schema `signet-log-checkpoint/2` (`at_ms`, `previous`); `signet checkpoint --first` /
  `--previous FILE`; `signet.verify.read_checkpoint`; `signet.log.head_at`. (Step 3)
- `signet_anchor`: chain, downgrade and time checks; anchored registries walked through `signet.trust`;
  `check --max-unanchored / --max-age-ms`. (Step 3)
- `signet_anchor.witness` and `check-witness`: Sigstore bundles as Rekor witness records for each checkpoint.
  `tools/witness_drill.py`, `.github/workflows/witness-drill.yml` (real Rekor), `.github/workflows/witness.yml`
  (production, scheduled, from main). (Steps 4, 6)
- Flood limits: `max_connections` with the `busy` refusal code, `refusal_budget` with `suppressed` summary log lines,
  `min_free_bytes`. The Rust client knows `busy`. (Step 5)
- `signet status`; `deploy/signet.service`; `tools/two_accounts.py` and the CI job `separate accounts`. (Step 6)
- `rust/signet-verify`, an independent verifier; `docs/vectors/signet-vectors-v1.json` and `tools/make_vectors.py`;
  CI job `independent verifier`. (Step 7)
- Docs: `SIGNET_BASELINE_v1`, `SIGNET_THREAT_MODEL_v1` and `_v2`, `SIGNET_SECURITY_ASSESSMENT_v1`,
  `SIGNET_ARCHITECTURE_v1`, `SIGNET_OPERATIONS_v1`, `SIGNET_INTEGRATION_MATRIX_v1`,
  `SIGNET_ADVERSARIAL_TEST_REPORT_v1`, `SIGNET_SCORECARD_v1`, this file. (Steps 1, 8)

### Changed

- Refusals past an account's budget, or below the disk floor, are answered but written as one summary line per
  account and window instead of one line each. A signature is never affected.
- The error text for a malformed checkpoint now names both schemas.

### Dev dependencies

- `hypothesis` (property tests). `sigstore` is installed in CI workflows only, never by the package.

### Tests edited

- `tests/test_baseline_gaps.py` (written in Step 1 of this run): gaps P1 to P3 moved to `tests/test_trust.py` in
  Step 2, and P5 to `tests/test_flood.py` in Step 5, as each closed. No test that existed at the baseline was edited.

## Modified and added files, and why

| File | Why |
|---|---|
| `signet/trust.py` | new: checker memory (T4) |
| `signet/verify.py` | checkpoint schema 2 and `read_checkpoint` (T2) |
| `signet/log.py` | `head_at`; optional `suppressed` field (T2, T13) |
| `signet/__main__.py` | chained checkpoints; `status` (T2, T18) |
| `signet/config.py` | optional flood limits (T13, T16) |
| `signet/server.py` | connection cap, refusal budget, disk floor, summary flushing (T13, T16) |
| `signet/protocol.py`, `rust/signet-client/src/lib.rs` | the `busy` code |
| `signet_anchor/anchor.py`, `__init__.py`, `__main__.py` | chain, monotonic revocation, staleness, witness command (T2, T3, T5) |
| `signet_anchor/witness.py` | new: Rekor witness records (T1) |
| `rust/signet-verify/*` | new: independent verifier (T20) |
| `tools/witness_drill.py`, `tools/two_accounts.py`, `tools/make_vectors.py` | new: drills and vectors |
| `.github/workflows/ci.yml` | jobs `independent verifier`, `separate accounts` |
| `.github/workflows/witness-drill.yml`, `witness.yml` | new: the witness |
| `deploy/signet.service` | new: deployment (T17) |
| `pyproject.toml` | `hypothesis` in the dev extra |
| `.gitignore` | the new crate's build folder |
| `tests/test_trust.py`, `test_anchor_chain.py`, `test_witness.py`, `test_flood.py`, `test_vectors.py`, `test_baseline_gaps.py`; one test added to `test_server.py` | new tests |
| `docs/*` (listed above), `README.md` | deliverables; README threat table and pointers |
