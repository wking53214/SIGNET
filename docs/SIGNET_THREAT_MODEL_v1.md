# SIGNET initial threat assessment, v1 (RACE 9.5, Phase Two: VENOM, first pass)

Date: 2026-11-27. Prepared for William N. King by Claude. Builds on `SIGNET_BASELINE_v1.md` (same evidence tags).
This is the assessment Phase Three is planned from. It does not yet include the three independent review passes of
Phase Five; those run after the fixes.

## Who the attackers are

| Attacker | Has | Wants |
|---|---|---|
| A1 Taken-over caller | an allowed account (zeta, delta, the HUMANITY issuer) | signatures it should not get, approvals bypassed |
| A2 Other local account | any account on the machine, no purpose | a signature, or to stop signing |
| A3 File tamperer | write access to registry, log or checkpoint files in transit or at rest | a checker to accept old or forged trust state |
| A4 Signer-account taker | signet's own account (or root) | keys, and a rewritten history no one notices |
| A5 Root-key thief | the offline root key | registries that every checker accepts |
| A6 Time | years of operation | lost keys, full disks, stale pins, upgrades gone wrong |

## Findings, ranked

🔴 = production blocker. 🟡 = required for 9.5. 🟢 = improvement. Each names what closes it and how it will be tested.

### B. External anchoring (P0)

- 🔴 **T1. No independent anchor is in operation.** The `anchor` branch is empty and lives in the same account that
  runs the signer; GitHub reports no active rules on it (baseline P7). Against A4 and A5 there is no protection
  today. INFERRED from EXECUTED probes.
  - **What closes it.** A witness SIGNET's owner does not control. Code cannot create that; it needs one owner
    decision. Candidates, with what each gives:
    1. A public transparency log (for example Sigstore's Rekor). Append-only, run by a third party, anyone can check
       it, no second account needed. Not a blockchain. Reachable from GitHub Actions; not reachable from this
       workspace (the network allowlist refused it), so publishing would run in CI.
    2. A GitHub organization owned by a second account, the publisher having write access only (the 🟢 row of
       `OUTSIDE_ANCHOR_v1.md`). Previously declined.
  - **What code can do regardless:** make the anchor format witness-ready (below), make CI publish and check, and make
    a missing or late checkpoint visible instead of silent.
- 🟡 **T2. Checkpoints are not bound to a signet instance, a registry version or a time.** A checkpoint from one
  signet is refused by another only because the log key differs. INSPECTED.
  - **Fix.** Checkpoint schema 2: instance id (the log key id is enough), registry version, signet's clock, and the
    previous checkpoint's digest, so checkpoints form their own chain and a gap or reorder shows. Schema 1 keeps
    verifying.
- 🟡 **T3. Suppression is invisible.** Nothing notices if checkpoints stop being published. INFERRED.
  - **Fix.** A staleness check in `signet_anchor check`: the newest checkpoint must be within N entries or N hours of
    the live log, or the check fails.

### C. Registry and revocation

- 🔴 **T4. Fork, resurrection and version jumps are accepted by checkers** (baseline P1 to P3). Exploitable by A5,
  and by A3 if two honest files ever share a version (an operator mistake). EXECUTED.
  - **Fix.** A checker-side **trust state**: a small file (or an in-memory object for libraries) holding the highest
    accepted version, that version's digest, and every key id ever seen revoked. Loading a registry through it
    refuses: a lower version; the same version with a different digest (fork); a revoked id that is no longer revoked
    (resurrection); a jump of more than a configured step (default: no limit, with the option to set one). Written
    atomically, never shrinks. Lives in `signet.registry` so the boundary rule holds.
  - **Test.** Each probe flips from a gap assertion to a refusal test; a property test generates random registry
    sequences and checks the state never accepts a non-monotonic one.
- 🟡 **T5. The anchor's registry list does not check revocation monotonicity either.** Same fix, applied in
  `signet_anchor` when it walks its registries.
- 🔴 **T6. HUMANITY's kernel trusts a pinned purpose key, not the registry**, so SIGNET revocation does not reach it.
  INSPECTED. A change in HUMANITY, not SIGNET: identify it, state its consequences, and do it only with approval.
- 🟢 **T7. Root rotation is a hand re-pin.** Documented honestly in the runbook. A signed "next root" statement in the
  last old-root registry would let checkers follow a planned (not a stolen) rotation. Deferred unless cheap.

### A. Key custody

- 🟡 **T8. Keys are files read into Python memory.** No seam for a hardware key, TPM or KMS. INSPECTED.
  - **Fix.** A small key-provider interface (sign by key id, return public key) with the existing file store as the
    one built-in provider. Concrete use case: HUMANITY's design already requires a non-exporting device. No hardware
    claim is made until a real device provider is built and tested; a PKCS#11 provider is the provider-neutral
    candidate.
- 🟢 **T9. Concurrent `keygen` and generation races.** O_EXCL already handles them. INSPECTED, no action.

### D. Approval integrity

- 🟡 **T10. Approvals never expire and carry no nonce** (baseline P4). Re-sending them re-signs the same bytes. The
  harm is limited because the same bytes give the same Ed25519 signature, and HUMANITY's kernel enforces one use per
  slip. INFERRED. Still, an approval should not be valid forever.
  - **Fix, compatible.** An optional `max_age_ms` in the approval rule; when set, approvers sign a time with the
    approval (approval message version 2) and signet refuses old ones. Rules without it behave exactly as today.
- 🟡 **T11. Removing an approver needs a restart.** Documented (threat 22). Fix: reload the config on SIGHUP with the
  same checks as start, refusing a reload that fails them.
- Residual by design: **T12. signet cannot know the summary was honest.** Stays a 🔴 residual in the README; the
  approver's device must hash the real bytes. Not hidden, not claimed.

### E. Audit integrity

- 🔴 **T13. Refusal flooding fills the disk** (baseline P5: about 36 GiB per day from one client). Every account can
  reach the socket and every refusal is fsynced.
  - **Fix.** Per-account refusal budget: after K refusals in a window, further refusals from that account are counted
    in memory and written as one summary line per window instead of one line each. Allowed callers' signatures are
    never throttled into silence; they are always logged. Plus a low-disk floor: below a configured free space,
    refusals stop being written individually, signatures still are.
- 🟡 **T14. No log rotation or archive.** Fix: `signet rotate-log` seals the current log with a checkpoint and starts
  a new file whose first line names the sealed file's head, so verification spans files.
- 🟢 **T15. `at_ms` is signet's own clock.** Documented; a witness timestamp (T1) is what fixes it.

### F. Operational security

- 🔴 **T16. One thread per connection, no cap** (baseline P6). Fix: a fixed connection limit with a refusal
  (`busy`) above it.
- 🟡 **T17. No deployment recipe.** Fix: a systemd unit with its own user, `ProtectSystem`, `PrivateTmp`,
  `NoNewPrivileges`, a socket directory under `/run/signet`, and a container recipe for the Chromebook case. Tested by
  starting it under a second account where CI allows (GitHub's runners do).
- 🟡 **T18. No monitoring.** Fix: a `signet status` command (log length, head, last checkpoint age, refusal rates,
  disk headroom) with exit codes an alerting job can read.
- 🟡 **T19. Every real run is one account.** Fix: a CI job that runs signet and its caller as two Linux accounts and
  proves a caller account cannot read the keys.

### Independent verification

- 🟡 **T20. Only one verifier implementation.** Fix: a written verification spec with fixed test vectors (registry,
  signature, checkpoint, log line), and a second verifier in Rust (inside the existing Rust crate) that must agree
  with the Python one on every vector, including the refusals.

## What needs an owner decision before Phase Three can close the P0

Only T1 (who the outside witness is) and T6 (changing HUMANITY). Everything else is buildable inside SIGNET now.

## Honest ceiling

With every buildable fix above and no independent witness, the defensible score is around 8.5: the anchoring
dimension cannot rise above about 4 while one account controls both the signer and its only record. With a working
third-party witness running in CI, 9.3 to 9.5 becomes defensible, and hardware key custody is what separates the two.
