# SIGNET baseline, v1 (RACE 9.5, Phase One: PHOENIX)

Date: 2026-11-27. Prepared for William N. King by Claude. Nothing in signet's behaviour was changed to produce this.

Evidence tags used throughout:

- **EXECUTED**: run by the investigator, result captured here.
- **INSPECTED**: read in the actual implementation.
- **INFERRED**: concluded from the implementation or architecture, not run.
- **UNKNOWN**: the evidence is not available from this workspace.

A documented claim is never counted as executed verification.

## 1. What was looked at

| Item | Value | Tag |
|---|---|---|
| Repository | github.com/wking53214/SIGNET (public) | EXECUTED |
| Baseline commit | `213c5a640cb21a7aadd0c6e443265fd29ef75c67` (main, merge of PR #6, key recovery) | EXECUTED |
| Other branches | `anchor` at `7d55f50`, holding only a README; no registry or checkpoint has ever been published to it | EXECUTED |
| Work branch | `signet/race-9.5`, from the baseline commit | EXECUTED |
| Size | 6,043 tracked lines: 1,452 Python in `signet/`, 264 in `signet_anchor/`, 612 Rust client source, 1,631 test lines | EXECUTED |
| Runtime dependency | `cryptography>=42` only (Ed25519 through OpenSSL); 50.0.2 installed | EXECUTED |
| Platform claimed | Linux only (`SO_PEERCRED`) | INSPECTED |

Consumer repositories inspected, at these commits:

| Repo | Commit | Tag |
|---|---|---|
| CNS | `0fde15e` | EXECUTED (clone), INSPECTED |
| HUMANITY | `39b7ef3` | EXECUTED (clone), INSPECTED |
| HERALD | `1c26d06` | EXECUTED (clone), INSPECTED |
| zeta, beta, delta | the commits pinned in `pyproject.toml` (`0ab30b2`, `9cabc93`, `525217b`) | EXECUTED (installed), INSPECTED |

## 2. Test and lint results at the baseline

All EXECUTED on Python 3.13.18, Linux, in a fresh virtual environment with `pip install -e ".[dev]"`.

| Command | Exit | Result |
|---|---|---|
| `python -m pytest -q` | 0 | 145 passed, 0 skipped, 18.5 s |
| `python -m ruff check .` | 0 | all checks passed |
| `cargo test --locked` (in `rust/signet-client`, `SIGNET_PYTHON` set) | 0 | 12 passed (2 unit, 5 stand-in server, 5 against the real signet) |
| `python -m pytest -q` after adding `tests/test_baseline_gaps.py` | 0 | 150 passed |

The CI matrix (Python 3.10 to 3.13 plus the Rust job) was not re-run from here: UNKNOWN for 3.10 to 3.12 at this commit.

## 3. How SIGNET works today, in one paragraph

SIGNET is a separate program that holds private signing keys in files only its own account can read. A program that
needs a signature connects to SIGNET's local socket and sends the bytes. SIGNET asks the Linux kernel which account
is calling (the caller cannot fake this), checks that account is allowed for the purpose, checks the bytes start with
that purpose's label, checks approvals if the purpose needs them, signs, writes a hash-chained log line to disk, and
only then returns the signature. Checkers verify through a signed registry (the list of keys and their status),
whose signing root key they pin by hand. An optional anchor package can keep copies of registries and log
checkpoints somewhere the signer cannot rewrite, but no such place is in operation.

## 4. Security-sensitive functions and their callers

All INSPECTED.

| Function | What it guards | Called by |
|---|---|---|
| `server.Signer.handle` | the whole decision for one request | `server.build.Handler.handle` (one thread per connection) |
| `server.peer` | caller identity from `SO_PEERCRED` | the handler, before anything is read |
| `server._claim_socket`, `_check_socket_dir` | socket squatting and replacement | `server.build` at start |
| `keys.load`, `keys.generate`, `keys._check_private` | key file type, owner, mode | `Signer.__init__`, the `keygen`, `registry` and `checkpoint` commands |
| `approval.check_rule`, `approval.counted` | quorum floor of 2, distinct listed approvers, exact-byte binding | config, registry, `Signer.handle` |
| `log.SignatureLog.append` | write and fsync before release | `Signer.handle`, `Signer._refuse` |
| `log.verify_file` | hash chain on start and on demand | `SignatureLog.__init__`, `verify-log`, `checkpoint`, `signet_anchor` |
| `registry.load_registry`, `check_body` | pinned root, shape, one current key per purpose, no shared public keys | every checker, `signet_anchor`, the `registry` command |
| `registry.next_body` | rotation, revoke-is-final (writer side only) | the `registry` command |
| `verify.verifier`, `check_checkpoint` | fail-closed signature check | consumers, `signet_anchor` |
| `strict.loads`, `strict.canonical` | one reading and one byte form of every input and signed object | everything above |
| `client.request` (and the Rust `Client`) | fail closed, optional `expected_uid` check of the server's account | consumers |

The boundary rule (callers never load the key store, server, log or config) is enforced by `tests/test_boundary.py`:
EXECUTED, passes.

## 5. Integrations: who actually uses SIGNET

| Component | What exists | Real end-to-end path exercised? | Tag |
|---|---|---|---|
| zeta | unchanged library; its `signer=` slot is filled by `signet.client` in SIGNET's and CNS's tests | Yes, in tests, one account | EXECUTED (SIGNET `test_interop.py`), INSPECTED (CNS) |
| beta | unchanged; its `lock_result_verifier=` slot is filled by `signet.verify` | Yes, in tests, one account | EXECUTED, INSPECTED |
| delta | unchanged; receipts signed through SIGNET in tests. delta's own checkpoint anchor is separate and does not use SIGNET's | Receipts yes (tests); checkpoints no | EXECUTED, INSPECTED |
| CNS | `chains/signet_live.py` starts a real SIGNET as a child process for six `signet:` spine scenarios | Yes, in CI, one account (SIGNET prints its same-account warning) | INSPECTED (not run from here) |
| HUMANITY | `issuer/src/signet_signer.rs` signs capability slips through SIGNET's Rust client with approvals and `expected_uid` | Yes, in HUMANITY's tests | INSPECTED (not run from here) |
| HERALD | no reference to SIGNET at all | No | EXECUTED (search) |

Two integration facts that matter for scoring:

1. **HUMANITY does not check slips through SIGNET's registry.** The issuer is handed SIGNET's purpose public key and
   the kernel's trust set "must hold the same" (`signet_signer.rs`, INSPECTED). So a revocation in SIGNET's registry
   does not reach the kernel that runs capabilities. INFERRED: HUMANITY slips are outside SIGNET's revocation.
2. **HUMANITY pins the Rust client at `0a83577`** (PR #4, step 3), not at the baseline. It is on main's history, so
   this is staleness, not a fork. INSPECTED.

No integration runs SIGNET under a separate account. Every exercised path is "the wiring is right", not "the
separation holds". INFERRED from the configs (all use `os.getuid()` for both sides).

## 6. Baseline probes (adversarial, run against the baseline code)

Each is EXECUTED. The deterministic ones are kept as gap assertions in `tests/test_baseline_gaps.py`, which fail the
day the gap closes.

| # | Probe | Result |
|---|---|---|
| P1 | Two different registries, both version 2, both root-signed, checker at `min_version=2` | **Both accepted.** A version number alone cannot detect a fork |
| P2 | Version 2 revokes `zeta1`; root-signed version 3 makes it current again | **Accepted, and the revoked key verifies again** under v3 |
| P3 | Registry jumps from version 1 to 1000 | **Accepted.** After a root theft, a checker that saw 1000 refuses honest versions |
| P4 | Same two approvals sent twice for the same bytes | **Signed twice**, two log lines. No nonce or expiry on approvals |
| P5 | 3,000 refused requests from one client, stderr drained | 386 bytes of fsynced log per refusal, 2.6 s; about **36 GiB per day** from one local client. Any account may connect (socket mode 0666) and refusals from accounts that are not allowed are logged too |
| P6 | 1,500 idle connections held open | **1,501 server threads** (one per connection, no cap), 52 MB resident; a legitimate request was still served. With a longer flood or a smaller host, threads or memory run out. INFERRED |
| P7 | GitHub rules active on the `anchor` branch (`GET /repos/wking53214/signet/rules/branches/anchor`) | **Empty list.** The branch README says a no-bypass ruleset protects it. Either the ruleset is not active on that branch or this session's token cannot see it: UNKNOWN which, needs a look in the repository's Settings |
| P8 | One run of a 2,000-refusal flood with stderr not drained timed out a client at 10 s; a repeat of 5,000 did not reproduce it | UNKNOWN. Recorded, not counted |

## 7. Baseline scorecard

Scored against the mission's standard: the property must be demonstrated, not documented. 1 to 10.

| Dimension | Score | Evidence (short) |
|---|---|---|
| Architecture | 9.0 | Clean signer/caller split, enforced by test; small modules; anchor separable by design |
| Cryptographic correctness | 8.5 | Ed25519 via OpenSSL; label prefix on every signed byte string; strict reader; canonical writer refuses surrogates and floats. Checkpoints carry no instance id, registry version or time |
| Key custody | 6.0 | Files with owner/mode/no-link checks and O_EXCL. No provider interface, no hardware path, keys live in Python memory |
| Identity enforcement | 8.0 | `SO_PEERCRED`; client-side `expected_uid`. Same-account runs only warn; every real run today is same-account |
| Purpose isolation | 9.5 | One key one purpose, labels unique, reserved purposes unservable, checker re-checks the label |
| Registry integrity | 6.5 | Pinned root, strict shape. Fork, resurrection and version jumps accepted (P1 to P3); remembering the version is left to each checker with no helper |
| Revocation | 6.5 | Works when a checker loads the new registry; not monotonic on the checker side; HUMANITY's kernel is outside it |
| Approval integrity | 8.0 | Exact-byte binding, distinct listed approvers, floor of 2 in code. No expiry or nonce (P4); approver removal needs a restart; summary honesty is out of scope by design |
| Audit integrity | 7.5 | fsync before release, hash chain, torn-line refusal, SIGKILL tested. No rate limit (P5), no rotation or archive, local clock |
| External anchoring | 2.5 | Mechanism built and tested; nothing published; protection unconfirmed (P7); same account owns signer and anchor |
| Failure handling | 8.5 | Fails closed everywhere tested; refusals reach the caller even with stderr gone |
| Independent verification | 5.0 | Only signet's own Python verifier exists; the Rust client signs but does not verify; no second implementation or spec test vectors |
| Integration | 6.0 | Real paths with zeta, beta, delta, CNS, HUMANITY in tests; all one account; HERALD absent; HUMANITY bypasses the registry |
| Testing | 8.5 | 145 Python and 12 Rust tests, real processes, no skips allowed. No property or fuzz tests; no disk-full or concurrency-under-load tests |
| Operational readiness | 4.5 | No service unit, no monitoring or alerting, no log rotation, no rate limits, no deployment recipe beyond prose; only deployment target is a one-account Chromebook |
| Documentation | 9.0 | Honest README with a purple-teamed threat table, runbook, anchor doc |
| Maintainability | 8.5 | Small, consistent, lint clean, one runtime dependency |
| **Mean** | **7.2** | |

**Why 7.2 and not 8.8.** The earlier 8.8 reads as a code-quality score, and on code quality SIGNET earns it. This
mission scores whether production trust properties are demonstrated. Three of those (an operating independent anchor,
consumer-side rollback and fork detection, and operational hardening) are not demonstrated at all, and they pull the
mean down hard. Nothing here says the existing code is poor; it says the system around it is not yet built.

## 8. Production blockers at the baseline

1. **No operating independent anchor** (P7, section 5). The mission's P0. Needs a party SIGNET's owner does not
   control, which is an owner decision, not a code change.
2. **Checkers cannot detect registry forks, resurrection or version jumps** (P1 to P3), and have no shared way to
   remember what they accepted.
3. **Any local account can exhaust disk or threads** (P5, P6), which stops all signing (closed, but down).
4. **Keys are files**; no key-provider seam to add a hardware or KMS key later.
5. **HUMANITY's kernel trusts a pinned key instead of the registry**, so revocation does not reach it.
6. **No deployment has separate accounts**; the separation is proven by design and by tests of the checks, not by a
   running deployment.
7. **No second, independent verifier.**

## 9. Modified files in this phase

| File | Why |
|---|---|
| `tests/test_baseline_gaps.py` (new) | Records probes P1 to P5 as assertions, so each gap fails loudly the day it is closed |
| `docs/SIGNET_BASELINE_v1.md` (new) | This document |
| `docs/SIGNET_THREAT_MODEL_v1.md` (new) | The initial threat assessment that Phase Three is planned from |

No pre-existing test or source file was changed.
