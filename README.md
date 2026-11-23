# SIGNET

> **Status, checked 2026-11-23 at `3181bf0` (branch `signet/phase-1`, before its first merge).** Version `0.1.0`, not tagged.
> Run here in fresh virtual environments holding only this repository and its `dev` extra: `python -m pytest -q` gives
> **92 passed, none skipped** on Python 3.11, 3.12 and 3.13 (EXECUTED). `ruff check .` is clean (EXECUTED). The `dev` extra
> pins zeta `0ab30b2`, beta `9cabc93` and delta `525217b`, the commits `contracts/spine-manifest.json` in CNS names, and the
> interop tests ran against exactly those. Not run: GitHub CI, Python 3.10 (the declared floor; no 3.10 interpreter was
> available here), any platform other than Linux. Phase 1 of 5 (see "Where this goes next").

The keyholder for the library. One small program that holds every signing key, signs only what each key is for, and
writes down every signature it makes, plus one signed list of keys that every checker reads.

## Role Within ≡TACK

- **What it is.** A separate signer program (`signet serve`), a signed key registry, a tamper-evident signature log,
  and the two small pieces a library needs to use them: a client that signs (`signet.client`) and a checker built from
  the registry (`signet.verify`).
- **What it owns.** Custody of private keys, the rule for which key may sign which bytes, the record of every signature
  and refusal, and the one list of which keys are trusted, retired or revoked.
- **What it contributes.** It removes keys from the programs that use signatures. zeta, beta, delta, HERALD and the
  HUMANITY issuer each have a signing slot that today says "keys, trust and revocation are the deployer's". signet is
  that deployer side, built once.
- **What it does not own.** What anything means. signet does not decide whether a lock is open, a Decision is right or a
  receipt is honest. It checks who is asking and that the bytes are labelled for the key's purpose, then signs. The
  libraries keep their own rules, and their checkers keep the final say.
- **Depends on.** The Python standard library and `cryptography` (Ed25519 through OpenSSL). Nothing in the package
  imports any other ≡TACK repository. The tests install zeta, beta and delta from the `dev` extra to prove the plug fits.
- **Depended on by.** Nothing yet. Phase 2 wires it into CNS's spine runner and the HUMANITY issuer.
- **Verified versus declared.** Every line under "What works" names the test that holds it. Every limit under "Limits" is
  either asserted by a test or stated as not established.
- **Failure behavior.** Closed, everywhere. A refused request, a signet that is down, a log that cannot be written, an
  unexpected answer: each ends with no signature, and the client raises. zeta and beta treat a raising signer as "no
  Decision" and put the lock state back (`tests/test_interop.py`). signet refuses to start rather than start unsafe.

License: Apache-2.0 (`LICENSE`, `NOTICE`). Copyright 2026 William N. King.

## The problem this solves

Over November 2026 the library gained five signing slots: zeta signs lock results, beta checks them, delta signs
receipts and checkpoints, HERALD signs its export, the HUMANITY issuer signs slips. Each slot was built the same careful
way: the library builds the exact bytes, calls a `sign` it is handed, and holds no key. Each README then carries the same
two sentences, because they are true:

1. **In-process code can still sign a fake.** The key sits in the same program as the code that uses it, so anything
   that takes over that program can sign whatever it likes.
2. **Keys, trust and revocation are the deployer's.** Five slots, five trust lists, no place to revoke a key once.

Every signature in the library is capped by those two sentences. signet is aimed at the cap, not at any one slot.

## How it works

```
   program that needs a signature                         signet (its own account)
   (zeta / beta / delta / HERALD / issuer)
                                                          +---------------------------------+
   sign = signet.client.signer(sock, purpose)             |  private keys (0600, 0700 dir)   |
   library calls sign(bytes) ---- Unix socket ---------->  |  1 frame <= 1 MiB, strict JSON   |
                                  kernel reports caller's  |  2 purpose is one it serves      |
                                  account (SO_PEERCRED)    |  3 caller's account is allowed   |
                                                           |  4 bytes start with the label    |
                                                           |  5 sign, write log, fsync        |
   <---------------- signature (key_id:ed25519) ---------  |  only then answer                |
                                                          +---------------+-----------------+
                                                                          |
   checker (beta / CNS / TIE / issuer)                                    | log checkpoint, registry
   verify = signet.verify.verifier(registry, purpose)                     v
   registry checked against a PINNED root key          outside anchor (a repository signet's
                                                        operator cannot rewrite; delta's anchor)
```

**One key, one job.** Every purpose has its own key. A purpose also has a label: the prefix every byte string signed for
it must start with. The libraries already put that label at the front of what they sign (zeta's is
`zeta-lock-result-signature/1\n`, delta's receipts `delta-ledger-receipt-signature/1\n`). signet checks it before
signing, and the checker checks it again. So the zeta key cannot be talked into signing a delta receipt
(`tests/test_interop.py::test_the_zeta_key_cannot_sign_a_delta_receipt`), and a signature made for one purpose never
checks under another.

**Who may ask.** Each purpose lists the accounts allowed to ask for it. signet does not take the caller's word: it asks
the kernel which account is at the other end of the socket (`SO_PEERCRED`). A caller cannot set that value.

**Nothing leaves before it is written down.** A signature is appended to signet's log and the log is forced to disk
before the signature is sent back. A signature that was not logged is never released
(`tests/test_server.py::test_a_log_that_cannot_be_written_releases_no_signature`).

**The libraries do not change.** signet's client is a `sign(data) -> bytes` callable and its checker a
`verify(data, signature) -> bool` callable, the exact shapes zeta (`LockEvaluator(signer=)`), beta
(`lock_result_signer=`, `lock_result_verifier=`) and delta (`sign_receipt`, `verify_receipt_signature`) already take.
The signature envelope, `key_id:` then the 64-byte Ed25519 signature, is the one CNS's reference deployer
(`chains/receipt_keys.py`) uses, so the two read each other.

## The registry

One file, `{"registry": {...}, "signature": "..."}`, signed by the **root key** over `signet-registry/1\n` and the
canonical bytes of the `registry` object. It lists every purpose with its label and every key with its purpose, public
key and status:

| status | signs now | still checks | how a key gets here |
|---|---|---|---|
| `current` | yes, at most one per purpose | yes | it is the key in the config when the registry is written |
| `verify-only` | no | yes, so what it signed keeps checking | the next version made another key current for its purpose |
| `revoked` | no | never, whatever it signed | `--revoke KEY_ID`; final, and the id can never come back |

A checker **pins the root public key out of band** (it is never read from the file it checks) and loads the registry
with `load_registry(text, root_public_key, min_version=N)`. The **version only goes up**. A checker that remembers the
highest version it has accepted passes it as `min_version`, and an older file (one from before a revocation, replayed by
whoever serves the file) is refused (`tests/test_registry.py::test_rollback_to_an_older_version_is_refused`).
Remembering that number is the checker's job; no file can tell a checker which version is newest.

A registry that could be read two ways is refused, naming why: a key id twice, one public key under two ids (revoking one
would leave the other), two current keys for one purpose, a key for a purpose the file does not list, an unknown status,
or one of signet's own purposes given a different label (`tests/test_registry.py::test_ambiguous_bodies_are_refused`).
The id and revocation rules are the ones CNS's `chains/receipt_keys.py` already holds, carried over, not reinvented.

**The root key does not have to live on the signer's machine.** `signet serve` never loads it. Only `signet registry`
does, so the safest setup writes registries on a separate, offline machine holding the root key, and copies only the
signed file to the signer and the checkers.

## The log

One JSON line per signature **and per refusal**, each holding: sequence number, previous line's hash, signet's clock
(`at_ms`), outcome and refusal code, purpose, key id, the caller's account and process id, the SHA-256 of the bytes
signed, the SHA-256 of the signature, and the line's own hash. The line's hash covers every other field, and each line
names the one before it, so an edited, removed, inserted or reordered line breaks the chain where it happened
(`tests/test_keys_and_log.py`).

**The log holds digests, never the bytes.** A record of what was signed must not become a copy of everything signed;
patient data that passes through zeta is not written to signet's disk
(`tests/test_server.py::test_the_log_holds_digests_never_the_signed_bytes`).

**Refusals are logged too**, with the account that asked. A program probing for a key it may not use leaves a trail.

**A checkpoint** is the log's length and head, signed with the log key (`signet checkpoint`). Copied somewhere signet's
operator cannot rewrite, it fixes history up to that point. That place is delta's outside anchor: a protected repository
the writer's account cannot force-push. The reason is in "Limits": the log alone cannot show a rewrite of the whole file.

## What one signature costs a caller

Nothing new to learn. Before:

```python
LockEvaluator(registry, signer=my_private_key_sign)        # the key is inside this program
```

With signet:

```python
from signet.client import signer
from signet.registry import load_registry
from signet.verify import verifier

sign = signer("/run/signet/signet.sock", "zeta-lock-result", expected_uid=SIGNET_UID)
registry = load_registry(open("/etc/signet/registry.json", "rb").read(), PINNED_ROOT_KEY, min_version=LAST_SEEN)
engine = DecisionEngine(rules, locks, lock_result_signer=sign,
                        lock_result_verifier=verifier(registry, "zeta-lock-result"))
```

Pass `expected_uid` (signet's account number) in production. The client then asks the kernel who is at the other end
of the socket and sends nothing to a program squatting on the path
(`tests/test_server.py::test_a_client_that_expects_another_account_sends_nothing`).

## Running it

Linux only: `SO_PEERCRED` is how signet learns the caller's account, and signet refuses to start without it.

1. **Make signet its own account** (for example `signet`), and give it a private state directory and a socket
   directory that no other account can write to:
   `install -d -o signet -m 0700 /var/lib/signet/keys` and `install -d -o signet -m 0755 /run/signet`.
2. **Write the keys, as that account**, one per job: `signet keygen --keys-dir /var/lib/signet/keys root-2026-11`,
   then `log-2026-11`, then one per purpose (`zeta-2026-11`, `delta-2026-11`, ...). Each prints its public key. A key
   id names one key forever; `keygen` never overwrites.
3. **Write the config** (`signet-config/1`, documented in `signet/config.py`): the socket, key and log paths, the
   registry and log key ids, and for each purpose its key id, label and the accounts allowed to ask.
4. **Write the first registry**: `signet registry --config CONFIG --out registry-1.json`. It prints the root public
   key; that is the value every checker pins. Copy the registry to the checkers.
5. **Run it**: `signet serve --config CONFIG`, under a service manager (systemd `User=signet`, `Restart=on-failure`).
6. **Publish checkpoints** on a schedule: `signet checkpoint --config CONFIG --out checkpoint-<n>.json`, copied to the
   outside anchor. Anyone checks one with `signet check-checkpoint --registry FILE --root-key HEX --checkpoint FILE`.

**Rotating a key**: generate a new id, put it in the config for that purpose, write the next registry with
`--previous registry-N.json --root-key HEX`, restart signet, hand checkers the new file. The old key becomes
`verify-only` on its own, so what it signed keeps checking. **Revoking**: the next registry with `--revoke KEY_ID`.
Both are walked end to end by `tests/test_server.py::test_checkpoint_and_rotation_through_the_command_line`.

**signet refuses to start**, exit 2 with one line naming why, on: a config it refuses (`signet/config.py` lists every
case), a key file or key directory that group or others can open or that is a link, a log that does not verify, a
socket directory another account can write to, a socket already served by a running signet, or a path that is not a
socket. A socket file left by a signet that died is reclaimed.

**After a crash in the middle of a write**, the log's last line can be torn. signet then refuses to start and says so.
That line's signature was never released (lines are synced before signatures leave), so removing the partial line is
safe, but signet will not decide that for the operator: check the line, remove it, start again.

## Threat model, purple-teamed

Red: how would someone get a signature they should not have, or hide one? Blue: what stops it, and which test holds it.
Run on the built code on 2026-11-23. Two holes were found in that run and closed in Step 6 (marked 🔧).

| # | Attack | What stops it | Held by | Result |
|---|---|---|---|---|
| 1 | Read a key from the program that uses it | The key is in another account's files; the caller's process has no key code loaded at all | `test_boundary.py` (both tests) | 🟢 Closed |
| 2 | Another account on the machine asks for a signature | The kernel reports the caller's account; not on the purpose's list means refused and logged | `test_an_account_not_allowed_is_refused` | 🟢 Closed |
| 3 | Use the zeta key to sign a delta receipt (or any bytes) | Each purpose signs only bytes starting with its label; the checker checks the label again | `test_the_zeta_key_cannot_sign_a_delta_receipt`, `test_verifier_refuses_other_purposes_labels_unknown_keys_and_junk` | 🟢 Closed |
| 4 | Ask for signet's own registry or log key over the socket | Those two purposes are never served to a caller and cannot be configured as caller purposes | `test_an_unknown_or_reserved_purpose_is_refused`, `test_config.py` | 🟢 Closed |
| 5 | Two readers, two meanings: duplicate keys, floats, huge numbers, deep nesting, oversize frames | One strict reader for every file and message; the frame size is checked before the body is read | `test_strict.py`, `test_malformed_requests_are_refused` | 🟢 Closed |
| 6 | 🔧 Swap signet's socket for your own, in a directory you can write to | signet refuses a socket directory another account can write to | `test_a_socket_directory_others_can_write_to_stops_the_start` | 🟢 Closed in Step 6 |
| 7 | 🔧 Squat on the socket path while signet is down, and collect callers' bytes | With `expected_uid`, the client checks the account at the other end and sends nothing to anyone else | `test_a_client_that_expects_another_account_sends_nothing` | 🟢 Closed in Step 6, when `expected_uid` is passed |
| 8 | Get a signature that never appears in the log | Write and fsync first, answer second; a failed write releases nothing | `test_a_log_that_cannot_be_written_releases_no_signature` | 🟢 Closed |
| 9 | Edit, remove or reorder log lines | Hash chain; signet will not start on a broken one | `test_an_edited_line_is_found`, `test_a_removed_line_is_found`, `test_reordered_lines_are_found`, `test_an_edited_log_stops_the_start` | 🟢 Closed |
| 10 | Replay an old registry from before a revocation | Versions only go up; a checker passes the highest it has seen | `test_rollback_to_an_older_version_is_refused` | 🟡 Closed only if the checker remembers its last version |
| 11 | Forge a registry | Checked against a root key pinned out of band, never against a key in the file | `test_a_wrong_pinned_root_is_refused`, `test_an_edited_registry_is_refused` | 🟢 Closed |
| 12 | Kill signet mid-burst and restart | One verified history continues; the stale socket is reclaimed | `test_sigkill_then_restart_keeps_one_verified_history` | 🟢 Closed |
| 13 | 🔴 Take over an ALLOWED caller and ask for a real-looking signature on fake content | Not stoppable by a signer that does not understand the content. Every such signature is in the log, counted and attributed, for an auditor to match against the ledger it should match | log tests | 🔴 Residual, now visible |
| 14 | 🔴 Take over signet's own account, or root | Reads the keys, rewrites the whole log consistently | `test_a_rewritten_chain_is_not_found_by_the_log_alone` asserts the limit | 🔴 Residual: published checkpoints show a rewrite after the fact; a hardware key is the fix |
| 15 | Flood signet with refused requests to fill its disk | Each refusal is logged with the account that sent it; a full disk then refuses everyone (closed, not open) | not tested | 🟡 Availability only; no rate limit yet |

## What works

Each line names the test that holds it. A claim without one is not made.

- A signature made through signet checks under the registry for its purpose and under no other purpose
  (`tests/test_server.py::test_a_signature_checks_under_the_registry`).
- Every check of a request refuses with its own code and leaves a log line: wrong label, unknown or reserved purpose,
  account not allowed, malformed or oversize frame (`tests/test_server.py`, five tests).
- A connection that never sends its request is closed and other callers are still served
  (`test_a_silent_connection_is_closed_and_others_are_still_served`).
- 32 callers at once each get a distinct signature and log line, and the log verifies
  (`test_many_callers_at_once_get_distinct_logged_signatures`).
- Unchanged zeta and beta: zeta signs lock results through signet, beta checks them through the registry, and the
  Decision equals the unsigned one. A lock result from another signet is refused with lock state put back. signet
  refusing, or signet down, means no Decision and lock state put back (`tests/test_interop.py`, four tests).
- Unchanged delta: receipts sign through signet and check through the registry; an edited receipt does not check; a
  receipt signature does not check under the zeta purpose (`test_delta_receipts_sign_through_signet_and_check_through_the_registry`).
- Rotation keeps old signatures checking; revocation ends them; an old registry is refused once a newer one was seen;
  checkpoints sign and check through the command line; outputs are never overwritten
  (`test_checkpoint_and_rotation_through_the_command_line`, `tests/test_registry.py`).
- Keys: written 0600 and never overwritten; refused when group or others can open them or their directory, when they
  are links, or when damaged (`tests/test_keys_and_log.py`).
- The caller side imports nothing of the signer side, read from the source and from a real import
  (`tests/test_boundary.py`, CLAUDE.md rule 3).
- No test skips; a skip fails the run (`conftest.py`).

## Limits

- **An allowed caller that is taken over still gets signatures for its own purpose** (threat 13). Separation stops key
  theft and cross-purpose signing. It does not make signet understand content. What changes is that every signature is
  logged by a program the caller does not control. Matching the log against delta's ledger is an audit step that is not
  built yet.
- **The keys are files.** Root, or anyone who takes over signet's account, can read them, and can read a key from
  signet's memory. A device that cannot export keys (a hardware key, a TPM, a cloud KMS) is the fix and is not here.
- **The log alone cannot show a whole rewrite.** Whoever can write the file can write a new, consistent chain
  (asserted by `test_a_rewritten_chain_is_not_found_by_the_log_alone`). Only a checkpoint published outside signet's
  reach shows it, and only for history up to that checkpoint.
- **Rollback protection is the checker's memory.** `min_version` works only if the checker keeps the last version it
  accepted.
- **No freshness.** `at_ms` is signet's own clock. A signature says nothing about when the signed thing happened; that
  is bound where it already was (beta's Decision timestamp, delta's ledger).
- **No rate limit.** A flood fills the disk; signet then refuses everyone, which is safe but stops the work.
- **One machine.** The socket is local. Callers on other machines are not served, by design, for now.
- **Linux only**, and the Python floor of 3.10 is declared, not run here.
- **Not yet wired in.** No ≡TACK repository uses signet yet. Phase 2 does that.

## Where this goes next

| Phase | Work | Closes |
|---|---|---|
| 1 (this) | The signer, the registry, the log, proven against unchanged zeta, beta and delta | the in-process key, the five trust lists |
| 2 | CNS's spine runner signs through signet from a separate process; the HUMANITY issuer too | proves phase 1 in the real chains |
| 3 | Checkpoints and the registry published to delta's outside anchor; CNS CI fails on a lost or forked history | the whole-rewrite limit |
| 4 | Vouched inputs: a data source signs "I supplied this" with its own registered key; ALPHA and HERALD record it | unchecked inputs at the edges |
| 5 | A verifier kit for outside reviewers, from the registry format, the labels and these tests | everything checked by one team |

## What broke and how it was fixed

| when | what broke | how it was found | fixed |
|---|---|---|---|
| 2026-11-23 | 32 callers at once: some were refused with "resource temporarily unavailable" (safe, but wrong) | `test_many_callers_at_once_get_distinct_logged_signatures` | the listen queue raised from Python's default of 5 to 128 (Step 4) |
| 2026-11-23 | a test helper checked "is signet up?" by connecting, and signet logged each check as a refused request | the log tests saw extra lines | the helper waits for signet's "serving" line instead; signet was right to log it (Step 4) |
| 2026-11-23 | a socket directory others could write to was accepted, so a squatter could swap the socket | the purple-team run | refused at start; the client gained `expected_uid` (Step 6) |

## Ceilings code cannot fix

- The repository is one day old, with one maintainer. No second person has reviewed it.
- No outside user. Every consumer it was tested against has the same author.
- No independent implementation of the registry or log format exists. Phase 5 is the attempt.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 William N. King.
