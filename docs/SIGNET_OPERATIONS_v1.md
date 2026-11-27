# SIGNET operations, v1

Date: 2026-11-27. How to deploy, watch, witness and recover. Key loss and compromise: `KEY_RECOVERY_v1.md`.

## Deploy (Linux with systemd)

Proven by CI job `separate accounts` on Ubuntu (EXECUTED there): the unit starts, signs for another account, reports
healthy and stops cleanly.

1. `sudo useradd --system --no-create-home --shell /usr/sbin/nologin signet`
2. Install signet where the `signet` account can read it, for example `sudo python3 -m pip install .` (use a virtual
   environment and change `ExecStart` if the system Python is managed).
3. As `signet`, make the keys: `sudo -u signet python3 -m signet keygen --keys-dir /var/lib/signet/keys ID` for the
   root, the log key and each purpose. Move the root key off the machine afterwards (runbook).
4. Write `/etc/signet/config.json` (root-owned, 0644): socket `/run/signet/signet.sock`, keys `/var/lib/signet/keys`,
   log `/var/lib/signet/signatures.log`, each purpose's `allowed_uids`. Optional limits: `max_connections` (64),
   `refusal_budget` (100 per account per minute), `min_free_bytes` (64 MiB).
5. `sudo install -m 0644 deploy/signet.service /etc/systemd/system/ && sudo systemctl daemon-reload && sudo systemctl
   enable --now signet`
6. Callers pass `expected_uid` (signet's account number) to the client, always.

The unit refuses to restart after exit 2 (a broken log or refused key): an operator must look.

**On the Chromebook.** Its Linux container has one account, so this separation is not available there (README, "On a
one-user machine"). Run signet in its own container or a second user inside the container if one can be added.

## Watch

- `sudo -u signet python3 -m signet status --config /etc/signet/config.json`: one JSON line, exit 1 when unhealthy
  (log does not verify, disk under the floor, a key refused, socket missing). Run it every few minutes from a timer or
  cron and alert on exit 1, or on `recent.suppressed` rising (someone is flooding).
- `python -m signet_anchor check --anchor DIR --root-key HEX --log LOG --max-unanchored N --max-age-ms T`: alert when
  publishing stalls.
- A failed run of the `witness` workflow is itself the alert; GitHub notifies the repository owner.

## Publish and witness

1. On the signer: `signet checkpoint --config CONFIG --out cN.json --previous c(N-1).json` (`--first` the first time).
2. In a working copy of the `anchor` branch: `python -m signet_anchor publish-checkpoint --anchor . --root-key HEX
   --checkpoint cN.json --log LOG`, then commit and push. Publish each new registry the same way with
   `publish-registry`.
3. The hourly `witness` workflow (from main) signs each new checkpoint with Sigstore, which records it in Rekor, checks
   every record, and pushes the records to the anchor branch. Set the repository variable `SIGNET_ROOT_KEY` to the
   pinned root public key first.
4. Anyone can re-check: `python -m signet_anchor check-witness --anchor . --root-key HEX --sigstore-identity
   https://github.com/wking53214/SIGNET/.github/workflows/witness.yml@refs/heads/main`, or look a record up at
   `https://search.sigstore.dev/?logIndex=N`.

Before relying on the anchor branch, confirm in the repository's Settings, Rules, that a ruleset blocking force pushes
and deletion applies to `anchor` with no bypass. GitHub's rules API listed none on 2026-11-27.

## Checkers

Load registries through `signet.trust.TrustStore` (`TrustStore.create` once, then `load` each time). Keep the memory
file with the checker's own state and back it up with it. A missing memory file stops the checker on purpose; after
a re-pin, start a new one by hand.

## Recover

| Event | Do |
|---|---|
| Disk full | Signatures fail closed (`log-failed`); free space; refusals were only counted below the floor |
| Torn last log line after a crash | Its signature was never released; remove the partial line after checking it, start again |
| Log does not verify | Stop. Compare with the anchor (`signet_anchor check`) and the witness; treat as compromise of signet's account |
| `busy` refusals | Someone holds the connections; find the account in the log's summary lines; raise `max_connections` only if real load |
| Key lost or stolen | `KEY_RECOVERY_v1.md` |
| Witness workflow failing | Read its log: a missing `SIGNET_ROOT_KEY`, a Rekor outage (retry), or a real mismatch (investigate as tampering) |

## Not yet operational

Log rotation, alert wiring, approver reload without restart, and any deployment under separate accounts outside CI.
