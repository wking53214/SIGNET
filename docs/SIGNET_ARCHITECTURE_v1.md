# SIGNET architecture, v1

Date: 2026-11-27. How the pieces fit after the RACE 9.5 run. The README stays the full description of the signer.

## The parts and who may load them

| Part | Side | Job |
|---|---|---|
| `signet.server`, `signet.keys`, `signet.log`, `signet.config` | signer only | hold keys, decide each request, write the hash-chained log, read the config |
| `signet.client` | caller | ask for a signature over the socket; fail closed |
| `signet.registry`, `signet.verify` | checker | read the signed key list; check signatures and checkpoints |
| `signet.trust` (new) | checker | remember accepted registries: refuse rollback, forks, resurrection, jumps |
| `signet_anchor` (+ `witness`, new) | checker | keep registries and checkpoints where the signer cannot rewrite them; check the Rekor witness records |
| `rust/signet-client` | caller | the Rust twin of `signet.client` (HUMANITY uses it) |
| `rust/signet-verify` (new) | checker | an independent verifier sharing no code with signet |

The rule (CLAUDE.md 3): caller- and checker-side code never loads signer-side code. `tests/test_boundary.py` holds it
for the original modules; `tests/test_trust.py` holds it for `signet.trust`; `signet_anchor` has its own test.

## Trust flow

```text
 caller account            signet account                        outside SIGNET's control
 --------------            --------------                        ------------------------
 sign(data) --socket-->  SO_PEERCRED uid -> purpose -> label
                         -> approvals (quorum >= 2) -> key.sign
                         -> log line, fsync -> answer
                         log --checkpoint (schema 2, chained)--> anchor branch --CI--> Rekor (public, append-only)
 checker:  registry --TrustStore--> verifier(purpose) --> True/False
           anchor + witness records --signet_anchor / signet-verify--> history holds or names the break
```

## Formats (all additive; old ones still read)

| Format | Schema | New in this run |
|---|---|---|
| Registry | `signet-registry/1` | none |
| Log line | fields in `signet.log` | optional `suppressed` on summary lines |
| Checkpoint | `signet-log-checkpoint/1` and `/2` | `/2`: `at_ms`, `previous` (SHA-256 of the previous checkpoint file) |
| Checker memory | `signet-trust-state/1` | new |
| Witness record | a Sigstore bundle, `witness/NNNNNN.sigstore.json` | new |
| Refusal codes | protocol | `busy` |
| Test vectors | `signet-vectors/1` | new, `docs/vectors/` |

## Design decisions in this run, with the reason

| Decision | Reason |
|---|---|
| Witness is Rekor through Sigstore keyless signing in GitHub Actions (owner's choice A) | A party the owner does not control, publicly checkable, not a blockchain, no second account |
| The cryptographic check of a witness is Sigstore's own verifier, run in CI | Re-implementing certificate and inclusion-proof checks would add risk; `signet_anchor` checks the binding, order and time itself |
| Checker memory is opt-in (`TrustStore`), `load_registry` unchanged | Preserve every existing caller; a missing memory file stops the checker rather than silently resetting |
| Signatures are never throttled; refusals are | A signature that is not logged must never be released; refusals carry no authority |
| `busy` is answered by the listening thread | No thread is made for a connection over the cap |
| No key-provider interface added | No real device to test against in this run; an untested seam would be decorative (mission rule) |
