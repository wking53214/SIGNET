# Key loss and compromise runbook, v1

Date: 2026-11-23. Decided by William N. King in review with Claude.
Rehearsed by `tests/test_key_recovery.py`: every case below is walked there with the same commands, and every gap named
here is asserted there, not skipped.

## What to know first

- **Purpose keys** (zeta, delta, and the other everyday signing keys) and the **log key** are replaceable from inside
  signet. Losing or leaking one is a routine job: the next registry fixes it.
- **The root key is not replaceable from inside signet.** Every checker pins the root public key in its own settings,
  out of band, and nothing in any file can move that pin. Losing or leaking the root means changing each pin by hand.
- So the root key gets the most care: kept offline, backed up twice, and never on the signer's machine
  (`signet serve` never loads it).

## Where the root is pinned today

Each of these must be changed by hand in a re-pin. Count them again whenever a checker is added.

1. CNS: the live signet check (`chains/signet_live.py`) and the CI that runs it.
2. Anyone running `signet check-checkpoint --root-key HEX`.
3. The outside anchor (`signet_anchor`, every command that takes `--root-key`).

HUMANITY does not pin the root; it only asks signet for signatures.

## Before anything goes wrong: back up the root

1. Copy the root key file to **two** offline places that cannot be lost together (for example two encrypted USB drives
   kept in different buildings). Never a cloud folder, never the signer's machine.
2. Write down, next to each copy, the root's key id and public key, and the number of the newest registry.
3. Once a year, check that each copy still reads (restore it to a scratch machine and write a throwaway registry).

## Case 1: a purpose key is lost

Signs: signet refuses to start and names the missing key file. Nothing has leaked.

1. Make a new key id for that purpose: `signet keygen --keys-dir DIR zeta-2`.
2. Put the new id in the config for that purpose.
3. Write the next registry: `signet registry --config CONFIG --out registry-N+1.json --previous registry-N.json
   --root-key HEX`.
4. Restart signet and hand checkers the new registry.

Done when: signet serves again and the new registry shows the new key as `current`.
What stays true: everything the lost key signed keeps checking, because it becomes `verify-only`.

## Case 2: a purpose key is stolen (or might be)

Treat "might be" as "is".

1. Steps 1 and 2 of case 1.
2. Write the next registry with the old key revoked in the same step: add `--revoke zeta-1`.
3. Restart signet, hand checkers the new registry, and publish it to the anchor.
4. Make every checker remember the new version number, so the old registry, where the stolen key still checks, is
   refused if someone replays it.

Done when: the stolen key's signatures fail under the new registry.
The cost: revoking ends **everything** that key signed, honest work included. List what it signed (signet's log has
every honest signature) and sign again what still matters.

## Case 3: the root key is lost

Signs: `signet registry` refuses because the root key file is missing. Until this is fixed nothing can be rotated or
revoked, so a purpose key stolen during this time cannot be stopped.

**With a backup (the normal case):**

1. Copy the backup back into the key directory, readable by signet's account only (`chmod 600`).
2. Write the next registry as usual to prove it works.

Done when: the next registry is written and checks under the same pin. No checker changes anything.
Afterwards, make a new second backup so there are two again.

**Without a backup:** this is a re-pin (see below), with one difference: the old root was lost, not stolen, so it
does not need revoking; it becomes `verify-only`.

## Case 4: the root key is stolen (or might be)

What the thief can do: write registries that every checker pinned to the old root accepts, with any version number and
any key made `current`. With a key they made current they can then sign anything for that purpose.

1. **Re-pin** (below), building the next registry from **your last legitimate registry**, never from one you did not
   write, and revoking the old root in it (`--revoke root-1`).
2. **Reset every checker's remembered version** along with its pin. A checker that saw the thief's registry (say
   version 50) would otherwise refuse your honest next one (version N+1).
3. **Find what the thief could have signed.** The root itself signs only registries, so:
   - any registry that is not in your own published sequence is the thief's;
   - any signature that checked during the window but has no matching entry in signet's log was not made by signet,
     because every honest signature is logged before it is released.
4. Sign again whatever honest work needs to stand under the new registry.

Done when: under the new pin the thief's registries are refused whatever version they claim, and the thief's keys are
not in your registry.

## The re-pin

1. Make a new root key id on the offline machine: `signet keygen --keys-dir DIR root-2`, and put it in the config as
   `registry_key_id`. Back it up twice before going on.
2. Write the next registry from the last legitimate one. `--root-key` is the **old** pin, which is only a public key, so
   this works even when the old root is lost: `signet registry --config CONFIG --out registry-N+1.json
   --previous registry-N.json --root-key OLD_HEX [--revoke root-1]`. It prints the new root public key.
3. Change the pin to the new root public key in every place listed under "Where the root is pinned today", and reset
   each one's remembered version.
4. **Start a new anchor directory.** The anchor checks every registry it holds against one pin and never removes a
   file, so the old anchor refuses everything after a re-pin. Publish the new registry into a fresh directory and keep
   the old one as frozen history, still readable under the old pin.

Done when: each checker loads the new registry under the new pin, and the new anchor holds it.

## Gaps this runbook does not close

- The root cannot be replaced from inside signet. Every re-pin is by hand, and it grows with every checker added.
- A checker that remembered a thief's version number refuses honest registries until someone resets it.
- The outside anchor does not follow a root change; a new anchor directory is the way out.
- While the root is lost with no backup, nothing can be revoked.
- Keys are files. A hardware key that cannot be copied is the real fix and is not built.
