"""The outside witness: a public transparency log (Sigstore's Rekor) that records each anchored checkpoint.

WHY IT EXISTS

An anchor directory protects nothing if the same account that runs signet can rewrite it. The witness is a party
signet's owner does not control: Rekor, a public, append-only log run by the Sigstore project. Each checkpoint file is
signed with a short-lived Sigstore certificate issued to a GitHub Actions workflow, and Rekor records that signature
with its own time (`integratedTime`) and a proof that the record is in its log. The result is a Sigstore bundle, kept
next to the checkpoint:

    <anchor>/checkpoints/000003.json
    <anchor>/witness/000003.sigstore.json

WHAT THE WITNESS GIVES, AND WHAT IT DOES NOT

  - It fixes WHEN a checkpoint existed, by a clock signet does not run. A rewritten history can be given a new chain
    of checkpoints, but not old Rekor times: anyone holding an earlier bundle, or its Rekor log index, sees the
    rewrite.
  - It cannot be removed. Deleting the bundle file from the anchor leaves the Rekor record.
  - It does NOT stop the owning account from witnessing a second, forked chain. Both would then be in Rekor for good;
    a checker holding either sees the other conflict. Keeping copies outside (CNS's CI, a reviewer) is what makes
    that conflict found rather than merely findable.
  - The signing identity is a workflow in signet's own repository. Rekor is what is independent, not the identity.

WHAT IS CHECKED HERE (`check_witnesses`), with no network:

  - every anchored checkpoint has a bundle (all but the newest `allow_pending`, which a scheduled job has not
    reached yet);
  - the bundle is a Sigstore bundle whose signed digest is SHA-256 of the checkpoint file's exact bytes, with one
    Rekor entry carrying an integrated time, a log index and an inclusion proof;
  - integrated times never go backwards along the checkpoints;
  - for a chained (schema 2) checkpoint, Rekor's time is not before signet's `at_ms` (less `skew_ms`), and, when
    `max_delay_ms` is set, not more than that after it (a checkpoint "signed" long before anyone saw it is one
    written later with an old time).

The cryptography (the certificate chain to Sigstore's root, the signature, the inclusion proof, the identity) is
checked by Sigstore's own verifier, `sigstore verify identity`, when `sigstore_identity` is given. It needs the
network and the `sigstore` package, so it runs in CI. Without the `sigstore` command, that step fails closed.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from signet.registry import Registry
from signet.strict import FormatError, loads

from .anchor import CHECKPOINTS, AnchorError, _read_checkpoints, latest_registry

WITNESS = "witness"
GITHUB_ISSUER = "https://token.actions.githubusercontent.com"
_MEDIA = "application/vnd.dev.sigstore.bundle"


@dataclass(frozen=True)
class Witnessed:
    log_index: int
    integrated_ms: int


def witness_path(anchor: Path, number: int) -> Path:
    return Path(anchor) / WITNESS / f"{number:06d}.sigstore.json"


def _witness_numbers(folder: Path) -> List[int]:
    if not folder.exists():
        return []
    out = []
    for path in sorted(folder.iterdir()):
        stem, _, ext = path.name.partition(".")
        if ext != "sigstore.json" or len(stem) != 6 or not stem.isdigit():
            raise AnchorError(f"{path} is not a numbered witness record (six digits, .sigstore.json)")
        out.append(int(stem))
    return out


def _dig(doc, *path):
    for key in path:
        if type(doc) is not dict or key not in doc:
            raise AnchorError(f"the bundle has no {'.'.join(path)}")
        doc = doc[key]
    return doc


def bundle_binding(bundle: bytes, checkpoint: bytes) -> Witnessed:
    """The Rekor record a bundle claims for exactly these checkpoint bytes, or AnchorError. Structure only."""
    try:
        doc = loads(bundle, max_bytes=1 << 20, max_depth=12)
    except FormatError as exc:
        raise AnchorError(f"the bundle is not strict JSON: {exc}") from None
    media = doc.get("mediaType")
    if type(media) is not str or not media.startswith(_MEDIA):
        raise AnchorError("not a Sigstore bundle")
    if _dig(doc, "messageSignature", "messageDigest", "algorithm") != "SHA2_256":
        raise AnchorError("the bundle does not sign a SHA-256 digest")
    try:
        digest = base64.b64decode(_dig(doc, "messageSignature", "messageDigest", "digest"), validate=True)
    except (ValueError, TypeError):
        raise AnchorError("the bundle's digest is not base64") from None
    if digest != hashlib.sha256(checkpoint).digest():
        raise AnchorError("the bundle witnesses other bytes than this checkpoint file")
    entries = _dig(doc, "verificationMaterial", "tlogEntries")
    if type(entries) is not list or len(entries) != 1:
        raise AnchorError("the bundle has no single Rekor entry")
    entry = entries[0]
    index, when = _dig(entry, "logIndex"), _dig(entry, "integratedTime")
    if type(index) is not str or not index.isdigit() or type(when) is not str or not when.isdigit():
        raise AnchorError("the Rekor entry's log index or integrated time is malformed")
    _dig(entry, "inclusionProof", "rootHash")
    return Witnessed(int(index), int(when) * 1000)


def sigstore_verify(bundle: Path, artifact: Path, identity: str, issuer: str = GITHUB_ISSUER,
                    command: Sequence[str] = ("sigstore",)) -> None:
    """Sigstore's own full verification of one bundle, or AnchorError. Needs the network and the sigstore package."""
    if shutil.which(command[0]) is None:
        raise AnchorError(f"the {command[0]!r} command is not installed, so the witness cannot be verified")
    done = subprocess.run([*command, "verify", "identity", "--bundle", str(bundle), "--cert-identity", identity,
                           "--cert-oidc-issuer", issuer, str(artifact)], capture_output=True, text=True, timeout=300)
    if done.returncode != 0:
        raise AnchorError(f"Sigstore refused {bundle.name}: {(done.stderr or done.stdout).strip()[-400:]}")


def check_witnesses(anchor: "str | Path", root_key: str, *, allow_pending: int = 0, skew_ms: int = 120_000,
                    max_delay_ms: Optional[int] = None, sigstore_identity: Optional[str] = None,
                    sigstore_issuer: str = GITHUB_ISSUER) -> List[str]:
    """Every problem with the anchor's witness records. Empty means each checkpoint (but the newest `allow_pending`)
    is witnessed by Rekor, in order, at a time that fits it."""
    anchor = Path(anchor)
    try:
        registry: Registry = latest_registry(anchor, root_key)
        checkpoints = _read_checkpoints(anchor, registry)
        known = set(_witness_numbers(anchor / WITNESS))
    except AnchorError as exc:
        return [str(exc)]
    problems: List[str] = []
    extra = sorted(known - set(range(1, len(checkpoints) + 1)))
    if extra:
        problems.append(f"witness records for checkpoints the anchor does not hold: {extra}")
    last: Optional[Witnessed] = None
    for number, (path, cp, raw) in enumerate(checkpoints, start=1):
        bundle = witness_path(anchor, number)
        if not bundle.exists():
            if number > len(checkpoints) - allow_pending:
                continue
            problems.append(f"{path.name}: no witness record: the checkpoint was never shown to Rekor")
            continue
        try:
            seen = bundle_binding(bundle.read_bytes(), raw)
        except AnchorError as exc:
            problems.append(f"{bundle.name}: {exc}")
            continue
        if last is not None and seen.integrated_ms < last.integrated_ms:
            problems.append(f"{bundle.name}: Rekor recorded it before the checkpoint it follows")
        if cp.at_ms is not None:
            if seen.integrated_ms + skew_ms < cp.at_ms:
                problems.append(f"{bundle.name}: Rekor recorded it before signet says it was signed")
            elif max_delay_ms is not None and seen.integrated_ms - cp.at_ms > max_delay_ms:
                problems.append(f"{bundle.name}: first witnessed {seen.integrated_ms - cp.at_ms} ms after signet says "
                                f"it was signed (limit {max_delay_ms}): an old time on a checkpoint written later")
        if sigstore_identity is not None:
            try:
                sigstore_verify(bundle, path, sigstore_identity, sigstore_issuer)
            except AnchorError as exc:
                problems.append(str(exc))
        last = seen
    return problems


__all__ = ["CHECKPOINTS", "WITNESS", "Witnessed", "bundle_binding", "check_witnesses", "sigstore_verify",
           "witness_path"]
