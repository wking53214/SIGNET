"""names: the rules for key ids, purpose names and purpose labels, shared by every module.

A KEY ID names one key, forever. It is 1 to 64 characters from A-Z a-z 0-9 . _ - and is never ":" (the signature
envelope is `key_id:signature`, so the first ":" ends the id). ASCII only, so one id cannot be spelled two ways.

A PURPOSE names one kind of thing signed, such as `zeta-lock-result`. Same character rules. Two purposes are
reserved for signet's own keys and can never be asked for over the socket: `signet-registry` (signs the registry)
and `signet-log` (signs log checkpoints).

A LABEL is the prefix every byte string signed for a purpose must start with, such as
`zeta-lock-result-signature/1\\n`. It is printable ASCII ending in a newline, 2 to 128 characters. The libraries
already put their label at the front of what they sign, so signet checking it means a key for one purpose cannot be
used to sign bytes meant for another.
"""

from __future__ import annotations

import re
from typing import Any

_NAME = re.compile(r"[A-Za-z0-9._-]{1,64}")

REGISTRY_PURPOSE = "signet-registry"
LOG_PURPOSE = "signet-log"
RESERVED_PURPOSES = frozenset({REGISTRY_PURPOSE, LOG_PURPOSE})

#: What signet itself signs: the registry body and a log checkpoint each start with their own label.
REGISTRY_LABEL = b"signet-registry/1\n"
CHECKPOINT_LABEL = b"signet-log-checkpoint/1\n"


def check_name(kind: str, value: Any) -> str:
    """`value` if it is a valid key id or purpose name (`kind` names which, for the message), else ValueError."""
    if type(value) is not str or not _NAME.fullmatch(value):
        raise ValueError(f"a {kind} is 1 to 64 characters from A-Z a-z 0-9 . _ - ; got {value!r}")
    return value


def check_label(value: Any) -> bytes:
    """The label as bytes if it is printable ASCII ending in one newline, 2 to 128 characters, else ValueError."""
    if type(value) is not str or not 2 <= len(value) <= 128 or not value.endswith("\n") \
            or not all(" " <= c <= "~" for c in value[:-1]):
        raise ValueError(f"a label is 2 to 128 printable ASCII characters ending in a newline; got {value!r}")
    return value.encode("ascii")
