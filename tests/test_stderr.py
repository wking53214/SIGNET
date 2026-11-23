"""A closed stderr does not cost a caller its answer.

Found by the Rust client's interop test: a supervisor that read signet's "serving" line and then closed the pipe made
every REFUSAL fail, because signet printed the refusal before answering and the print raised. The caller got no reply
at all instead of the refusal code. Fail closed, but the caller could not tell a wrong label from signet being down.
"""

from __future__ import annotations

import pytest

from signet.client import SignetRefused, request
from instance import Instance


def test_a_refusal_still_arrives_after_stderr_is_closed(tmp_path):
    inst = Instance(tmp_path).start()
    try:
        inst.proc.stderr.close()
        for _ in range(3):
            with pytest.raises(SignetRefused) as caught:
                request(inst.socket, "zeta-lock-result", b"not labelled")
            assert caught.value.code == "wrong-label"
        assert [line["outcome"] for line in inst.log_lines()].count("refused") == 3
    finally:
        inst.kill()
