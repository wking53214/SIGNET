"""signet plugged into the real libraries, at the commits the CNS spine manifest names (pinned in the dev extra).

The point of these tests: zeta, beta and delta are NOT changed. zeta takes `signer=`, beta takes
`lock_result_signer=` and `lock_result_verifier=`, delta's `sign_receipt` takes a `sign` callable. signet's client and
verifier are dropped into those slots, signet runs as its own process, and the libraries never see a key.
"""

from datetime import datetime

import pytest

from instance import Instance
from signet.client import SignetRefused, signer
from signet.registry import load_registry
from signet.verify import verifier

from beta import DecisionEngine, DecisionRule, DecisionRuleRegistry, LockResultSignatureError, lock_result_signature_ok
from delta.signing import sign_receipt, verify_receipt_signature
from zeta import Combination, Key, KeySet, LockRegistry, LockSpec
from zeta.signing import LOCK_RESULT_SIGNATURE_DOMAIN

T0 = datetime(2026, 11, 23, 8, 0, 0)


def engine(**options):
    locks = LockRegistry([LockSpec(lock_id="sepsis_lock", required_keys=("septic_shock",), combination=Combination.OR,
                                   dwell_threshold=1)])
    rules = DecisionRuleRegistry([
        DecisionRule(decision_id="escalate", decision="ESCALATE", open_locks=("sepsis_lock",), priority=10,
                     reasoning_template="{decision}", instructions="Now."),
        DecisionRule(decision_id="safe", decision="SAFE", closed_locks=("sepsis_lock",), priority=0,
                     reasoning_template="{decision}", instructions="Fine."),
    ])
    return DecisionEngine(rules, locks, **options)


SICK = KeySet([Key("septic_shock", True)])


@pytest.fixture
def live(tmp_path):
    inst = Instance(tmp_path).start()
    yield inst
    inst.stop()


def test_the_label_signet_is_configured_with_is_zetas_own():
    from instance import ZETA_LABEL
    assert ZETA_LABEL.encode() == LOCK_RESULT_SIGNATURE_DOMAIN


def test_zeta_signs_through_signet_and_beta_checks_through_the_registry(live):
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    check = verifier(reg, "zeta-lock-result")
    e = engine(lock_result_signer=signer(live.socket, "zeta-lock-result"), lock_result_verifier=check)
    evaluated = e.evaluate_and_decide("patient_1", SICK, T0)
    assert evaluated.decision.decision == "ESCALATE"
    assert all(lock_result_signature_ok(r, check) for r in evaluated.lock_results.values())
    assert engine().evaluate_and_decide("patient_1", SICK, T0).decision == evaluated.decision
    signed = [line for line in live.log_lines() if line["outcome"] == "signed"]
    assert [line["purpose"] for line in signed] == ["zeta-lock-result"]


def test_a_lock_result_signed_by_another_signet_is_refused_by_beta(live, tmp_path_factory):
    stranger = Instance(tmp_path_factory.mktemp("stranger")).start()
    try:
        reg = load_registry(live.registry().read_bytes(), live.root_key())
        e = engine(lock_result_signer=signer(stranger.socket, "zeta-lock-result"),
                   lock_result_verifier=verifier(reg, "zeta-lock-result"))
        before = e.state_store.snapshot("patient_1")
        with pytest.raises(LockResultSignatureError):
            e.evaluate_and_decide("patient_1", SICK, T0)
        assert e.state_store.snapshot("patient_1") == before
    finally:
        stranger.stop()


def test_when_signet_refuses_beta_makes_no_decision_and_puts_lock_state_back(live):
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    e = engine(lock_result_signer=signer(live.socket, "delta-receipt"),  # the wrong purpose: zeta's label is refused
               lock_result_verifier=verifier(reg, "zeta-lock-result"))
    before = e.state_store.snapshot("patient_1")
    with pytest.raises(SignetRefused) as caught:
        e.evaluate_and_decide("patient_1", SICK, T0)
    assert caught.value.code == "wrong-label"
    assert e.state_store.snapshot("patient_1") == before


def test_when_signet_is_down_beta_makes_no_decision(live):
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    sign = signer(live.socket, "zeta-lock-result")
    live.stop()
    e = engine(lock_result_signer=sign, lock_result_verifier=verifier(reg, "zeta-lock-result"))
    before = e.state_store.snapshot("patient_1")
    with pytest.raises(Exception) as caught:
        e.evaluate_and_decide("patient_1", SICK, T0)
    assert type(caught.value).__name__ == "SignetUnavailable"
    assert e.state_store.snapshot("patient_1") == before


def receipt():
    return {"schema": "delta-ledger-receipt/1", "entry_digest": "a" * 64, "entry_hash": "b" * 64,
            "previous_hash": "c" * 64, "ledger_head": "b" * 64, "checkpoint_head": "c" * 64, "index": 3,
            "ledger_length": 4, "checkpoint_length": 3,
            "context": {"schema": "delta-context/1", "entity_id": "patient_1", "event_id": "e1", "run_id": "r1"}}


def test_delta_receipts_sign_through_signet_and_check_through_the_registry(live):
    reg = load_registry(live.registry().read_bytes(), live.root_key())
    check = verifier(reg, "delta-receipt")
    signature = sign_receipt(receipt(), signer(live.socket, "delta-receipt"))
    assert verify_receipt_signature(receipt(), signature, check) is True
    edited = {**receipt(), "index": 2}
    assert verify_receipt_signature(edited, signature, check) is False
    assert verify_receipt_signature(receipt(), signature, verifier(reg, "zeta-lock-result")) is False


def test_the_zeta_key_cannot_sign_a_delta_receipt(live):
    with pytest.raises(SignetRefused) as caught:
        sign_receipt(receipt(), signer(live.socket, "zeta-lock-result"))
    assert caught.value.code == "wrong-label"
