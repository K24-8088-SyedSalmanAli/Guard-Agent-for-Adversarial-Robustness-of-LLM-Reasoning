"""
============================================
Guard Agent - Week 5 Tests
============================================
Tests for Stability Score S(O) and Full RTS.
All tests work WITHOUT Ollama.

Run: python tests/test_stability_rts.py
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.output_parser import ThreatAssessment
from src.agents.guard_stability import (
    PerturbationEngine,
    compute_classification_drift,
    compute_severity_drift,
    compute_technique_drift,
    compute_overall_drift,
    compute_stability_score,
)
from src.agents.guard_agent import (
    compute_rts,
    make_decision,
    calibrate_threshold,
    calibrate_weights,
)


def make_assessment(classification, severity, confidence, technique_ids):
    """Helper."""
    return ThreatAssessment(
        threat_classification=classification,
        severity_level=severity,
        confidence=confidence,
        mitre_attack_techniques=[
            {"technique_id": t, "technique_name": "", "tactic": "", "relevance": ""}
            for t in technique_ids
        ],
        parse_success=True,
    )


# ============================================
# PERTURBATION ENGINE TESTS
# ============================================

def test_perturbation_engine():
    engine = PerturbationEngine(seed=42)
    scenario = {
        "id": "SC-001",
        "event_description": "Email requesting bank account change. Domain mismatch detected. Payment of $2.3M at risk.",
        "timestamp": "2025-03-15T14:23:00Z",
        "source_org": "AutoCorp",
        "event_type": "Email Anomaly",
        "data_source": "Email Gateway",
    }
    perturbations = engine.generate_perturbations(scenario, 4)
    assert len(perturbations) == 4

    types = [p[0] for p in perturbations]
    assert "paraphrase" in types
    assert "field_reorder" in types
    assert "noise_injection" in types
    assert "value_tweak" in types

    # Verify perturbations actually changed the input
    for ptype, perturbed in perturbations:
        assert perturbed["event_description"] != scenario["event_description"] or ptype == "field_reorder"
        assert perturbed["source_org"] == scenario["source_org"]  # Should not change org

    print("✅ test_perturbation_engine PASSED")


def test_perturbation_value_tweak():
    engine = PerturbationEngine(seed=42)
    scenario = {
        "id": "SC-001",
        "event_description": "Payment of $2,300,000 requested.",
        "timestamp": "2025-03-15T14:23:00Z",
        "source_org": "Corp", "event_type": "Test", "data_source": "Test",
    }
    perturbations = engine.generate_perturbations(scenario, 4)
    value_tweak = next(p for ptype, p in perturbations if ptype == "value_tweak")
    # Timestamp should be shifted
    assert value_tweak["timestamp"] != scenario["timestamp"]
    print("✅ test_perturbation_value_tweak PASSED")


# ============================================
# DRIFT TESTS
# ============================================

def test_classification_drift_same():
    a = make_assessment("BEC Payment Fraud", 5, 0.9, ["T1566"])
    b = make_assessment("BEC Payment Fraud", 4, 0.8, ["T1078"])
    assert compute_classification_drift(a, b) == 0.0
    print("✅ test_classification_drift_same PASSED")


def test_classification_drift_different():
    a = make_assessment("BEC Payment Fraud", 5, 0.9, ["T1566"])
    b = make_assessment("Phishing", 4, 0.8, ["T1566"])
    assert compute_classification_drift(a, b) == 1.0
    print("✅ test_classification_drift_different PASSED")


def test_severity_drift_same():
    a = make_assessment("BEC", 5, 0.9, [])
    b = make_assessment("BEC", 5, 0.8, [])
    assert compute_severity_drift(a, b) == 0.0
    print("✅ test_severity_drift_same PASSED")


def test_severity_drift_max():
    a = make_assessment("BEC", 1, 0.9, [])
    b = make_assessment("BEC", 5, 0.8, [])
    assert compute_severity_drift(a, b) == 1.0
    print("✅ test_severity_drift_max PASSED")


def test_technique_drift_same():
    a = make_assessment("BEC", 5, 0.9, ["T1566", "T1534"])
    b = make_assessment("BEC", 5, 0.9, ["T1566", "T1534"])
    assert compute_technique_drift(a, b) == 0.0
    print("✅ test_technique_drift_same PASSED")


def test_technique_drift_partial():
    a = make_assessment("BEC", 5, 0.9, ["T1566", "T1534"])
    b = make_assessment("BEC", 5, 0.9, ["T1566", "T1078"])
    drift = compute_technique_drift(a, b)
    assert 0 < drift < 1
    print(f"✅ test_technique_drift_partial PASSED (drift={drift:.4f})")


def test_technique_drift_complete():
    a = make_assessment("BEC", 5, 0.9, ["T1566"])
    b = make_assessment("BEC", 5, 0.9, ["T1078"])
    assert compute_technique_drift(a, b) == 1.0
    print("✅ test_technique_drift_complete PASSED")


def test_overall_drift_stable():
    a = make_assessment("BEC Payment Fraud", 5, 0.9, ["T1566.002"])
    b = make_assessment("BEC Payment Fraud", 5, 0.85, ["T1566.002"])
    drift = compute_overall_drift(a, b)
    assert drift["overall_drift"] == 0.0
    print("✅ test_overall_drift_stable PASSED")


def test_overall_drift_unstable():
    a = make_assessment("BEC Payment Fraud", 5, 0.9, ["T1566"])
    b = make_assessment("Ransomware", 1, 0.3, ["T1486"])
    drift = compute_overall_drift(a, b)
    assert drift["overall_drift"] > 0.8
    print(f"✅ test_overall_drift_unstable PASSED (drift={drift['overall_drift']:.4f})")


# ============================================
# STABILITY SCORE TESTS
# ============================================

def test_stability_score_perfect():
    a = make_assessment("BEC", 5, 0.9, ["T1566"])
    drifts = []
    for _ in range(4):
        b = make_assessment("BEC", 5, 0.85, ["T1566"])
        drifts.append(compute_overall_drift(a, b))
    result = compute_stability_score(drifts)
    assert result["stability_score"] == 1.0
    print("✅ test_stability_score_perfect PASSED")


def test_stability_score_unstable():
    a = make_assessment("BEC", 5, 0.9, ["T1566"])
    drifts = [
        compute_overall_drift(a, make_assessment("Phishing", 3, 0.5, ["T1078"])),
        compute_overall_drift(a, make_assessment("Ransomware", 1, 0.3, ["T1486"])),
        compute_overall_drift(a, make_assessment("DDoS", 4, 0.7, ["T1498"])),
        compute_overall_drift(a, make_assessment("Insider Threat", 2, 0.4, ["T1078"])),
    ]
    result = compute_stability_score(drifts)
    assert result["stability_score"] < 0.3
    print(f"✅ test_stability_score_unstable PASSED (S={result['stability_score']:.4f})")


# ============================================
# RTS TESTS
# ============================================

def test_rts_computation():
    result = compute_rts(c_score=0.8, v_score=0.9, s_score=0.7)
    expected = (1/3) * 0.8 + (1/3) * 0.9 + (1/3) * 0.7
    assert abs(result["rts_score"] - round(expected, 4)) < 0.001
    assert result["components"]["C_O"] == 0.8
    assert result["components"]["V_O"] == 0.9
    assert result["components"]["S_O"] == 0.7
    print(f"✅ test_rts_computation PASSED (RTS={result['rts_score']})")


def test_rts_custom_weights():
    result = compute_rts(c_score=1.0, v_score=0.0, s_score=0.0, alpha=1.0, beta=0.0, gamma=0.0)
    assert result["rts_score"] == 1.0
    result2 = compute_rts(c_score=0.0, v_score=1.0, s_score=0.0, alpha=0.0, beta=1.0, gamma=0.0)
    assert result2["rts_score"] == 1.0
    print("✅ test_rts_custom_weights PASSED")


def test_rts_perfect():
    result = compute_rts(c_score=1.0, v_score=1.0, s_score=1.0)
    assert result["rts_score"] == 1.0
    print("✅ test_rts_perfect PASSED")


def test_rts_zero():
    result = compute_rts(c_score=0.0, v_score=0.0, s_score=0.0)
    assert result["rts_score"] == 0.0
    print("✅ test_rts_zero PASSED")


# ============================================
# DECISION TESTS
# ============================================

def test_decision_autonomous():
    decision = make_decision(rts_score=0.85, threshold=0.7)
    assert decision["decision"] == "AUTONOMOUS"
    assert decision["margin"] == 0.15
    print("✅ test_decision_autonomous PASSED")


def test_decision_human():
    decision = make_decision(rts_score=0.55, threshold=0.7)
    assert decision["decision"] == "HUMAN_REVIEW"
    assert decision["deficit"] == 0.15
    print("✅ test_decision_human PASSED")


def test_decision_boundary():
    decision = make_decision(rts_score=0.7, threshold=0.7)
    assert decision["decision"] == "AUTONOMOUS"
    print("✅ test_decision_boundary PASSED")


# ============================================
# CALIBRATION TESTS
# ============================================

def test_threshold_calibration():
    rts_scores = [0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5, 0.45]
    correctness = [True, True, True, True, True, False, False, True, False, False]

    result = calibrate_threshold(rts_scores, correctness)
    assert "optimal_threshold" in result
    assert "all_thresholds" in result
    assert len(result["all_thresholds"]) > 0
    # At τ=0.7, scenarios above are [0.9, 0.85, 0.8, 0.75, 0.7] — all correct
    print(f"✅ test_threshold_calibration PASSED (optimal_τ={result['optimal_threshold']})")


def test_weight_calibration():
    c_scores = [0.9, 0.8, 0.5, 0.3]
    v_scores = [0.95, 0.9, 0.6, 0.4]
    s_scores = [0.85, 0.7, 0.4, 0.2]
    correctness = [True, True, False, False]

    result = calibrate_weights(c_scores, v_scores, s_scores, correctness)
    assert "best_weights" in result
    assert "best_gap" in result
    assert result["best_gap"] > 0
    bw = result["best_weights"]
    assert abs(bw["alpha"] + bw["beta"] + bw["gamma"] - 1.0) < 0.01
    print(f"✅ test_weight_calibration PASSED (gap={result['best_gap']:.4f}, weights={bw})")


def test_rts_output_structure():
    result = compute_rts(0.7, 0.8, 0.9)
    required = ["rts_score", "components", "weights", "weighted_contributions"]
    for key in required:
        assert key in result, f"Missing: {key}"
    assert "C_O" in result["components"]
    assert "V_O" in result["components"]
    assert "S_O" in result["components"]
    print("✅ test_rts_output_structure PASSED")


# ============================================
# Run all tests
# ============================================
if __name__ == "__main__":
    print("\n🧪 Running Week 5 Tests...\n")

    # Perturbation Engine
    test_perturbation_engine()
    test_perturbation_value_tweak()

    # Drift Metrics
    test_classification_drift_same()
    test_classification_drift_different()
    test_severity_drift_same()
    test_severity_drift_max()
    test_technique_drift_same()
    test_technique_drift_partial()
    test_technique_drift_complete()
    test_overall_drift_stable()
    test_overall_drift_unstable()

    # Stability Score
    test_stability_score_perfect()
    test_stability_score_unstable()

    # RTS
    test_rts_computation()
    test_rts_custom_weights()
    test_rts_perfect()
    test_rts_zero()

    # Decisions
    test_decision_autonomous()
    test_decision_human()
    test_decision_boundary()

    # Calibration
    test_threshold_calibration()
    test_weight_calibration()
    test_rts_output_structure()

    print(f"\n✅ All 23 Week 5 tests passed!\n")
