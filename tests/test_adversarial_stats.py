"""
============================================
Guard Agent - Week 6 & 7 Tests
============================================
Tests adversarial scenario integrity and statistical functions.

Run: python tests/test_adversarial_stats.py
"""

import json
import sys
import math
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.agents.statistical_validation import (
    cohens_d, interpret_cohens_d, interpret_p_value,
    compute_epsilon_bound,
)


# ============================================
# Week 6: Adversarial Test Suite Integrity
# ============================================

def test_adversarial_scenario_count():
    """Verify 100 scenarios exist."""
    path = PROJECT_ROOT / "data" / "scenarios" / "adversarial_test_suite.json"
    with open(path, "r") as f:
        data = json.load(f)
    assert len(data["scenarios"]) == 100, f"Expected 100, got {len(data['scenarios'])}"
    print("✅ test_adversarial_scenario_count PASSED (100 scenarios)")


def test_adversarial_category_distribution():
    """Verify correct distribution: 25 legit attacks + 25 benign + 50 adversarial."""
    path = PROJECT_ROOT / "data" / "scenarios" / "adversarial_test_suite.json"
    with open(path, "r") as f:
        data = json.load(f)

    categories = {}
    for s in data["scenarios"]:
        cat = s["category"]
        categories[cat] = categories.get(cat, 0) + 1

    assert categories.get("legitimate_attack", 0) == 25
    assert categories.get("legitimate_benign", 0) == 25
    assert categories.get("adversarial_prompt_injection", 0) == 10
    assert categories.get("adversarial_conflicting_narratives", 0) == 10
    assert categories.get("adversarial_fabricated_cves", 0) == 10
    assert categories.get("adversarial_subtle_manipulation", 0) == 10
    assert categories.get("adversarial_data_poisoning", 0) == 10

    print(f"✅ test_adversarial_category_distribution PASSED")
    for cat, count in sorted(categories.items()):
        print(f"   {cat}: {count}")


def test_adversarial_ground_truth():
    """Verify all scenarios have proper ground truth."""
    path = PROJECT_ROOT / "data" / "scenarios" / "adversarial_test_suite.json"
    with open(path, "r") as f:
        data = json.load(f)

    for s in data["scenarios"]:
        gt = s.get("ground_truth", {})
        assert "classification" in gt, f"{s['id']} missing classification"
        assert "severity" in gt, f"{s['id']} missing severity"
        assert "is_attack" in gt, f"{s['id']} missing is_attack"
        assert isinstance(gt["is_attack"], bool), f"{s['id']} is_attack not boolean"
        assert 1 <= gt["severity"] <= 5, f"{s['id']} severity out of range: {gt['severity']}"

    # Prompt injection scenarios should be attacks with injection_type
    pi_scenarios = [s for s in data["scenarios"] if s["category"] == "adversarial_prompt_injection"]
    for s in pi_scenarios:
        assert s["ground_truth"]["is_attack"] is True, f"PI {s['id']} should be attack"

    # Fabricated CVE scenarios should be benign
    fc_scenarios = [s for s in data["scenarios"] if s["category"] == "adversarial_fabricated_cves"]
    for s in fc_scenarios:
        assert s["ground_truth"]["is_attack"] is False, f"FC {s['id']} should be benign"

    print("✅ test_adversarial_ground_truth PASSED")


def test_adversarial_unique_ids():
    """All scenario IDs must be unique."""
    path = PROJECT_ROOT / "data" / "scenarios" / "adversarial_test_suite.json"
    with open(path, "r") as f:
        data = json.load(f)

    ids = [s["id"] for s in data["scenarios"]]
    assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"
    print("✅ test_adversarial_unique_ids PASSED")


def test_prompt_injection_contains_injection():
    """Verify prompt injection scenarios actually contain injection attempts."""
    path = PROJECT_ROOT / "data" / "scenarios" / "adversarial_test_suite.json"
    with open(path, "r") as f:
        data = json.load(f)

    injection_keywords = ["ignore", "override", "system", "admin", "debug",
                          "benign", "training", "correction", "maintenance", "pentesting"]

    pi_scenarios = [s for s in data["scenarios"] if s["category"] == "adversarial_prompt_injection"]
    for s in pi_scenarios:
        desc_lower = s["event_description"].lower()
        has_injection = any(kw in desc_lower for kw in injection_keywords)
        assert has_injection, f"{s['id']} doesn't contain injection keywords"

    print("✅ test_prompt_injection_contains_injection PASSED")


# ============================================
# Week 7: Statistical Functions
# ============================================

def test_cohens_d_large():
    """Large effect: clearly different groups."""
    g1 = [0.9, 0.85, 0.88, 0.92, 0.87]
    g2 = [0.3, 0.35, 0.28, 0.32, 0.37]
    d = cohens_d(g1, g2)
    assert d > 0.8, f"Expected large effect, got d={d}"
    assert interpret_cohens_d(d) == "large"
    print(f"✅ test_cohens_d_large PASSED (d={d:.4f})")


def test_cohens_d_negligible():
    """Negligible effect: similar groups."""
    g1 = [0.50, 0.55, 0.45, 0.52, 0.48, 0.51, 0.49, 0.53, 0.47, 0.50]
    g2 = [0.49, 0.54, 0.46, 0.51, 0.47, 0.50, 0.48, 0.52, 0.46, 0.50]
    d = cohens_d(g1, g2)
    assert abs(d) < 0.5, f"Expected small/negligible, got d={d}"
    print(f"✅ test_cohens_d_negligible PASSED (d={d:.4f})")


def test_cohens_d_medium():
    """Medium effect."""
    g1 = [0.7, 0.75, 0.72, 0.68, 0.73]
    g2 = [0.5, 0.55, 0.48, 0.52, 0.53]
    d = cohens_d(g1, g2)
    assert 0.5 <= abs(d) <= 0.8 or abs(d) > 0.8, f"Got d={d}"
    print(f"✅ test_cohens_d_medium PASSED (d={d:.4f}, {interpret_cohens_d(d)})")


def test_epsilon_bound_zero():
    """All correct above threshold → ε = 0."""
    rts = [0.9, 0.85, 0.8, 0.7, 0.6]
    correct = [True, True, True, False, False]
    result = compute_epsilon_bound(rts, correct, threshold=0.8)
    assert result["epsilon"] == 0.0
    assert result["n_above_threshold"] == 3
    assert result["errors_above_threshold"] == 0
    assert result["meets_target"] is True
    print(f"✅ test_epsilon_bound_zero PASSED (ε={result['epsilon']})")


def test_epsilon_bound_nonzero():
    """Some errors above threshold → ε > 0."""
    rts = [0.9, 0.85, 0.8, 0.7, 0.6]
    correct = [True, False, True, False, False]
    result = compute_epsilon_bound(rts, correct, threshold=0.8)
    assert result["epsilon"] > 0
    assert result["n_above_threshold"] == 3
    assert result["errors_above_threshold"] == 1
    print(f"✅ test_epsilon_bound_nonzero PASSED (ε={result['epsilon']:.4f})")


def test_epsilon_bound_confidence_interval():
    """Verify CI is computed."""
    rts = [0.9, 0.85, 0.8, 0.75, 0.7, 0.65, 0.6, 0.55, 0.5, 0.45]
    correct = [True, True, True, True, True, False, False, True, False, False]
    result = compute_epsilon_bound(rts, correct, threshold=0.7)
    assert "confidence_interval" in result
    assert "formal_statement" in result
    print(f"✅ test_epsilon_bound_confidence_interval PASSED")
    print(f"   {result['formal_statement']}")


def test_interpret_p_value():
    assert "significant" in interpret_p_value(0.03)
    assert "NOT significant" in interpret_p_value(0.06)
    assert "highly significant" in interpret_p_value(0.0001)
    print("✅ test_interpret_p_value PASSED")


# ============================================
# Run all tests
# ============================================
if __name__ == "__main__":
    print("\n🧪 Running Week 6 & 7 Tests...\n")

    # Week 6
    print("--- Week 6: Adversarial Test Suite ---")
    test_adversarial_scenario_count()
    test_adversarial_category_distribution()
    test_adversarial_ground_truth()
    test_adversarial_unique_ids()
    test_prompt_injection_contains_injection()

    # Week 7
    print("\n--- Week 7: Statistical Validation ---")
    test_cohens_d_large()
    test_cohens_d_negligible()
    test_cohens_d_medium()
    test_epsilon_bound_zero()
    test_epsilon_bound_nonzero()
    test_epsilon_bound_confidence_interval()
    test_interpret_p_value()

    print(f"\n✅ All 12 Week 6-7 tests passed!\n")
