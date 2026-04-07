import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.output_parser import ThreatAssessment
from src.agents.guard_validation import (
    MitreValidator,
    validate_evidence_chain,
    compute_validation_score,
)


class MockValidator:
    """Mock validator with a small set of known techniques."""

    def __init__(self):
        self.technique_lookup = {
            "T1566": {"name": "Phishing", "tactics": ["Initial Access"], "is_subtechnique": False},
            "T1566.001": {"name": "Spearphishing Attachment", "tactics": ["Initial Access"], "is_subtechnique": True},
            "T1566.002": {"name": "Spearphishing Link", "tactics": ["Initial Access"], "is_subtechnique": True},
            "T1534": {"name": "Internal Spearphishing", "tactics": ["Lateral Movement"], "is_subtechnique": False},
            "T1486": {"name": "Data Encrypted for Impact", "tactics": ["Impact"], "is_subtechnique": False},
            "T1565": {"name": "Data Manipulation", "tactics": ["Impact"], "is_subtechnique": False},
            "T1565.001": {"name": "Stored Data Manipulation", "tactics": ["Impact"], "is_subtechnique": True},
            "T1078": {"name": "Valid Accounts", "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"], "is_subtechnique": False},
            "T1110": {"name": "Brute Force", "tactics": ["Credential Access"], "is_subtechnique": False},
            "T1498": {"name": "Network Denial of Service", "tactics": ["Impact"], "is_subtechnique": False},
            "T1133": {"name": "External Remote Services", "tactics": ["Persistence", "Initial Access"], "is_subtechnique": False},
            "T1657": {"name": "Financial Theft", "tactics": ["Impact"], "is_subtechnique": False},
        }
        self.valid_technique_ids = set(self.technique_lookup.keys())
        self.tactic_lookup = {}

    def validate_technique_id(self, technique_id):
        if technique_id in self.valid_technique_ids:
            info = self.technique_lookup[technique_id]
            return {
                "technique_id": technique_id, "format_valid": True, "exists": True,
                "ground_truth_name": info["name"], "ground_truth_tactics": info["tactics"],
            }
        import re
        format_valid = bool(re.match(r'^T\d{4}(\.\d{3})?$', str(technique_id)))
        return {
            "technique_id": technique_id, "format_valid": format_valid, "exists": False,
            "error": "HALLUCINATED_ID" if format_valid else "INVALID_FORMAT",
        }

    def validate_technique_name(self, technique_id, claimed_name):
        if technique_id not in self.valid_technique_ids:
            return {"valid": False, "error": "ID not found", "similarity": 0.0}
        real_name = self.technique_lookup[technique_id]["name"]
        from difflib import SequenceMatcher
        sim = SequenceMatcher(None, claimed_name.lower(), real_name.lower()).ratio()
        return {
            "valid": sim >= 0.7, "real_name": real_name, "claimed_name": claimed_name,
            "similarity": round(sim, 4), "match_type": "exact" if sim == 1.0 else "fuzzy" if sim >= 0.7 else "mismatch",
        }

    def validate_tactic(self, technique_id, claimed_tactic):
        if technique_id not in self.valid_technique_ids:
            return {"valid": False, "error": "ID not found"}
        real_tactics = self.technique_lookup[technique_id]["tactics"]
        for rt in real_tactics:
            if claimed_tactic.strip().lower() == rt.strip().lower():
                return {"valid": True, "claimed_tactic": claimed_tactic, "real_tactics": real_tactics}
        return {"valid": False, "claimed_tactic": claimed_tactic, "real_tactics": real_tactics, "error": "WRONG_TACTIC"}


def make_assessment(classification, severity, confidence, techniques, indicators=None, reasoning="", actions=None):
    """Helper to create ThreatAssessment with techniques."""
    return ThreatAssessment(
        threat_classification=classification,
        severity_level=severity,
        confidence=confidence,
        mitre_attack_techniques=techniques,
        detected_indicators=indicators or ["Suspicious domain mismatch detected", "Urgency language in email"],
        reasoning_chain=reasoning or "Step 1: Domain mismatch found. Step 2: Mapped to phishing. Step 3: High severity due to financial impact.",
        recommended_actions=actions or [{"action": "Block payment", "priority": "immediate", "rationale": "Prevent financial loss"}],
        parse_success=True,
    )


# ============================================
# Test ID Validation
# ============================================

def test_id_valid_existing():
    v = MockValidator()
    result = v.validate_technique_id("T1566.002")
    assert result["exists"] is True
    assert result["ground_truth_name"] == "Spearphishing Link"
    print("✅ test_id_valid_existing PASSED")


def test_id_valid_hallucinated():
    v = MockValidator()
    result = v.validate_technique_id("T9999")
    assert result["exists"] is False
    assert result["error"] == "HALLUCINATED_ID"
    print("✅ test_id_valid_hallucinated PASSED")


def test_id_valid_bad_format():
    v = MockValidator()
    result = v.validate_technique_id("FAKE123")
    assert result["exists"] is False
    assert result["error"] == "INVALID_FORMAT"
    print("✅ test_id_valid_bad_format PASSED")


# ============================================
# Test Name Validation
# ============================================

def test_name_exact_match():
    v = MockValidator()
    result = v.validate_technique_name("T1566.002", "Spearphishing Link")
    assert result["valid"] is True
    assert result["similarity"] == 1.0
    print("✅ test_name_exact_match PASSED")


def test_name_fuzzy_match():
    v = MockValidator()
    result = v.validate_technique_name("T1566.002", "Spearphishing Links")  # slight variation
    assert result["valid"] is True
    assert result["similarity"] >= 0.7
    print(f"✅ test_name_fuzzy_match PASSED (sim={result['similarity']})")


def test_name_wrong():
    v = MockValidator()
    result = v.validate_technique_name("T1566.002", "Ransomware Attack")
    assert result["valid"] is False
    assert result["similarity"] < 0.7
    print(f"✅ test_name_wrong PASSED (sim={result['similarity']})")


# ============================================
# Test Tactic Validation
# ============================================

def test_tactic_correct():
    v = MockValidator()
    result = v.validate_tactic("T1566.002", "Initial Access")
    assert result["valid"] is True
    print("✅ test_tactic_correct PASSED")


def test_tactic_wrong():
    v = MockValidator()
    result = v.validate_tactic("T1566.002", "Impact")  # Wrong tactic for phishing
    assert result["valid"] is False
    assert result["error"] == "WRONG_TACTIC"
    print("✅ test_tactic_wrong PASSED")


def test_tactic_multi_tactic_technique():
    v = MockValidator()
    # T1078 (Valid Accounts) has 4 tactics
    result1 = v.validate_tactic("T1078", "Defense Evasion")
    result2 = v.validate_tactic("T1078", "Initial Access")
    assert result1["valid"] is True
    assert result2["valid"] is True
    print("✅ test_tactic_multi_tactic_technique PASSED")


# ============================================
# Test Evidence Chain
# ============================================

def test_chain_complete():
    assessment = make_assessment(
        "BEC Payment Fraud", 5, 0.92,
        [{"technique_id": "T1566.002", "technique_name": "Spearphishing Link",
          "tactic": "Initial Access", "relevance": "Email with domain mismatch targets accounts payable"}],
        indicators=["Domain mismatch: techparts-inc.com vs techparts.com", "Urgency language in email body"],
        reasoning="Step 1: Identified domain mismatch. Step 2: Mapped to T1566.002. Step 3: High severity due to $2.3M.",
        actions=[{"action": "Block payment immediately", "priority": "immediate", "rationale": "Prevent $2.3M loss"}],
    )
    result = validate_evidence_chain(assessment)
    assert result["chain_completeness"] >= 0.9
    print(f"✅ test_chain_complete PASSED (completeness={result['chain_completeness']})")


def test_chain_incomplete():
    assessment = ThreatAssessment(
        threat_classification="BEC Payment Fraud",
        severity_level=5,
        confidence=0.0,  # Missing confidence
        mitre_attack_techniques=[],  # No techniques
        detected_indicators=[],  # No indicators
        reasoning_chain="",  # No reasoning
        recommended_actions=[],  # No actions
        parse_success=True,
    )
    result = validate_evidence_chain(assessment)
    assert result["chain_completeness"] < 0.3
    print(f"✅ test_chain_incomplete PASSED (completeness={result['chain_completeness']})")


def test_chain_benign_no_techniques():
    """Benign classification should get full marks even without techniques."""
    assessment = make_assessment(
        "Benign/Normal", 1, 0.85,
        [],  # No techniques expected for benign
        indicators=["All changes match maintenance ticket CM-2025-0891"],
        reasoning="Scheduled maintenance confirmed via change management system.",
        actions=[{"action": "No action needed", "priority": "long-term", "rationale": "Confirmed benign"}],
    )
    result = validate_evidence_chain(assessment)
    assert result["chain_completeness"] >= 0.8
    print(f"✅ test_chain_benign_no_techniques PASSED (completeness={result['chain_completeness']})")


# ============================================
# Test Full V(O) Score
# ============================================

def test_vo_perfect():
    v = MockValidator()
    assessment = make_assessment(
        "BEC Payment Fraud", 5, 0.92,
        [{"technique_id": "T1566.002", "technique_name": "Spearphishing Link",
          "tactic": "Initial Access", "relevance": "Domain mismatch and urgency language"}],
    )
    result = compute_validation_score(assessment, v)
    assert result["validation_score"] >= 0.8
    assert result["id_validation"]["score"] == 1.0
    assert len(result["id_validation"]["hallucinated_ids"]) == 0
    print(f"✅ test_vo_perfect PASSED (V(O)={result['validation_score']})")


def test_vo_hallucinated_id():
    v = MockValidator()
    assessment = make_assessment(
        "BEC Payment Fraud", 5, 0.92,
        [
            {"technique_id": "T1566.002", "technique_name": "Spearphishing Link",
             "tactic": "Initial Access", "relevance": "Valid technique"},
            {"technique_id": "T9999", "technique_name": "Fake Technique",
             "tactic": "Impact", "relevance": "Hallucinated technique"},
        ],
    )
    result = compute_validation_score(assessment, v)
    assert result["id_validation"]["score"] == 0.5  # 1 of 2 valid
    assert "T9999" in result["id_validation"]["hallucinated_ids"]
    print(f"✅ test_vo_hallucinated_id PASSED (V(O)={result['validation_score']}, ID={result['id_validation']['score']})")


def test_vo_wrong_tactic():
    v = MockValidator()
    assessment = make_assessment(
        "BEC Payment Fraud", 5, 0.92,
        [{"technique_id": "T1566.002", "technique_name": "Spearphishing Link",
          "tactic": "Impact", "relevance": "Wrong tactic for this technique"}],
    )
    result = compute_validation_score(assessment, v)
    assert result["tactic_validation"]["score"] == 0.0  # Wrong tactic
    assert result["id_validation"]["score"] == 1.0  # ID is valid though
    print(f"✅ test_vo_wrong_tactic PASSED (V(O)={result['validation_score']}, Tactic={result['tactic_validation']['score']})")


def test_vo_all_hallucinated():
    v = MockValidator()
    assessment = make_assessment(
        "BEC Payment Fraud", 5, 0.92,
        [
            {"technique_id": "T9999", "technique_name": "Fake1", "tactic": "Impact", "relevance": "x"},
            {"technique_id": "T8888", "technique_name": "Fake2", "tactic": "Impact", "relevance": "x"},
        ],
    )
    result = compute_validation_score(assessment, v)
    assert result["id_validation"]["score"] == 0.0
    assert len(result["id_validation"]["hallucinated_ids"]) == 2
    assert result["validation_score"] < 0.5
    print(f"✅ test_vo_all_hallucinated PASSED (V(O)={result['validation_score']})")


def test_vo_output_structure():
    v = MockValidator()
    assessment = make_assessment("Phishing", 4, 0.8,
        [{"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access", "relevance": "test"}])
    result = compute_validation_score(assessment, v)

    required_keys = ["validation_score", "weights", "id_validation", "name_validation", "tactic_validation", "evidence_chain"]
    for key in required_keys:
        assert key in result, f"Missing key: {key}"

    assert "score" in result["id_validation"]
    assert "hallucinated_ids" in result["id_validation"]
    assert "chain_completeness" in result["evidence_chain"]
    print("✅ test_vo_output_structure PASSED")


# ============================================
# Run all tests
# ============================================
if __name__ == "__main__":
    print("\n🧪 Running Week 4 Tests...\n")

    # ID Validation
    test_id_valid_existing()
    test_id_valid_hallucinated()
    test_id_valid_bad_format()

    # Name Validation
    test_name_exact_match()
    test_name_fuzzy_match()
    test_name_wrong()

    # Tactic Validation
    test_tactic_correct()
    test_tactic_wrong()
    test_tactic_multi_tactic_technique()

    # Evidence Chain
    test_chain_complete()
    test_chain_incomplete()
    test_chain_benign_no_techniques()

    # Full V(O)
    test_vo_perfect()
    test_vo_hallucinated_id()
    test_vo_wrong_tactic()
    test_vo_all_hallucinated()
    test_vo_output_structure()

    print(f"\n✅ All 17 Week 4 tests passed!\n")
