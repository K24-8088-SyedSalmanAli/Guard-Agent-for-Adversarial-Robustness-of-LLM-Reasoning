import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.utils.output_parser import (
    parse_llm_output,
    extract_json_from_response,
    compute_output_completeness,
    extract_technique_ids,
)
from src.agents.baseline_llm import compute_summary_metrics


# ============================================
# Test Output Parser
# ============================================

def test_parse_valid_json():
    """Test parsing a well-formed LLM response."""
    raw = json.dumps({
        "threat_classification": "BEC Payment Fraud",
        "severity_level": 5,
        "confidence": 0.92,
        "mitre_attack_techniques": [
            {"technique_id": "T1566.002", "technique_name": "Spearphishing Link",
             "tactic": "Initial Access", "relevance": "Email-based attack"}
        ],
        "detected_indicators": ["Domain mismatch", "Urgency language"],
        "reasoning_chain": "The email uses a lookalike domain and urgent language.",
        "recommended_actions": [
            {"action": "Block payment", "priority": "immediate", "rationale": "Prevent loss"}
        ],
        "false_positive_assessment": "Unlikely false positive due to domain mismatch."
    })

    result = parse_llm_output(raw)
    assert result.parse_success is True
    assert result.threat_classification == "BEC Payment Fraud"
    assert result.severity_level == 5
    assert result.confidence == 0.92
    assert len(result.mitre_attack_techniques) == 1
    assert len(result.detected_indicators) == 2
    print("test_parse_valid_json PASSED")


def test_parse_json_in_markdown():
    """Test parsing JSON wrapped in markdown code blocks."""
    raw = """Here is my analysis:
```json
{
    "threat_classification": "Network Intrusion",
    "severity_level": 4,
    "confidence": 0.85,
    "mitre_attack_techniques": [],
    "detected_indicators": ["Port scan detected"],
    "reasoning_chain": "Port scanning activity observed.",
    "recommended_actions": [],
    "false_positive_assessment": "Could be legitimate scan."
}
```
    """
    result = parse_llm_output(raw)
    assert result.threat_classification == "Network Intrusion"
    assert result.severity_level == 4
    print("test_parse_json_in_markdown PASSED")


def test_parse_malformed_response():
    """Test handling of completely unparseable response."""
    raw = "I cannot analyze this threat because I don't have enough information."
    result = parse_llm_output(raw)
    assert result.parse_success is False
    assert result.threat_classification == "PARSE_ERROR"
    assert len(result.parse_errors) > 0
    print("test_parse_malformed_response PASSED")


def test_technique_id_validation():
    """Test that technique IDs are validated for format."""
    raw = json.dumps({
        "threat_classification": "Phishing",
        "severity_level": 3,
        "confidence": 0.7,
        "mitre_attack_techniques": [
            {"technique_id": "T1566.002", "technique_name": "Valid", "tactic": "IA", "relevance": "x"},
            {"technique_id": "FAKE123", "technique_name": "Invalid", "tactic": "IA", "relevance": "x"},
            {"technique_id": "T9999", "technique_name": "Unknown but valid format", "tactic": "IA", "relevance": "x"},
        ],
        "detected_indicators": [],
        "reasoning_chain": "",
        "recommended_actions": [],
        "false_positive_assessment": ""
    })

    result = parse_llm_output(raw)
    ids = extract_technique_ids(result)
    # All 3 should be extracted (parser keeps invalid format ones but flags them)
    assert "T1566.002" in ids
    assert "FAKE123" in ids  # Kept but flagged in parse_errors
    assert any("Invalid technique ID format" in e for e in result.parse_errors)
    print("test_technique_id_validation PASSED")


def test_output_completeness():
    """Test completeness scoring."""
    raw = json.dumps({
        "threat_classification": "Ransomware",
        "severity_level": 5,
        "confidence": 0.95,
        "mitre_attack_techniques": [{"technique_id": "T1486", "technique_name": "X", "tactic": "X", "relevance": "X"}],
        "detected_indicators": ["Encrypted files"],
        "reasoning_chain": "Files were encrypted with .lockbit extension.",
        "recommended_actions": [{"action": "Isolate", "priority": "immediate", "rationale": "X"}],
        "false_positive_assessment": "Not a false positive."
    })

    result = parse_llm_output(raw)
    completeness = compute_output_completeness(result)
    assert completeness == 1.0  # All 7 fields present
    print("test_output_completeness PASSED")


def test_summary_metrics():
    """Test aggregate metric computation with mock results."""
    mock_results = [
        {
            "scenario_id": "SC-001",
            "inference_time_seconds": 5.2,
            "output_completeness": 1.0,
            "parsed_assessment": {"parse_success": True},
            "evaluation": {
                "classification_correct": True,
                "predicted_classification": "BEC Payment Fraud",
                "ground_truth_classification": "BEC Payment Fraud",
                "is_attack_correct": True,
                "predicted_is_attack": True,
                "ground_truth_is_attack": True,
                "severity_predicted": 5,
                "severity_ground_truth": 5,
                "severity_error": 0,
                "technique_overlap_jaccard": 0.667,
                "predicted_techniques": ["T1566.002", "T1534"],
                "ground_truth_techniques": ["T1566.002", "T1534"],
                "hallucinated_techniques": [],
                "confidence_score": 0.92,
            },
        },
        {
            "scenario_id": "SC-021",
            "inference_time_seconds": 4.8,
            "output_completeness": 1.0,
            "parsed_assessment": {"parse_success": True},
            "evaluation": {
                "classification_correct": False,
                "predicted_classification": "BEC Payment Fraud",
                "ground_truth_classification": "Benign/Normal",
                "is_attack_correct": False,
                "predicted_is_attack": True,
                "ground_truth_is_attack": False,
                "severity_predicted": 4,
                "severity_ground_truth": 1,
                "severity_error": 3,
                "technique_overlap_jaccard": 0.0,
                "predicted_techniques": ["T1566.002"],
                "ground_truth_techniques": [],
                "hallucinated_techniques": ["T1566.002"],
                "confidence_score": 0.78,
            },
        },
    ]

    metrics = compute_summary_metrics(mock_results)
    assert metrics["total_scenarios"] == 2
    assert metrics["classification_accuracy"] == 0.5
    assert metrics["binary_detection"]["true_positives"] == 1
    assert metrics["binary_detection"]["false_positives"] == 1
    assert metrics["false_escalation_rate"] == 1.0  # 1/1 benign was escalated
    print("test_summary_metrics PASSED")


def test_scenarios_file_integrity():
    """Verify the threat scenarios file is valid and complete."""
    scenarios_path = PROJECT_ROOT / "data" / "scenarios" / "threat_scenarios.json"
    with open(scenarios_path, "r") as f:
        data = json.load(f)

    scenarios = data["scenarios"]
    metadata = data["metadata"]

    assert len(scenarios) == metadata["total_scenarios"]
    assert len(scenarios) == 30

    # Check all required fields exist
    required_fields = ["id", "event_description", "timestamp", "source_org",
                       "event_type", "data_source", "ground_truth"]
    for s in scenarios:
        for field in required_fields:
            assert field in s, f"Missing field '{field}' in scenario {s.get('id', 'UNKNOWN')}"

    # Check ground truth structure
    for s in scenarios:
        gt = s["ground_truth"]
        assert "classification" in gt
        assert "severity" in gt
        assert "is_attack" in gt
        assert "attack_techniques" in gt

    # Check IDs are unique
    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids)), "Duplicate scenario IDs found"

    # Check attack/benign distribution
    attack_count = sum(1 for s in scenarios if s["ground_truth"]["is_attack"])
    benign_count = sum(1 for s in scenarios if not s["ground_truth"]["is_attack"])
    assert attack_count == metadata["attack_scenarios"]
    assert benign_count == metadata["benign_scenarios"]

    print(f"test_scenarios_file_integrity PASSED ({attack_count} attacks, {benign_count} benign)")


# ============================================
# Run all tests
# ============================================
if __name__ == "__main__":
    print("\nRunning Week 1 Tests...\n")

    test_parse_valid_json()
    test_parse_json_in_markdown()
    test_parse_malformed_response()
    test_technique_id_validation()
    test_output_completeness()
    test_summary_metrics()
    test_scenarios_file_integrity()

    print("\nAll tests passed!\n")
