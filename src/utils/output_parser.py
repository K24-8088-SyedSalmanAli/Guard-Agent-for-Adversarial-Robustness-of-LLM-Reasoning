import json
import re
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class ThreatAssessment:
    """Structured representation of an LLM threat analysis output."""
    threat_classification: str = "PARSE_ERROR"
    severity_level: int = 0
    confidence: float = 0.0
    mitre_attack_techniques: list = field(default_factory=list)
    detected_indicators: list = field(default_factory=list)
    reasoning_chain: str = ""
    recommended_actions: list = field(default_factory=list)
    false_positive_assessment: str = ""
    raw_output: str = ""
    parse_success: bool = False
    parse_errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "threat_classification": self.threat_classification,
            "severity_level": self.severity_level,
            "confidence": self.confidence,
            "mitre_attack_techniques": self.mitre_attack_techniques,
            "detected_indicators": self.detected_indicators,
            "reasoning_chain": self.reasoning_chain,
            "recommended_actions": self.recommended_actions,
            "false_positive_assessment": self.false_positive_assessment,
            "parse_success": self.parse_success,
            "parse_errors": self.parse_errors,
        }


VALID_CLASSIFICATIONS = [
    "BEC Payment Fraud",
    "Invoice Fraud",
    "Data Tampering",
    "Network Intrusion",
    "Insider Threat",
    "Ransomware",
    "Phishing",
    "DDoS",
    "Brute Force",
    "Benign/Normal",
]


def extract_json_from_response(raw_text: str) -> Optional[dict]:
    """
    Extract JSON from LLM response, handling common formatting issues.
    LLMs often wrap JSON in markdown code blocks or add preamble text.
    """
    # Strategy 1: Try direct parse
    try:
        return json.loads(raw_text.strip())
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from markdown code block
    json_block = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', raw_text, re.DOTALL)
    if json_block:
        try:
            return json.loads(json_block.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find the outermost { ... } block
    brace_match = re.search(r'\{.*\}', raw_text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # Strategy 4: Try to fix common issues (trailing commas, single quotes)
    if brace_match:
        cleaned = brace_match.group(0)
        # Remove trailing commas before } or ]
        cleaned = re.sub(r',\s*([}\]])', r'\1', cleaned)
        # Replace single quotes with double quotes (risky but sometimes needed)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

    return None


def parse_llm_output(raw_text: str) -> ThreatAssessment:
    """
    Parse raw LLM text output into a validated ThreatAssessment.
    Tracks all parse errors for analysis.
    """
    assessment = ThreatAssessment(raw_output=raw_text)
    errors = []

    # Step 1: Extract JSON
    parsed = extract_json_from_response(raw_text)
    if parsed is None:
        assessment.parse_errors = ["FATAL: Could not extract valid JSON from response"]
        return assessment

    # Step 2: Extract and validate each field

    # --- threat_classification ---
    classification = parsed.get("threat_classification", "MISSING")
    if classification in VALID_CLASSIFICATIONS:
        assessment.threat_classification = classification
    else:
        # Try fuzzy matching
        matched = False
        for valid in VALID_CLASSIFICATIONS:
            if classification.lower().strip() in valid.lower() or valid.lower() in classification.lower().strip():
                assessment.threat_classification = valid
                errors.append(f"Fuzzy-matched classification: '{classification}' -> '{valid}'")
                matched = True
                break
        if not matched:
            assessment.threat_classification = classification
            errors.append(f"Invalid classification: '{classification}' not in valid set")

    # --- severity_level ---
    severity = parsed.get("severity_level", 0)
    try:
        severity = int(severity)
        if 1 <= severity <= 5:
            assessment.severity_level = severity
        else:
            assessment.severity_level = max(1, min(5, severity))
            errors.append(f"Severity {severity} out of range, clamped to {assessment.severity_level}")
    except (ValueError, TypeError):
        errors.append(f"Invalid severity_level: {severity}")

    # --- confidence ---
    confidence = parsed.get("confidence", 0.0)
    try:
        confidence = float(confidence)
        if 0.0 <= confidence <= 1.0:
            assessment.confidence = confidence
        else:
            assessment.confidence = max(0.0, min(1.0, confidence))
            errors.append(f"Confidence {confidence} out of range, clamped to {assessment.confidence}")
    except (ValueError, TypeError):
        errors.append(f"Invalid confidence: {confidence}")

    # --- mitre_attack_techniques ---
    techniques = parsed.get("mitre_attack_techniques", [])
    if isinstance(techniques, list):
        validated_techniques = []
        for tech in techniques:
            if isinstance(tech, dict):
                technique_id = tech.get("technique_id", "")
                # Validate technique ID format: T followed by digits, optional .digits
                if re.match(r'^T\d{4}(\.\d{3})?$', str(technique_id)):
                    validated_techniques.append(tech)
                else:
                    errors.append(f"Invalid technique ID format: '{technique_id}'")
                    validated_techniques.append(tech)  # Keep it but flag it
            else:
                errors.append(f"Technique entry is not a dict: {tech}")
        assessment.mitre_attack_techniques = validated_techniques
    else:
        errors.append("mitre_attack_techniques is not a list")

    # --- detected_indicators ---
    indicators = parsed.get("detected_indicators", [])
    if isinstance(indicators, list):
        assessment.detected_indicators = indicators
    else:
        assessment.detected_indicators = [str(indicators)]
        errors.append("detected_indicators was not a list, converted")

    # --- reasoning_chain ---
    reasoning = parsed.get("reasoning_chain", "")
    assessment.reasoning_chain = str(reasoning)
    if not reasoning:
        errors.append("Empty reasoning_chain")

    # --- recommended_actions ---
    actions = parsed.get("recommended_actions", [])
    if isinstance(actions, list):
        assessment.recommended_actions = actions
    else:
        errors.append("recommended_actions is not a list")

    # --- false_positive_assessment ---
    fp = parsed.get("false_positive_assessment", "")
    assessment.false_positive_assessment = str(fp)

    # Final status
    assessment.parse_errors = errors
    assessment.parse_success = len([e for e in errors if "FATAL" in e or "Invalid classification" in e]) == 0

    return assessment


def extract_technique_ids(assessment: ThreatAssessment) -> list[str]:
    """Extract all MITRE ATT&CK technique IDs from an assessment."""
    ids = []
    for tech in assessment.mitre_attack_techniques:
        if isinstance(tech, dict):
            tid = tech.get("technique_id", "")
            if tid:
                ids.append(str(tid))
    return ids


def compute_output_completeness(assessment: ThreatAssessment) -> float:
    """
    Score how complete the LLM output is (0.0 to 1.0).
    Used later by Guard Agent for evidence chain validation.
    """
    score = 0.0
    total_fields = 7

    if assessment.threat_classification != "PARSE_ERROR":
        score += 1
    if assessment.severity_level > 0:
        score += 1
    if assessment.confidence > 0:
        score += 1
    if len(assessment.mitre_attack_techniques) > 0:
        score += 1
    if len(assessment.detected_indicators) > 0:
        score += 1
    if assessment.reasoning_chain:
        score += 1
    if len(assessment.recommended_actions) > 0:
        score += 1

    return score / total_fields
