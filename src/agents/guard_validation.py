import json
import re
import sys
import time
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
from difflib import SequenceMatcher

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    LLM_MODEL, LLM_TEMPERATURE_BASELINE,
    LLM_MAX_TOKENS, RESULTS_DIR,
    SCENARIOS_DIR, RAG_TOP_K, MITRE_DATA_DIR
)
from src.utils.prompt_templates import RAG_THREAT_ANALYSIS_PROMPT, SYSTEM_PROMPT
from src.utils.output_parser import (
    parse_llm_output, ThreatAssessment
)

# ============================================
# MITRE ATT&CK LOOKUP DATABASE
# ============================================

class MitreValidator:
    """
    Validates LLM outputs against the MITRE ATT&CK knowledge base.
    Uses technique_lookup.json (generated in Week 2) for validation.
    """

    def __init__(self, lookup_path: Optional[Path] = None):
        self.technique_lookup = {}
        self.tactic_lookup = {}
        self.valid_technique_ids = set()

        # Load technique lookup
        t_path = lookup_path or (MITRE_DATA_DIR / "technique_lookup.json")
        if t_path.exists():
            with open(t_path, "r", encoding="utf-8") as f:
                self.technique_lookup = json.load(f)
            self.valid_technique_ids = set(self.technique_lookup.keys())
            print(f"   [✓] Loaded {len(self.valid_technique_ids)} technique IDs for validation")
        else:
            print(f"   [!] WARNING: technique_lookup.json not found at {t_path}")
            print(f"   [!] Run Week 2 first: python -m src.agents.mitre_attack_loader")

        # Load tactic lookup
        tactic_path = MITRE_DATA_DIR / "tactic_lookup.json"
        if tactic_path.exists():
            with open(tactic_path, "r", encoding="utf-8") as f:
                self.tactic_lookup = json.load(f)
            print(f"   [✓] Loaded {len(self.tactic_lookup)} tactics for validation")

    def validate_technique_id(self, technique_id: str) -> dict:
        """
        Check if a technique ID exists in MITRE ATT&CK.
        Returns validation result with details.
        """
        # Step 1: Format check
        format_valid = bool(re.match(r'^T\d{4}(\.\d{3})?$', str(technique_id)))

        # Step 2: Existence check
        exists = technique_id in self.valid_technique_ids

        # Step 3: Get ground truth info if exists
        if exists:
            info = self.technique_lookup[technique_id]
            return {
                "technique_id": technique_id,
                "format_valid": True,
                "exists": True,
                "ground_truth_name": info.get("name", ""),
                "ground_truth_tactics": info.get("tactics", []),
                "is_subtechnique": info.get("is_subtechnique", False),
            }
        else:
            # Check if it's close to a real ID (typo detection)
            suggestion = self._find_closest_id(technique_id)
            return {
                "technique_id": technique_id,
                "format_valid": format_valid,
                "exists": False,
                "ground_truth_name": None,
                "ground_truth_tactics": None,
                "closest_valid_id": suggestion,
                "error": "HALLUCINATED_ID" if format_valid else "INVALID_FORMAT",
            }

    def validate_technique_name(self, technique_id: str, claimed_name: str) -> dict:
        """
        Check if the LLM's claimed technique name matches the real name.
        Uses fuzzy matching to handle minor variations.
        """
        if technique_id not in self.valid_technique_ids:
            return {
                "valid": False,
                "error": "Cannot validate name — technique ID does not exist",
                "similarity": 0.0,
            }

        real_name = self.technique_lookup[technique_id].get("name", "")
        if not claimed_name or not real_name:
            return {"valid": False, "error": "Empty name", "similarity": 0.0}

        # Exact match
        if claimed_name.strip().lower() == real_name.strip().lower():
            return {
                "valid": True,
                "real_name": real_name,
                "claimed_name": claimed_name,
                "similarity": 1.0,
                "match_type": "exact",
            }

        # Fuzzy match (handle minor variations)
        similarity = SequenceMatcher(
            None,
            claimed_name.strip().lower(),
            real_name.strip().lower()
        ).ratio()

        return {
            "valid": similarity >= 0.7,  # 70% threshold for name match
            "real_name": real_name,
            "claimed_name": claimed_name,
            "similarity": round(similarity, 4),
            "match_type": "fuzzy" if similarity >= 0.7 else "mismatch",
        }

    def validate_tactic(self, technique_id: str, claimed_tactic: str) -> dict:
        """
        Check if the LLM's claimed tactic is correct for the technique.
        A technique can belong to multiple tactics.
        """
        if technique_id not in self.valid_technique_ids:
            return {
                "valid": False,
                "error": "Cannot validate tactic — technique ID does not exist",
            }

        real_tactics = self.technique_lookup[technique_id].get("tactics", [])
        if not real_tactics:
            return {
                "valid": True,  # No tactics listed, can't invalidate
                "note": "No tactics in database for this technique",
            }

        if not claimed_tactic:
            return {"valid": False, "error": "Empty tactic claimed"}

        # Check if claimed tactic matches any real tactic (case-insensitive)
        claimed_lower = claimed_tactic.strip().lower()
        for real_tactic in real_tactics:
            if claimed_lower == real_tactic.strip().lower():
                return {
                    "valid": True,
                    "claimed_tactic": claimed_tactic,
                    "real_tactics": real_tactics,
                    "match_type": "exact",
                }
            # Fuzzy match for minor variations
            sim = SequenceMatcher(None, claimed_lower, real_tactic.strip().lower()).ratio()
            if sim >= 0.7:
                return {
                    "valid": True,
                    "claimed_tactic": claimed_tactic,
                    "real_tactics": real_tactics,
                    "match_type": "fuzzy",
                    "similarity": round(sim, 4),
                }

        return {
            "valid": False,
            "claimed_tactic": claimed_tactic,
            "real_tactics": real_tactics,
            "error": "WRONG_TACTIC",
        }

    def _find_closest_id(self, technique_id: str) -> Optional[str]:
        """Find the closest valid technique ID (for typo suggestions)."""
        if not self.valid_technique_ids:
            return None

        best_match = None
        best_sim = 0.0
        for valid_id in self.valid_technique_ids:
            sim = SequenceMatcher(None, technique_id, valid_id).ratio()
            if sim > best_sim:
                best_sim = sim
                best_match = valid_id

        return best_match if best_sim > 0.6 else None


# ============================================
# EVIDENCE CHAIN VALIDATION
# ============================================

def validate_evidence_chain(assessment: ThreatAssessment) -> dict:
    """
    Validate that the LLM's output contains a complete evidence chain.
    
    Required components (from proposal Section 6.11):
    1. Detected Indicators — specific data points
    2. ATT&CK Mapping — technique IDs with context
    3. Reasoning Chain — logical steps
    4. Confidence Assessment — self-reported confidence
    5. Recommended Actions — prioritized responses
    
    Returns completeness score and per-field validation.
    """
    fields = {}
    total_score = 0.0
    max_score = 5.0

    # 1. Detected Indicators (must be specific, not generic)
    indicators = assessment.detected_indicators
    if indicators and len(indicators) > 0:
        non_empty = [i for i in indicators if isinstance(i, str) and len(i.strip()) > 10]
        if len(non_empty) >= 2:
            fields["detected_indicators"] = {"valid": True, "count": len(non_empty), "score": 1.0}
            total_score += 1.0
        elif len(non_empty) == 1:
            fields["detected_indicators"] = {"valid": True, "count": 1, "score": 0.5, "note": "Only 1 indicator"}
            total_score += 0.5
        else:
            fields["detected_indicators"] = {"valid": False, "score": 0.0, "error": "Indicators too short/generic"}
    else:
        fields["detected_indicators"] = {"valid": False, "score": 0.0, "error": "No indicators provided"}

    # 2. ATT&CK Mapping
    techniques = assessment.mitre_attack_techniques
    if techniques and len(techniques) > 0:
        has_relevance = any(
            isinstance(t, dict) and len(str(t.get("relevance", ""))) > 10
            for t in techniques
        )
        if has_relevance:
            fields["attack_mapping"] = {"valid": True, "count": len(techniques), "score": 1.0}
            total_score += 1.0
        else:
            fields["attack_mapping"] = {"valid": True, "count": len(techniques), "score": 0.5, "note": "Missing relevance explanations"}
            total_score += 0.5
    else:
        # Benign classifications may legitimately have no techniques
        if assessment.threat_classification == "Benign/Normal":
            fields["attack_mapping"] = {"valid": True, "score": 1.0, "note": "No techniques expected for benign"}
            total_score += 1.0
        else:
            fields["attack_mapping"] = {"valid": False, "score": 0.0, "error": "No ATT&CK techniques provided for attack classification"}

    # 3. Reasoning Chain
    reasoning = assessment.reasoning_chain
    if reasoning and len(reasoning.strip()) > 50:
        fields["reasoning_chain"] = {"valid": True, "length": len(reasoning), "score": 1.0}
        total_score += 1.0
    elif reasoning and len(reasoning.strip()) > 20:
        fields["reasoning_chain"] = {"valid": True, "length": len(reasoning), "score": 0.5, "note": "Reasoning too brief"}
        total_score += 0.5
    else:
        fields["reasoning_chain"] = {"valid": False, "score": 0.0, "error": "No reasoning chain provided"}

    # 4. Confidence Assessment
    confidence = assessment.confidence
    if 0.0 < confidence <= 1.0:
        fields["confidence"] = {"valid": True, "value": confidence, "score": 1.0}
        total_score += 1.0
    else:
        fields["confidence"] = {"valid": False, "score": 0.0, "error": f"Invalid confidence: {confidence}"}

    # 5. Recommended Actions
    actions = assessment.recommended_actions
    if actions and len(actions) > 0:
        has_rationale = any(
            isinstance(a, dict) and len(str(a.get("rationale", ""))) > 5
            for a in actions
        )
        if has_rationale:
            fields["recommended_actions"] = {"valid": True, "count": len(actions), "score": 1.0}
            total_score += 1.0
        else:
            fields["recommended_actions"] = {"valid": True, "count": len(actions), "score": 0.5, "note": "Missing rationale"}
            total_score += 0.5
    else:
        fields["recommended_actions"] = {"valid": False, "score": 0.0, "error": "No actions recommended"}

    completeness = total_score / max_score

    return {
        "chain_completeness": round(completeness, 4),
        "total_score": round(total_score, 1),
        "max_score": max_score,
        "fields": fields,
    }


# ============================================
# FULL V(O) SCORE COMPUTATION
# ============================================

def compute_validation_score(
    assessment: ThreatAssessment,
    validator: MitreValidator,
    w1: float = 0.35,
    w2: float = 0.20,
    w3: float = 0.20,
    w4: float = 0.25,
) -> dict:
    """
    Compute the full Validation Score V(O).
    
    V(O) = w1·ID_VALID + w2·NAME_ACC + w3·TACTIC_ACC + w4·CHAIN_COMP
    
    Weights:
        w1 = 0.35 → Technique ID existence (most critical — hallucination check)
        w2 = 0.20 → Technique name accuracy
        w3 = 0.20 → Tactic attribution accuracy
        w4 = 0.25 → Evidence chain completeness
    """
    techniques = assessment.mitre_attack_techniques

    # === ID Validation ===
    id_validations = []
    for tech in techniques:
        if isinstance(tech, dict):
            tid = tech.get("technique_id", "")
            if tid:
                result = validator.validate_technique_id(tid)
                id_validations.append(result)

    valid_ids = sum(1 for v in id_validations if v.get("exists", False))
    total_ids = len(id_validations)
    id_valid_score = valid_ids / total_ids if total_ids > 0 else 1.0  # No techniques = no hallucination

    # === Name Validation ===
    name_validations = []
    for tech in techniques:
        if isinstance(tech, dict):
            tid = tech.get("technique_id", "")
            tname = tech.get("technique_name", "")
            if tid and tname:
                result = validator.validate_technique_name(tid, tname)
                name_validations.append(result)

    valid_names = sum(1 for v in name_validations if v.get("valid", False))
    total_names = len(name_validations)
    name_acc_score = valid_names / total_names if total_names > 0 else 1.0

    # === Tactic Validation ===
    tactic_validations = []
    for tech in techniques:
        if isinstance(tech, dict):
            tid = tech.get("technique_id", "")
            tactic = tech.get("tactic", "")
            if tid and tactic:
                result = validator.validate_tactic(tid, tactic)
                tactic_validations.append(result)

    valid_tactics = sum(1 for v in tactic_validations if v.get("valid", False))
    total_tactics = len(tactic_validations)
    tactic_acc_score = valid_tactics / total_tactics if total_tactics > 0 else 1.0

    # === Evidence Chain ===
    chain_result = validate_evidence_chain(assessment)
    chain_comp_score = chain_result["chain_completeness"]

    # === Final V(O) ===
    validation_score = (
        w1 * id_valid_score +
        w2 * name_acc_score +
        w3 * tactic_acc_score +
        w4 * chain_comp_score
    )

    # === Hallucination detection summary ===
    hallucinated_ids = [v["technique_id"] for v in id_validations if not v.get("exists", False)]
    wrong_names = [v for v in name_validations if not v.get("valid", False)]
    wrong_tactics = [v for v in tactic_validations if not v.get("valid", False)]

    return {
        "validation_score": round(validation_score, 4),
        "weights": {"w1_id": w1, "w2_name": w2, "w3_tactic": w3, "w4_chain": w4},
        "id_validation": {
            "score": round(id_valid_score, 4),
            "valid_count": valid_ids,
            "total_count": total_ids,
            "hallucinated_ids": hallucinated_ids,
            "details": id_validations,
        },
        "name_validation": {
            "score": round(name_acc_score, 4),
            "valid_count": valid_names,
            "total_count": total_names,
            "wrong_names": [
                {"claimed": v.get("claimed_name"), "real": v.get("real_name"), "similarity": v.get("similarity")}
                for v in wrong_names
            ],
        },
        "tactic_validation": {
            "score": round(tactic_acc_score, 4),
            "valid_count": valid_tactics,
            "total_count": total_tactics,
            "wrong_tactics": [
                {"claimed": v.get("claimed_tactic"), "real": v.get("real_tactics")}
                for v in wrong_tactics
            ],
        },
        "evidence_chain": chain_result,
    }


# ============================================
# BATCH VALIDATION (from Week 3 results)
# ============================================

def validate_consistency_results(results_path: str, validator: MitreValidator) -> list:
    """
    Validate all passes from Week 3 consistency results.
    Adds V(O) score to each pass result.
    """
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    scenarios = data.get("individual_results", data.get("scenarios", []))
    validated_results = []

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")

        # Week 3 stores passes under "individual_passes"
        passes = scenario.get("individual_passes",
                 scenario.get("pass_results",
                 scenario.get("passes", [])))

        pass_validations = []
        for p in passes:
            # Week 3 stores raw_output — re-parse it to get full technique data
            raw_output = p.get("raw_output", "")
            if raw_output and not raw_output.startswith("LLM_ERROR"):
                assessment = parse_llm_output(raw_output)
            else:
                # Fallback: try to reconstruct from stored fields
                parsed = p.get("parsed", p)
                assessment = ThreatAssessment(
                    threat_classification=parsed.get("threat_classification", "PARSE_ERROR"),
                    severity_level=parsed.get("severity_level", 0),
                    confidence=parsed.get("confidence", 0.0),
                    mitre_attack_techniques=parsed.get("mitre_attack_techniques", []),
                    detected_indicators=parsed.get("detected_indicators", []),
                    reasoning_chain=parsed.get("reasoning_chain", ""),
                    recommended_actions=parsed.get("recommended_actions", []),
                    false_positive_assessment=parsed.get("false_positive_assessment", ""),
                    parse_success=parsed.get("parse_success", False),
                )

            v_score = compute_validation_score(assessment, validator)
            pass_validations.append(v_score)

        # Average V(O) across all passes for this scenario
        v_scores = [pv["validation_score"] for pv in pass_validations]
        avg_v = sum(v_scores) / len(v_scores) if v_scores else 0.0

        # Count hallucinations across all passes
        total_hallucinated = sum(
            len(pv["id_validation"]["hallucinated_ids"]) for pv in pass_validations
        )
        total_wrong_names = sum(
            len(pv["name_validation"]["wrong_names"]) for pv in pass_validations
        )
        total_wrong_tactics = sum(
            len(pv["tactic_validation"]["wrong_tactics"]) for pv in pass_validations
        )

        validated_results.append({
            "scenario_id": scenario_id,
            "avg_validation_score": round(avg_v, 4),
            "per_pass_v_scores": [round(v, 4) for v in v_scores],
            "total_hallucinated_ids": total_hallucinated,
            "total_wrong_names": total_wrong_names,
            "total_wrong_tactics": total_wrong_tactics,
            "pass_validations": pass_validations,
        })

    return validated_results


# ============================================
# STANDALONE VALIDATION (uses RAG pipeline)
# ============================================

def run_standalone_validation(scenario: dict, validator: MitreValidator) -> dict:
    """
    Run a single scenario through LLM+RAG, then validate.
    Uses same pipeline as Week 2 but adds V(O) scoring.
    """
    try:
        import ollama as ollama_client
    except ImportError:
        return {"error": "ollama not installed"}

    from src.agents.rag_knowledge_base import MitreKnowledgeBase

    kb = MitreKnowledgeBase()
    kb.load()

    # RAG retrieval
    retrieved = kb.query(scenario["event_description"], top_k=RAG_TOP_K)
    context = kb.format_context_for_llm(retrieved)

    prompt = RAG_THREAT_ANALYSIS_PROMPT.format(
        retrieved_context=context,
        event_description=scenario["event_description"],
        timestamp=scenario["timestamp"],
        source_org=scenario["source_org"],
        event_type=scenario["event_type"],
        data_source=scenario["data_source"],
    )

    start_time = time.time()
    try:
        response = ollama_client.chat(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            options={"temperature": LLM_TEMPERATURE_BASELINE, "num_predict": LLM_MAX_TOKENS},
        )
        raw_output = response["message"]["content"]
    except Exception as e:
        raw_output = f"LLM_ERROR: {str(e)}"

    inference_time = time.time() - start_time

    assessment = parse_llm_output(raw_output)
    v_result = compute_validation_score(assessment, validator)

    ground_truth = scenario.get("ground_truth", {})

    return {
        "scenario_id": scenario["id"],
        "inference_time": round(inference_time, 3),
        "classification": assessment.threat_classification,
        "ground_truth": ground_truth.get("classification", ""),
        "correct": assessment.threat_classification == ground_truth.get("classification", ""),
        "validation": v_result,
    }


# ============================================
# SUMMARY METRICS
# ============================================

def compute_summary(validated_results: list) -> dict:
    """Compute aggregate V(O) metrics."""
    total = len(validated_results)
    if total == 0:
        return {}

    v_scores = [r["avg_validation_score"] for r in validated_results]
    total_hallucinated = sum(r["total_hallucinated_ids"] for r in validated_results)
    total_wrong_names = sum(r["total_wrong_names"] for r in validated_results)
    total_wrong_tactics = sum(r["total_wrong_tactics"] for r in validated_results)

    scenarios_with_hallucinations = sum(
        1 for r in validated_results if r["total_hallucinated_ids"] > 0
    )

    import statistics
    return {
        "total_scenarios": total,
        "mean_v_score": round(statistics.mean(v_scores), 4),
        "std_v_score": round(statistics.stdev(v_scores), 4) if len(v_scores) > 1 else 0,
        "min_v_score": round(min(v_scores), 4),
        "max_v_score": round(max(v_scores), 4),
        "hallucination_summary": {
            "total_hallucinated_ids": total_hallucinated,
            "scenarios_with_hallucinations": scenarios_with_hallucinations,
            "hallucination_rate": round(scenarios_with_hallucinations / total, 4),
        },
        "name_accuracy_summary": {
            "total_wrong_names": total_wrong_names,
        },
        "tactic_accuracy_summary": {
            "total_wrong_tactics": total_wrong_tactics,
        },
    }


# ============================================
# CLI
# ============================================

def load_scenarios(path=None):
    if path is None:
        path = SCENARIOS_DIR / "threat_scenarios.json"
    else:
        path = Path(path)
    with open(path, "r") as f:
        data = json.load(f)
    return data["scenarios"]


def main():
    parser = argparse.ArgumentParser(description="Guard Agent - Week 4: Validation Score V(O)")
    parser.add_argument("--input", type=str, default=None,
                        help="Path to Week 3 consistency results JSON (validates existing results)")
    parser.add_argument("--single", type=str, default=None, help="Run single scenario by ID")
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    print("\n🔬 Guard Agent - Week 4: Validation Score V(O)")
    print(f"   Timestamp: {datetime.now().isoformat()}")

    # Initialize validator
    print("\n   Initializing MITRE ATT&CK Validator...")
    validator = MitreValidator()

    if args.input:
        # === Mode 1: Validate existing Week 3 results ===
        print(f"\n   Validating results from: {args.input}")
        validated = validate_consistency_results(args.input, validator)
        summary = compute_summary(validated)

        # Print results
        print(f"\n{'='*65}")
        print(f"  WEEK 4 RESULTS: Validation Score V(O)")
        print(f"{'='*65}")
        print(f"\n  Mean V(O):   {summary['mean_v_score']:.4f}")
        print(f"  Std V(O):    {summary['std_v_score']:.4f}")
        print(f"  Range:       [{summary['min_v_score']:.4f}, {summary['max_v_score']:.4f}]")

        hs = summary["hallucination_summary"]
        print(f"\n  --- Hallucination Detection ---")
        print(f"  Total hallucinated IDs:        {hs['total_hallucinated_ids']}")
        print(f"  Scenarios with hallucinations: {hs['scenarios_with_hallucinations']}/{summary['total_scenarios']}")
        print(f"  Hallucination rate:            {hs['hallucination_rate']:.1%}")

        ns = summary["name_accuracy_summary"]
        ts = summary["tactic_accuracy_summary"]
        print(f"\n  --- Attribution Accuracy ---")
        print(f"  Wrong technique names:  {ns['total_wrong_names']}")
        print(f"  Wrong tactic claims:    {ts['total_wrong_tactics']}")

        # Per-scenario details
        print(f"\n  --- Per-Scenario V(O) ---")
        for r in validated:
            halluc = f"⚠️ {r['total_hallucinated_ids']} halluc" if r['total_hallucinated_ids'] > 0 else "✅ clean"
            print(f"  {r['scenario_id']}: V(O)={r['avg_validation_score']:.3f}  {halluc}")

        print(f"{'='*65}")

        # Save
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = args.output or str(RESULTS_DIR / "guard_validation_results.json")
        with open(out_path, "w") as f:
            json.dump({
                "experiment": "Week 4 - Validation Score V(O)",
                "source": args.input,
                "timestamp": datetime.now().isoformat(),
                "summary": summary,
                "validated_results": validated,
            }, f, indent=2, default=str)
        print(f"\n   Results saved to: {out_path}")

    elif args.single:
        # === Mode 2: Single scenario standalone ===
        scenarios = load_scenarios()
        scenario = next((s for s in scenarios if s["id"] == args.single), None)
        if not scenario:
            print(f"   ERROR: Scenario {args.single} not found")
            return

        result = run_standalone_validation(scenario, validator)
        v = result["validation"]
        print(f"\n   Scenario: {result['scenario_id']}")
        print(f"   Classification: {result['classification']} (GT: {result['ground_truth']})")
        print(f"   V(O) = {v['validation_score']:.4f}")
        print(f"   ID Valid:     {v['id_validation']['score']:.2f} ({v['id_validation']['valid_count']}/{v['id_validation']['total_count']})")
        print(f"   Name Acc:     {v['name_validation']['score']:.2f} ({v['name_validation']['valid_count']}/{v['name_validation']['total_count']})")
        print(f"   Tactic Acc:   {v['tactic_validation']['score']:.2f} ({v['tactic_validation']['valid_count']}/{v['tactic_validation']['total_count']})")
        print(f"   Chain Comp:   {v['evidence_chain']['chain_completeness']:.2f}")
        if v['id_validation']['hallucinated_ids']:
            print(f"   ⚠️  Hallucinated IDs: {v['id_validation']['hallucinated_ids']}")

    else:
        print("\n   Usage:")
        print("   python -m src.agents.guard_validation --input data/results/guard_consistency_results.json")
        print("   python -m src.agents.guard_validation --single SC-001")


if __name__ == "__main__":
    main()