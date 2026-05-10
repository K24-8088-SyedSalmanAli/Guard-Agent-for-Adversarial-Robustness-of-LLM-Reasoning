"""
============================================
Guard Agent - Week 5: Semantic Stability Score S(O)
============================================
Third component of the Reasoning Trust Score (RTS).

Measures how stable LLM outputs are when inputs are
slightly perturbed. Stable outputs = trustworthy.
Unstable outputs = unreliable, route to human.

S(O) = 1 - avg_drift

Where drift measures classification, severity, and
technique changes across perturbed inputs.

Perturbation Types:
  P1: Paraphrase — rephrase event description
  P2: Field Reorder — change metadata order
  P3: Noise Injection — add irrelevant details
  P4: Value Tweak — slightly change non-critical values
  P5: Truncation — remove some details

Usage:
    python -m src.agents.guard_stability --single SC-001
    python -m src.agents.guard_stability
    python tests/test_stability_rts.py
"""

import json
import re
import sys
import time
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    LLM_MODEL, OLLAMA_BASE_URL, LLM_TEMPERATURE_BASELINE,
    LLM_MAX_TOKENS, LLM_REQUEST_TIMEOUT, RESULTS_DIR,
    SCENARIOS_DIR, RAG_TOP_K
)
from src.utils.prompt_templates import RAG_THREAT_ANALYSIS_PROMPT, SYSTEM_PROMPT
from src.utils.output_parser import (
    parse_llm_output, extract_technique_ids, ThreatAssessment
)

# ============================================
# PERTURBATION ENGINE
# ============================================

class PerturbationEngine:
    """
    Generates controlled perturbations of threat scenarios.
    Each perturbation should NOT change the ground truth —
    only tests whether the LLM is robust to minor input variations.
    """

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_perturbations(self, scenario: dict, num_perturbations: int = 4) -> list:
        """
        Generate multiple perturbations of a scenario.
        Returns list of (perturbation_type, perturbed_scenario) tuples.
        """
        perturbations = []

        # P1: Paraphrase — add context prefix/suffix
        perturbations.append(("paraphrase", self._perturb_paraphrase(scenario)))

        # P2: Field Reorder — present metadata differently
        perturbations.append(("field_reorder", self._perturb_field_reorder(scenario)))

        # P3: Noise Injection — add irrelevant details
        perturbations.append(("noise_injection", self._perturb_noise(scenario)))

        # P4: Value Tweak — change timestamp, minor amounts
        perturbations.append(("value_tweak", self._perturb_values(scenario)))

        return perturbations[:num_perturbations]

    def _perturb_paraphrase(self, scenario: dict) -> dict:
        """Add paraphrasing prefixes/suffixes to event description."""
        prefixes = [
            "The following security event was reported: ",
            "Security monitoring systems detected the following: ",
            "An automated alert has been generated for: ",
            "The security operations center received a report about: ",
            "During routine monitoring, the following was observed: ",
        ]
        suffixes = [
            " This event requires immediate analysis.",
            " Please assess the threat level.",
            " The security team is awaiting classification.",
            " This has been flagged for review.",
            " An assessment is needed urgently.",
        ]

        perturbed = scenario.copy()
        prefix = self.rng.choice(prefixes)
        suffix = self.rng.choice(suffixes)
        perturbed["event_description"] = prefix + scenario["event_description"] + suffix
        return perturbed

    def _perturb_field_reorder(self, scenario: dict) -> dict:
        """Present the event description with reordered sentences."""
        perturbed = scenario.copy()
        desc = scenario["event_description"]

        # Split into sentences and shuffle middle ones (keep first and last)
        sentences = [s.strip() for s in desc.split('.') if s.strip()]
        if len(sentences) > 3:
            first = sentences[0]
            last = sentences[-1]
            middle = sentences[1:-1]
            self.rng.shuffle(middle)
            perturbed["event_description"] = '. '.join([first] + middle + [last]) + '.'
        return perturbed

    def _perturb_noise(self, scenario: dict) -> dict:
        """Add irrelevant but plausible details."""
        noise_additions = [
            " The office HVAC system was undergoing scheduled maintenance at the time.",
            " Company stock price remained stable during this period.",
            " The quarterly sales meeting was scheduled for the following week.",
            " Weather conditions were normal for the region.",
            " The IT department recently completed a routine firewall update last month.",
            " Employee satisfaction survey results were published the same day.",
            " The company cafeteria menu was updated to include new options.",
        ]

        perturbed = scenario.copy()
        noise = self.rng.choice(noise_additions)
        # Insert noise in the middle of description
        desc = scenario["event_description"]
        mid = len(desc) // 2
        # Find a sentence break near the middle
        break_point = desc.find('.', mid)
        if break_point > 0:
            perturbed["event_description"] = desc[:break_point + 1] + noise + desc[break_point + 1:]
        else:
            perturbed["event_description"] = desc + noise
        return perturbed

    def _perturb_values(self, scenario: dict) -> dict:
        """Slightly change non-critical values like timestamp."""
        perturbed = scenario.copy()

        # Shift timestamp by 1-3 hours
        try:
            ts = datetime.fromisoformat(scenario["timestamp"].replace("Z", "+00:00"))
            delta = timedelta(hours=self.rng.randint(1, 3), minutes=self.rng.randint(0, 59))
            new_ts = ts + delta
            perturbed["timestamp"] = new_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, TypeError):
            pass

        # Slightly modify monetary amounts in description (±5%)
        desc = perturbed["event_description"]
        amounts = re.findall(r'\$[\d,]+(?:\.\d+)?', desc)
        for amount_str in amounts[:1]:  # Only modify first amount
            try:
                num = float(amount_str.replace('$', '').replace(',', ''))
                factor = 1 + self.rng.uniform(-0.05, 0.05)
                new_num = num * factor
                if new_num > 1000:
                    new_str = f"${new_num:,.0f}"
                else:
                    new_str = f"${new_num:,.2f}"
                desc = desc.replace(amount_str, new_str, 1)
            except ValueError:
                pass
        perturbed["event_description"] = desc

        return perturbed


# ============================================
# STABILITY METRICS
# ============================================

def compute_classification_drift(original: ThreatAssessment, perturbed: ThreatAssessment) -> float:
    """
    Measure classification change between original and perturbed.
    0.0 = same classification (stable)
    1.0 = different classification (unstable)
    """
    if original.threat_classification == perturbed.threat_classification:
        return 0.0
    return 1.0


def compute_severity_drift(original: ThreatAssessment, perturbed: ThreatAssessment) -> float:
    """
    Measure severity change, normalized to [0, 1].
    0.0 = same severity
    1.0 = maximum change (1→5 or 5→1)
    """
    if original.severity_level == 0 or perturbed.severity_level == 0:
        return 0.5  # Parse error, uncertain
    diff = abs(original.severity_level - perturbed.severity_level)
    return diff / 4.0  # Max possible diff is 4 (1→5)


def compute_technique_drift(original: ThreatAssessment, perturbed: ThreatAssessment) -> float:
    """
    Measure ATT&CK technique change using Jaccard distance.
    0.0 = same techniques (stable)
    1.0 = completely different techniques (unstable)
    """
    orig_ids = set(extract_technique_ids(original))
    pert_ids = set(extract_technique_ids(perturbed))

    union = orig_ids | pert_ids
    if len(union) == 0:
        return 0.0  # Both empty = stable

    intersection = orig_ids & pert_ids
    jaccard = len(intersection) / len(union)
    return 1.0 - jaccard  # Jaccard distance


def compute_overall_drift(original: ThreatAssessment, perturbed: ThreatAssessment,
                          w_class: float = 0.5, w_sev: float = 0.2, w_tech: float = 0.3) -> dict:
    """
    Compute weighted overall drift between original and perturbed output.
    
    Weights:
        w_class = 0.5 → Classification change (most important)
        w_sev   = 0.2 → Severity change
        w_tech  = 0.3 → Technique change
    """
    class_drift = compute_classification_drift(original, perturbed)
    sev_drift = compute_severity_drift(original, perturbed)
    tech_drift = compute_technique_drift(original, perturbed)

    overall = w_class * class_drift + w_sev * sev_drift + w_tech * tech_drift

    return {
        "overall_drift": round(overall, 4),
        "classification_drift": round(class_drift, 4),
        "severity_drift": round(sev_drift, 4),
        "technique_drift": round(tech_drift, 4),
        "original_class": original.threat_classification,
        "perturbed_class": perturbed.threat_classification,
        "original_severity": original.severity_level,
        "perturbed_severity": perturbed.severity_level,
        "original_techniques": extract_technique_ids(original),
        "perturbed_techniques": extract_technique_ids(perturbed),
    }


def compute_stability_score(drift_results: list) -> dict:
    """
    Compute S(O) from multiple perturbation drift results.
    
    S(O) = 1 - mean(overall_drift)
    
    S(O) close to 1.0 = very stable (resistant to perturbations)
    S(O) close to 0.0 = very unstable (output changes with minor input changes)
    """
    if not drift_results:
        return {"stability_score": 0.0, "num_perturbations": 0}

    drifts = [d["overall_drift"] for d in drift_results]
    class_drifts = [d["classification_drift"] for d in drift_results]
    sev_drifts = [d["severity_drift"] for d in drift_results]
    tech_drifts = [d["technique_drift"] for d in drift_results]

    mean_drift = sum(drifts) / len(drifts)
    stability_score = 1.0 - mean_drift

    return {
        "stability_score": round(stability_score, 4),
        "mean_drift": round(mean_drift, 4),
        "num_perturbations": len(drift_results),
        "classification_stability": round(1.0 - sum(class_drifts) / len(class_drifts), 4),
        "severity_stability": round(1.0 - sum(sev_drifts) / len(sev_drifts), 4),
        "technique_stability": round(1.0 - sum(tech_drifts) / len(tech_drifts), 4),
        "per_perturbation": drift_results,
    }


# ============================================
# STABILITY PIPELINE (with LLM)
# ============================================

def run_stability_analysis(scenario: dict, num_perturbations: int = 4, seed: int = 42) -> dict:
    """
    Full stability analysis pipeline:
    1. Run original scenario through LLM+RAG
    2. Generate perturbations
    3. Run each perturbation through LLM+RAG
    4. Measure drift for each
    5. Compute S(O)
    """
    try:
        import ollama as ollama_client
    except ImportError:
        return {"error": "ollama not installed"}

    from src.agents.rag_knowledge_base import MitreKnowledgeBase

    kb = MitreKnowledgeBase()
    kb.load()

    def run_llm(event_desc, timestamp, source_org, event_type, data_source):
        """Run single LLM+RAG inference."""
        retrieved = kb.query(event_desc, top_k=RAG_TOP_K)
        context = kb.format_context_for_llm(retrieved)
        prompt = RAG_THREAT_ANALYSIS_PROMPT.format(
            retrieved_context=context,
            event_description=event_desc,
            timestamp=timestamp,
            source_org=source_org,
            event_type=event_type,
            data_source=data_source,
        )
        try:
            response = ollama_client.chat(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": LLM_TEMPERATURE_BASELINE, "num_predict": LLM_MAX_TOKENS},
            )
            return parse_llm_output(response["message"]["content"])
        except Exception as e:
            return ThreatAssessment(raw_output=f"LLM_ERROR: {e}")

    # Step 1: Run original
    start = time.time()
    original_assessment = run_llm(
        scenario["event_description"], scenario["timestamp"],
        scenario["source_org"], scenario["event_type"], scenario["data_source"]
    )
    original_time = time.time() - start

    # Step 2: Generate perturbations
    engine = PerturbationEngine(seed=seed)
    perturbations = engine.generate_perturbations(scenario, num_perturbations)

    # Step 3: Run each perturbation and measure drift
    drift_results = []
    total_perturb_time = 0

    for perturb_type, perturbed_scenario in perturbations:
        start = time.time()
        perturbed_assessment = run_llm(
            perturbed_scenario["event_description"], perturbed_scenario["timestamp"],
            perturbed_scenario["source_org"], perturbed_scenario["event_type"],
            perturbed_scenario["data_source"]
        )
        perturb_time = time.time() - start
        total_perturb_time += perturb_time

        drift = compute_overall_drift(original_assessment, perturbed_assessment)
        drift["perturbation_type"] = perturb_type
        drift["inference_time"] = round(perturb_time, 3)
        drift_results.append(drift)

    # Step 4: Compute S(O)
    stability = compute_stability_score(drift_results)

    ground_truth = scenario.get("ground_truth", {})

    return {
        "scenario_id": scenario["id"],
        "stability": stability,
        "original_classification": original_assessment.threat_classification,
        "ground_truth": ground_truth.get("classification", ""),
        "correct": original_assessment.threat_classification == ground_truth.get("classification", ""),
        "timing": {
            "original_time": round(original_time, 3),
            "total_perturbation_time": round(total_perturb_time, 3),
            "total_time": round(original_time + total_perturb_time, 3),
        },
    }


# ============================================
# BATCH STABILITY FROM WEEK 3 RESULTS
# (No new LLM calls — uses existing multi-pass data)
# ============================================

def compute_stability_from_consistency(results_path: str) -> list:
    """
    Estimate S(O) from Week 3 multi-pass results.
    
    Instead of perturbation-based stability, uses the
    existing 5-pass data to measure output stability
    across different prompt formulations (which act as
    a form of input perturbation).
    
    This is a valid proxy because different prompt
    formulations ARE perturbations of the same input.
    """
    with open(results_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    scenarios = data.get("individual_results", [])
    stability_results = []

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")
        passes = scenario.get("individual_passes", [])

        if len(passes) < 2:
            stability_results.append({
                "scenario_id": scenario_id,
                "stability_score": 0.0,
                "note": "Insufficient passes"
            })
            continue

        # Parse all passes
        assessments = []
        for p in passes:
            raw = p.get("raw_output", "")
            if raw and not raw.startswith("LLM_ERROR"):
                assessments.append(parse_llm_output(raw))

        if len(assessments) < 2:
            stability_results.append({
                "scenario_id": scenario_id,
                "stability_score": 0.0,
                "note": "Insufficient parseable passes"
            })
            continue

        # Use first pass as "original", rest as "perturbations"
        original = assessments[0]
        drift_results = []

        for i, perturbed in enumerate(assessments[1:], 1):
            drift = compute_overall_drift(original, perturbed)
            drift["perturbation_type"] = f"prompt_variation_{i}"
            drift_results.append(drift)

        stability = compute_stability_score(drift_results)

        stability_results.append({
            "scenario_id": scenario_id,
            "stability_score": stability["stability_score"],
            "mean_drift": stability["mean_drift"],
            "classification_stability": stability["classification_stability"],
            "severity_stability": stability["severity_stability"],
            "technique_stability": stability["technique_stability"],
            "num_perturbations": stability["num_perturbations"],
        })

    return stability_results


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
    parser = argparse.ArgumentParser(description="Guard Agent - Week 5: Stability Score S(O)")
    parser.add_argument("--single", type=str, help="Run single scenario with LLM")
    parser.add_argument("--from-consistency", type=str, help="Estimate S(O) from Week 3 results (no LLM needed)")
    parser.add_argument("--perturbations", type=int, default=4)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    print("\n🔬 Guard Agent - Week 5: Semantic Stability Score S(O)")
    print(f"   Timestamp: {datetime.now().isoformat()}")

    if args.from_consistency:
        # === Mode 1: Estimate from Week 3 data (fast, no LLM) ===
        print(f"\n   Estimating S(O) from: {args.from_consistency}")
        results = compute_stability_from_consistency(args.from_consistency)

        import statistics
        s_scores = [r["stability_score"] for r in results]

        print(f"\n{'='*65}")
        print(f"  WEEK 5 RESULTS: Stability Score S(O)")
        print(f"  (Estimated from Week 3 multi-pass data)")
        print(f"{'='*65}")
        print(f"  Mean S(O):  {statistics.mean(s_scores):.4f}")
        print(f"  Std S(O):   {statistics.stdev(s_scores):.4f}" if len(s_scores) > 1 else "")
        print(f"  Range:      [{min(s_scores):.4f}, {max(s_scores):.4f}]")

        print(f"\n  --- Per-Scenario S(O) ---")
        for r in results:
            indicator = "✅" if r["stability_score"] >= 0.7 else "⚠️" if r["stability_score"] >= 0.5 else "❌"
            print(f"  {r['scenario_id']}: S(O)={r['stability_score']:.3f} {indicator}"
                  f"  class_stab={r.get('classification_stability', 0):.2f}"
                  f"  sev_stab={r.get('severity_stability', 0):.2f}"
                  f"  tech_stab={r.get('technique_stability', 0):.2f}")
        print(f"{'='*65}")

        # Save
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = args.output or str(RESULTS_DIR / "guard_stability_results.json")
        with open(out_path, "w") as f:
            json.dump({
                "experiment": "Week 5 - Stability Score S(O)",
                "source": args.from_consistency,
                "timestamp": datetime.now().isoformat(),
                "method": "estimated_from_consistency_passes",
                "mean_stability": round(statistics.mean(s_scores), 4),
                "results": results,
            }, f, indent=2)
        print(f"\n   Results saved to: {out_path}")

    elif args.single:
        # === Mode 2: Single scenario with LLM ===
        scenarios = load_scenarios()
        scenario = next((s for s in scenarios if s["id"] == args.single), None)
        if not scenario:
            print(f"   ERROR: Scenario {args.single} not found")
            return

        print(f"\n   Running stability analysis for {args.single}...")
        print(f"   Perturbations: {args.perturbations}")
        print(f"   Total LLM calls: {1 + args.perturbations}")

        result = run_stability_analysis(scenario, num_perturbations=args.perturbations)
        s = result["stability"]
        print(f"\n   S(O) = {s['stability_score']:.4f}")
        print(f"   Classification stability: {s['classification_stability']:.4f}")
        print(f"   Severity stability: {s['severity_stability']:.4f}")
        print(f"   Technique stability: {s['technique_stability']:.4f}")
        print(f"   Classification: {result['original_classification']} (GT: {result['ground_truth']})")
        print(f"   Time: {result['timing']['total_time']:.1f}s")

        for d in s["per_perturbation"]:
            status = "✅ stable" if d["overall_drift"] == 0 else f"⚠️ drift={d['overall_drift']:.3f}"
            print(f"     {d['perturbation_type']}: {d['original_class']} → {d['perturbed_class']} {status}")

    else:
        print("\n   Usage:")
        print("   python -m src.agents.guard_stability --from-consistency data/results/guard_consistency_results.json")
        print("   python -m src.agents.guard_stability --single SC-001")


if __name__ == "__main__":
    main()
