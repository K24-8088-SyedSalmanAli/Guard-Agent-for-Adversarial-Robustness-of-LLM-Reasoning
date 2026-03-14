import json
import time
import argparse
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    LLM_MODEL, OLLAMA_BASE_URL, LLM_TEMPERATURE_BASELINE,
    LLM_MAX_TOKENS, LLM_REQUEST_TIMEOUT, RESULTS_DIR, SCENARIOS_DIR
)
from src.utils.prompt_templates import BASELINE_THREAT_ANALYSIS_PROMPT, SYSTEM_PROMPT
from src.utils.output_parser import parse_llm_output, compute_output_completeness, extract_technique_ids

# ============================================
# LangChain + Ollama Setup
# ============================================
try:
    from langchain_ollama import ChatOllama
    from langchain_core.messages import SystemMessage, HumanMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("[WARNING] langchain_ollama not installed. Install with: pip install langchain-ollama")
    print("[WARNING] Falling back to direct Ollama API calls.")

try:
    import ollama as ollama_client
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False


def get_llm():
    """Initialize the LLM client."""
    if LANGCHAIN_AVAILABLE:
        return ChatOllama(
            model=LLM_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=LLM_TEMPERATURE_BASELINE,
            num_predict=LLM_MAX_TOKENS,
            timeout=LLM_REQUEST_TIMEOUT,
        )
    elif OLLAMA_AVAILABLE:
        return "ollama_direct"
    else:
        raise RuntimeError(
            "Neither langchain_ollama nor ollama package available. "
            "Install one: pip install langchain-ollama OR pip install ollama"
        )


def run_llm_analysis(llm, scenario: dict) -> dict:
    """
    Run a single threat scenario through the LLM-only baseline.
    Returns the raw output, parsed assessment, and timing info.
    """
    # Format the prompt with scenario data
    prompt = BASELINE_THREAT_ANALYSIS_PROMPT.format(
        event_description=scenario["event_description"],
        timestamp=scenario["timestamp"],
        source_org=scenario["source_org"],
        event_type=scenario["event_type"],
        data_source=scenario["data_source"],
    )

    # Run inference
    start_time = time.time()

    if LANGCHAIN_AVAILABLE and not isinstance(llm, str):
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]
        try:
            response = llm.invoke(messages)
            raw_output = response.content
        except Exception as e:
            raw_output = f"LLM_ERROR: {str(e)}"
    elif OLLAMA_AVAILABLE:
        try:
            response = ollama_client.chat(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                options={
                    "temperature": LLM_TEMPERATURE_BASELINE,
                    "num_predict": LLM_MAX_TOKENS,
                },
            )
            raw_output = response["message"]["content"]
        except Exception as e:
            raw_output = f"LLM_ERROR: {str(e)}"
    else:
        raw_output = "LLM_ERROR: No LLM client available"

    inference_time = time.time() - start_time

    # Parse the output
    assessment = parse_llm_output(raw_output)
    completeness = compute_output_completeness(assessment)
    technique_ids = extract_technique_ids(assessment)

    # Compare with ground truth
    ground_truth = scenario.get("ground_truth", {})
    gt_classification = ground_truth.get("classification", "")
    gt_techniques = ground_truth.get("attack_techniques", [])
    gt_is_attack = ground_truth.get("is_attack", None)

    # Evaluate correctness
    classification_correct = assessment.threat_classification == gt_classification
    is_attack_predicted = assessment.threat_classification != "Benign/Normal"
    is_attack_correct = is_attack_predicted == gt_is_attack if gt_is_attack is not None else None

    # Technique overlap (Jaccard similarity)
    predicted_set = set(technique_ids)
    gt_set = set(gt_techniques)
    technique_overlap = (
        len(predicted_set & gt_set) / len(predicted_set | gt_set)
        if (predicted_set | gt_set)
        else 1.0 if not gt_set else 0.0
    )

    # Check for hallucinated techniques (predicted but not in ground truth)
    hallucinated_techniques = list(predicted_set - gt_set) if gt_set else []

    return {
        "scenario_id": scenario["id"],
        "inference_time_seconds": round(inference_time, 3),
        "raw_output": raw_output,
        "parsed_assessment": assessment.to_dict(),
        "output_completeness": round(completeness, 3),
        "evaluation": {
            "classification_correct": classification_correct,
            "predicted_classification": assessment.threat_classification,
            "ground_truth_classification": gt_classification,
            "is_attack_correct": is_attack_correct,
            "predicted_is_attack": is_attack_predicted,
            "ground_truth_is_attack": gt_is_attack,
            "severity_predicted": assessment.severity_level,
            "severity_ground_truth": ground_truth.get("severity", 0),
            "severity_error": abs(assessment.severity_level - ground_truth.get("severity", 0)),
            "technique_overlap_jaccard": round(technique_overlap, 3),
            "predicted_techniques": technique_ids,
            "ground_truth_techniques": gt_techniques,
            "hallucinated_techniques": hallucinated_techniques,
            "confidence_score": assessment.confidence,
        },
    }


def load_scenarios(path: Optional[str] = None) -> list:
    """Load threat scenarios from JSON file."""
    if path is None:
        path = SCENARIOS_DIR / "threat_scenarios.json"
    else:
        path = Path(path)

    with open(path, "r") as f:
        data = json.load(f)

    return data["scenarios"]


def compute_summary_metrics(results: list) -> dict:
    """Compute aggregate metrics across all scenario results."""
    total = len(results)
    if total == 0:
        return {}

    # Classification accuracy
    correct_classifications = sum(
        1 for r in results if r["evaluation"]["classification_correct"]
    )

    # Attack detection (binary: attack vs benign)
    attack_results = [r for r in results if r["evaluation"]["ground_truth_is_attack"] is not None]
    if attack_results:
        tp = sum(1 for r in attack_results if r["evaluation"]["predicted_is_attack"] and r["evaluation"]["ground_truth_is_attack"])
        tn = sum(1 for r in attack_results if not r["evaluation"]["predicted_is_attack"] and not r["evaluation"]["ground_truth_is_attack"])
        fp = sum(1 for r in attack_results if r["evaluation"]["predicted_is_attack"] and not r["evaluation"]["ground_truth_is_attack"])
        fn = sum(1 for r in attack_results if not r["evaluation"]["predicted_is_attack"] and r["evaluation"]["ground_truth_is_attack"])

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / len(attack_results)
    else:
        tp = tn = fp = fn = 0
        precision = recall = f1 = accuracy = 0

    # Average severity error
    severity_errors = [r["evaluation"]["severity_error"] for r in results]
    avg_severity_error = sum(severity_errors) / len(severity_errors)

    # Average technique overlap
    technique_overlaps = [r["evaluation"]["technique_overlap_jaccard"] for r in results]
    avg_technique_overlap = sum(technique_overlaps) / len(technique_overlaps)

    # Hallucination analysis
    total_hallucinated = sum(
        len(r["evaluation"]["hallucinated_techniques"]) for r in results
    )
    scenarios_with_hallucinations = sum(
        1 for r in results if len(r["evaluation"]["hallucinated_techniques"]) > 0
    )

    # Parse success rate
    parse_successes = sum(
        1 for r in results if r["parsed_assessment"]["parse_success"]
    )

    # Average inference time
    avg_time = sum(r["inference_time_seconds"] for r in results) / total

    # Average confidence
    avg_confidence = sum(r["evaluation"]["confidence_score"] for r in results) / total

    # Output completeness
    avg_completeness = sum(r["output_completeness"] for r in results) / total

    # False escalation rate (benign classified as attack)
    benign_scenarios = [r for r in results if not r["evaluation"]["ground_truth_is_attack"]]
    false_escalations = sum(1 for r in benign_scenarios if r["evaluation"]["predicted_is_attack"])
    false_escalation_rate = false_escalations / len(benign_scenarios) if benign_scenarios else 0

    return {
        "total_scenarios": total,
        "classification_accuracy": round(correct_classifications / total, 4),
        "correct_classifications": correct_classifications,
        "binary_detection": {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
        },
        "severity_analysis": {
            "mean_absolute_error": round(avg_severity_error, 3),
            "max_error": max(severity_errors),
            "errors": severity_errors,
        },
        "technique_mapping": {
            "avg_jaccard_overlap": round(avg_technique_overlap, 3),
            "total_hallucinated_techniques": total_hallucinated,
            "scenarios_with_hallucinations": scenarios_with_hallucinations,
            "hallucination_rate": round(scenarios_with_hallucinations / total, 4),
        },
        "false_escalation_rate": round(false_escalation_rate, 4),
        "parse_success_rate": round(parse_successes / total, 4),
        "avg_inference_time_seconds": round(avg_time, 3),
        "avg_confidence": round(avg_confidence, 3),
        "avg_output_completeness": round(avg_completeness, 3),
    }


def print_summary(metrics: dict):
    """Print a formatted summary of results."""
    print("\n" + "=" * 60)
    print("  WEEK 1 BASELINE RESULTS: LLM-Only (No RAG, No Guard)")
    print("=" * 60)

    print(f"\n  Total Scenarios: {metrics['total_scenarios']}")
    print(f"  Classification Accuracy: {metrics['classification_accuracy']:.1%}")
    print(f"  Parse Success Rate: {metrics['parse_success_rate']:.1%}")
    print(f"  Avg Inference Time: {metrics['avg_inference_time_seconds']:.1f}s")
    print(f"  Avg Output Completeness: {metrics['avg_output_completeness']:.1%}")

    bd = metrics["binary_detection"]
    print(f"\n  --- Binary Attack Detection ---")
    print(f"  Accuracy:  {bd['accuracy']:.1%}")
    print(f"  Precision: {bd['precision']:.1%}")
    print(f"  Recall:    {bd['recall']:.1%}")
    print(f"  F1 Score:  {bd['f1_score']:.1%}")
    print(f"  TP={bd['true_positives']} TN={bd['true_negatives']} FP={bd['false_positives']} FN={bd['false_negatives']}")

    tm = metrics["technique_mapping"]
    print(f"\n  --- MITRE ATT&CK Technique Mapping ---")
    print(f"  Avg Jaccard Overlap: {tm['avg_jaccard_overlap']:.1%}")
    print(f"  Hallucination Rate:  {tm['hallucination_rate']:.1%}")
    print(f"  Total Hallucinated Techniques: {tm['total_hallucinated_techniques']}")

    print(f"\n  --- Key Metrics for Guard Agent Comparison ---")
    print(f"  False Escalation Rate: {metrics['false_escalation_rate']:.1%}")
    print(f"  Technique Hallucination Rate: {tm['hallucination_rate']:.1%}")
    print(f"  Avg Confidence: {metrics['avg_confidence']:.3f}")

    sa = metrics["severity_analysis"]
    print(f"\n  --- Severity Assessment ---")
    print(f"  Mean Absolute Error: {sa['mean_absolute_error']:.2f} levels")
    print(f"  Max Error: {sa['max_error']} levels")

    print("\n" + "=" * 60)
    print("  These metrics will be compared against:")
    print("  Week 2: LLM + RAG")
    print("  Week 5: LLM + RAG + Guard (RTS)")
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Guard Agent - Week 1: LLM-Only Baseline")
    parser.add_argument("--scenarios", type=str, default=None, help="Path to scenarios JSON")
    parser.add_argument("--single", type=str, default=None, help="Run single scenario by ID")
    parser.add_argument("--output", type=str, default=None, help="Output results path")
    parser.add_argument("--dry-run", action="store_true", help="Print prompts without LLM calls")
    args = parser.parse_args()

    print("\n Guard Agent - Week 1: LLM-Only Baseline")
    print(f"   Model: {LLM_MODEL}")
    print(f"   Temperature: {LLM_TEMPERATURE_BASELINE}")
    print(f"   Timestamp: {datetime.now().isoformat()}")

    # Load scenarios
    scenarios = load_scenarios(args.scenarios)
    print(f"   Loaded {len(scenarios)} scenarios")

    # Filter single scenario if requested
    if args.single:
        scenarios = [s for s in scenarios if s["id"] == args.single]
        if not scenarios:
            print(f"   ERROR: Scenario {args.single} not found")
            return
        print(f"   Running single scenario: {args.single}")

    # Dry run mode — just print prompts
    if args.dry_run:
        for scenario in scenarios[:3]:
            prompt = BASELINE_THREAT_ANALYSIS_PROMPT.format(
                event_description=scenario["event_description"],
                timestamp=scenario["timestamp"],
                source_org=scenario["source_org"],
                event_type=scenario["event_type"],
                data_source=scenario["data_source"],
            )
            print(f"\n--- {scenario['id']} ---")
            print(f"System: {SYSTEM_PROMPT[:200]}...")
            print(f"Prompt: {prompt[:500]}...")
        print("\n[DRY RUN] No LLM calls made.")
        return

    # Initialize LLM
    print("\n   Initializing LLM...")
    try:
        llm = get_llm()
        print("   LLM ready.\n")
    except Exception as e:
        print(f"   ERROR initializing LLM: {e}")
        print("   Make sure Ollama is running: ollama serve")
        print("   And model is pulled: ollama pull llama3:8b")
        return

    # Run all scenarios
    results = []
    for i, scenario in enumerate(scenarios):
        print(f"   [{i+1}/{len(scenarios)}] Processing {scenario['id']}...", end=" ", flush=True)

        result = run_llm_analysis(llm, scenario)
        results.append(result)

        # Quick status
        eval_info = result["evaluation"]
        status = "✅" if eval_info["classification_correct"] else "❌"
        print(
            f"{status} Predicted: {eval_info['predicted_classification']:<20} "
            f"GT: {eval_info['ground_truth_classification']:<20} "
            f"Time: {result['inference_time_seconds']:.1f}s"
        )

    # Compute summary metrics
    metrics = compute_summary_metrics(results)

    # Print summary
    print_summary(metrics)

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_path = args.output or str(RESULTS_DIR / "baseline_llm_results.json")

    output_data = {
        "experiment": "Week 1 - LLM-Only Baseline",
        "model": LLM_MODEL,
        "temperature": LLM_TEMPERATURE_BASELINE,
        "timestamp": datetime.now().isoformat(),
        "summary_metrics": metrics,
        "individual_results": results,
    }

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2, default=str)

    print(f"   Results saved to: {output_path}")


if __name__ == "__main__":
    main()
