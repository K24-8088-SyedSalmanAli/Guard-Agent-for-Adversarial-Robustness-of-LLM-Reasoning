import json
import argparse
import sys
from pathlib import Path
from collections import Counter
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ============================================
# METRIC FUNCTIONS
# ============================================

def confusion_matrix_by_category(results: list) -> dict:
    """
    Build a per-category confusion matrix.
    Shows which attack types the LLM confuses most.
    """
    matrix = {}
    for r in results:
        gt = r["evaluation"]["ground_truth_classification"]
        pred = r["evaluation"]["predicted_classification"]
        if gt not in matrix:
            matrix[gt] = Counter()
        matrix[gt][pred] += 1
    return {gt: dict(preds) for gt, preds in matrix.items()}


def hallucination_analysis(results: list) -> dict:
    """
    Detailed hallucination analysis:
    - Which technique IDs are most commonly hallucinated
    - Which scenario types trigger the most hallucinations
    - Hallucination severity (inventing vs. misattributing)
    """
    hallucinated_ids = Counter()
    hallucinations_by_category = Counter()
    total_predicted_techniques = 0
    total_valid_techniques = 0

    for r in results:
        ev = r["evaluation"]
        gt_category = ev["ground_truth_classification"]
        hallucinated = ev.get("hallucinated_techniques", [])
        predicted = ev.get("predicted_techniques", [])
        gt_techniques = ev.get("ground_truth_techniques", [])

        total_predicted_techniques += len(predicted)
        total_valid_techniques += len(set(predicted) & set(gt_techniques))

        for tech_id in hallucinated:
            hallucinated_ids[tech_id] += 1
            hallucinations_by_category[gt_category] += 1

    return {
        "most_hallucinated_techniques": dict(hallucinated_ids.most_common(10)),
        "hallucinations_by_attack_category": dict(hallucinations_by_category),
        "total_predicted_techniques": total_predicted_techniques,
        "total_valid_techniques": total_valid_techniques,
        "technique_precision": (
            round(total_valid_techniques / total_predicted_techniques, 4)
            if total_predicted_techniques > 0 else 0
        ),
    }


def confidence_calibration(results: list) -> dict:
    """
    Analyze whether LLM confidence correlates with correctness.
    Well-calibrated: high confidence → correct, low confidence → uncertain.
    Poorly calibrated: high confidence on wrong answers = dangerous for automation.
    """
    correct_confidences = []
    incorrect_confidences = []

    for r in results:
        conf = r["evaluation"]["confidence_score"]
        correct = r["evaluation"]["classification_correct"]
        if correct:
            correct_confidences.append(conf)
        else:
            incorrect_confidences.append(conf)

    avg_correct = sum(correct_confidences) / len(correct_confidences) if correct_confidences else 0
    avg_incorrect = sum(incorrect_confidences) / len(incorrect_confidences) if incorrect_confidences else 0

    # Overconfidence on wrong answers is the key danger metric
    overconfident_wrong = [c for c in incorrect_confidences if c >= 0.8]

    return {
        "avg_confidence_when_correct": round(avg_correct, 4),
        "avg_confidence_when_incorrect": round(avg_incorrect, 4),
        "confidence_gap": round(avg_correct - avg_incorrect, 4),
        "overconfident_wrong_count": len(overconfident_wrong),
        "overconfident_wrong_rate": (
            round(len(overconfident_wrong) / len(incorrect_confidences), 4)
            if incorrect_confidences else 0
        ),
        "total_correct": len(correct_confidences),
        "total_incorrect": len(incorrect_confidences),
        "interpretation": (
            "DANGEROUS: LLM is overconfident on wrong answers"
            if avg_incorrect > 0.7
            else "MODERATE: Some overconfidence on wrong answers"
            if avg_incorrect > 0.5
            else "ACCEPTABLE: LLM shows lower confidence when wrong"
        ),
    }


def benign_vs_attack_analysis(results: list) -> dict:
    """
    Specifically analyze benign scenario handling.
    False escalation of benign events = wasted analyst time.
    """
    benign_results = [r for r in results if not r["evaluation"]["ground_truth_is_attack"]]
    attack_results = [r for r in results if r["evaluation"]["ground_truth_is_attack"]]

    benign_correct = sum(1 for r in benign_results if not r["evaluation"]["predicted_is_attack"])
    benign_escalated = sum(1 for r in benign_results if r["evaluation"]["predicted_is_attack"])

    attack_detected = sum(1 for r in attack_results if r["evaluation"]["predicted_is_attack"])
    attack_missed = sum(1 for r in attack_results if not r["evaluation"]["predicted_is_attack"])

    # What are benign events being misclassified as?
    false_escalation_types = Counter()
    for r in benign_results:
        if r["evaluation"]["predicted_is_attack"]:
            false_escalation_types[r["evaluation"]["predicted_classification"]] += 1

    # What attack types are being missed?
    missed_attack_types = Counter()
    for r in attack_results:
        if not r["evaluation"]["predicted_is_attack"]:
            missed_attack_types[r["evaluation"]["ground_truth_classification"]] += 1

    return {
        "benign_scenarios": {
            "total": len(benign_results),
            "correctly_identified": benign_correct,
            "false_escalations": benign_escalated,
            "false_escalation_rate": round(benign_escalated / len(benign_results), 4) if benign_results else 0,
            "escalated_as": dict(false_escalation_types),
        },
        "attack_scenarios": {
            "total": len(attack_results),
            "correctly_detected": attack_detected,
            "missed": attack_missed,
            "miss_rate": round(attack_missed / len(attack_results), 4) if attack_results else 0,
            "missed_types": dict(missed_attack_types),
        },
    }


def generate_full_report(results_path: str) -> dict:
    """Generate a comprehensive evaluation report from results JSON."""
    with open(results_path, "r") as f:
        data = json.load(f)

    results = data["individual_results"]
    summary = data.get("summary_metrics", {})

    report = {
        "experiment": data.get("experiment", "Unknown"),
        "model": data.get("model", "Unknown"),
        "timestamp": data.get("timestamp", "Unknown"),
        "summary_metrics": summary,
        "confusion_matrix": confusion_matrix_by_category(results),
        "hallucination_analysis": hallucination_analysis(results),
        "confidence_calibration": confidence_calibration(results),
        "benign_vs_attack": benign_vs_attack_analysis(results),
    }

    return report


def print_detailed_report(report: dict):
    """Print a detailed human-readable report."""
    print("\n" + "=" * 70)
    print(f"  DETAILED EVALUATION REPORT: {report['experiment']}")
    print(f"  Model: {report['model']} | {report['timestamp']}")
    print("=" * 70)

    # Confusion matrix
    print("\n  📊 CONFUSION MATRIX (Ground Truth → Predicted)")
    print("  " + "-" * 50)
    cm = report["confusion_matrix"]
    for gt_class, predictions in sorted(cm.items()):
        print(f"  {gt_class}:")
        for pred_class, count in sorted(predictions.items(), key=lambda x: -x[1]):
            marker = "✅" if pred_class == gt_class else "❌"
            print(f"    {marker} → {pred_class}: {count}")

    # Hallucination analysis
    print("\n  🔍 HALLUCINATION ANALYSIS")
    print("  " + "-" * 50)
    ha = report["hallucination_analysis"]
    print(f"  Technique Precision: {ha['technique_precision']:.1%}")
    print(f"  Most Hallucinated Technique IDs:")
    for tech_id, count in ha["most_hallucinated_techniques"].items():
        print(f"    {tech_id}: {count} times")
    print(f"  Hallucinations by Category:")
    for cat, count in ha["hallucinations_by_attack_category"].items():
        print(f"    {cat}: {count}")

    # Confidence calibration
    print("\n  📈 CONFIDENCE CALIBRATION")
    print("  " + "-" * 50)
    cc = report["confidence_calibration"]
    print(f"  Avg confidence when CORRECT: {cc['avg_confidence_when_correct']:.3f}")
    print(f"  Avg confidence when WRONG:   {cc['avg_confidence_when_incorrect']:.3f}")
    print(f"  Confidence gap: {cc['confidence_gap']:.3f}")
    print(f"  Overconfident wrong answers (≥0.8): {cc['overconfident_wrong_count']}")
    print(f"  ⚠️  {cc['interpretation']}")

    # Benign vs Attack
    print("\n  🛡️  BENIGN vs ATTACK DETECTION")
    print("  " + "-" * 50)
    ba = report["benign_vs_attack"]
    b = ba["benign_scenarios"]
    a = ba["attack_scenarios"]
    print(f"  Benign: {b['correctly_identified']}/{b['total']} correct, {b['false_escalations']} false escalations ({b['false_escalation_rate']:.1%})")
    if b["escalated_as"]:
        print(f"    Escalated as: {b['escalated_as']}")
    print(f"  Attacks: {a['correctly_detected']}/{a['total']} detected, {a['missed']} missed ({a['miss_rate']:.1%})")
    if a["missed_types"]:
        print(f"    Missed types: {a['missed_types']}")

    print("\n" + "=" * 70)


def generate_visualization_script(results_path: str, output_dir: str = "data/results"):
    """
    Generate a matplotlib visualization script.
    Run separately to create publication-quality figures.
    """
    script = '''"""
Auto-generated visualization for Guard Agent baseline results.
Run: python data/results/visualize_baseline.py
"""
import json
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')
import numpy as np
from pathlib import Path

# Load results
with open("RESULTS_PATH", "r") as f:
    data = json.load(f)

results = data["individual_results"]
metrics = data["summary_metrics"]

fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle("Week 1 Baseline: LLM-Only Threat Analysis", fontsize=14, fontweight="bold")

# --- Plot 1: Classification accuracy by category ---
ax1 = axes[0, 0]
categories = {}
for r in results:
    gt = r["evaluation"]["ground_truth_classification"]
    correct = r["evaluation"]["classification_correct"]
    if gt not in categories:
        categories[gt] = {"correct": 0, "total": 0}
    categories[gt]["total"] += 1
    if correct:
        categories[gt]["correct"] += 1

cats = sorted(categories.keys())
accuracies = [categories[c]["correct"] / categories[c]["total"] for c in cats]
colors = ["#2ecc71" if a >= 0.8 else "#f39c12" if a >= 0.5 else "#e74c3c" for a in accuracies]
ax1.barh(cats, accuracies, color=colors)
ax1.set_xlim(0, 1)
ax1.set_xlabel("Accuracy")
ax1.set_title("Classification Accuracy by Category")
ax1.axvline(x=0.8, color="gray", linestyle="--", alpha=0.5, label="80% threshold")

# --- Plot 2: Confidence distribution ---
ax2 = axes[0, 1]
correct_conf = [r["evaluation"]["confidence_score"] for r in results if r["evaluation"]["classification_correct"]]
wrong_conf = [r["evaluation"]["confidence_score"] for r in results if not r["evaluation"]["classification_correct"]]
ax2.hist(correct_conf, bins=10, alpha=0.6, label=f"Correct (n={len(correct_conf)})", color="#2ecc71")
ax2.hist(wrong_conf, bins=10, alpha=0.6, label=f"Wrong (n={len(wrong_conf)})", color="#e74c3c")
ax2.set_xlabel("Confidence Score")
ax2.set_ylabel("Count")
ax2.set_title("Confidence Calibration")
ax2.legend()

# --- Plot 3: Severity error distribution ---
ax3 = axes[1, 0]
severity_errors = [r["evaluation"]["severity_error"] for r in results]
ax3.hist(severity_errors, bins=range(0, 6), alpha=0.7, color="#3498db", edgecolor="black")
ax3.set_xlabel("Severity Level Error (|predicted - actual|)")
ax3.set_ylabel("Count")
ax3.set_title("Severity Assessment Error Distribution")
ax3.set_xticks(range(0, 5))

# --- Plot 4: Technique overlap ---
ax4 = axes[1, 1]
overlaps = [r["evaluation"]["technique_overlap_jaccard"] for r in results]
attack_overlaps = [r["evaluation"]["technique_overlap_jaccard"] for r in results if r["evaluation"]["ground_truth_is_attack"]]
benign_overlaps = [r["evaluation"]["technique_overlap_jaccard"] for r in results if not r["evaluation"]["ground_truth_is_attack"]]
ax4.hist(attack_overlaps, bins=10, alpha=0.6, label=f"Attack (n={len(attack_overlaps)})", color="#e74c3c")
ax4.hist(benign_overlaps, bins=10, alpha=0.6, label=f"Benign (n={len(benign_overlaps)})", color="#2ecc71")
ax4.set_xlabel("ATT&CK Technique Overlap (Jaccard)")
ax4.set_ylabel("Count")
ax4.set_title("MITRE ATT&CK Mapping Accuracy")
ax4.legend()

plt.tight_layout()
plt.savefig("OUTPUT_DIR/baseline_llm_analysis.png", dpi=150, bbox_inches="tight")
print("Saved: OUTPUT_DIR/baseline_llm_analysis.png")
'''.replace("RESULTS_PATH", results_path).replace("OUTPUT_DIR", output_dir)

    script_path = Path(output_dir) / "visualize_baseline.py"
    with open(script_path, "w") as f:
        f.write(script)
    print(f"   Visualization script saved to: {script_path}")


# ============================================
# COMPARISON ACROSS CONFIGURATIONS (Week 5+)
# ============================================

def compare_configurations(paths: list[str]):
    """
    Compare results across LLM-only, LLM+RAG, LLM+RAG+Guard.
    Used from Week 5 onward.
    """
    configs = []
    for path in paths:
        with open(path, "r") as f:
            data = json.load(f)
        configs.append(data)

    print("\n" + "=" * 80)
    print("  CONFIGURATION COMPARISON")
    print("=" * 80)

    headers = ["Metric"]
    for c in configs:
        headers.append(c.get("experiment", "Unknown")[:25])

    # Build comparison rows
    rows = []
    metric_keys = [
        ("Classification Accuracy", "classification_accuracy"),
        ("F1 Score", ("binary_detection", "f1_score")),
        ("Precision", ("binary_detection", "precision")),
        ("Recall", ("binary_detection", "recall")),
        ("False Escalation Rate", "false_escalation_rate"),
        ("Hallucination Rate", ("technique_mapping", "hallucination_rate")),
        ("Avg Confidence", "avg_confidence"),
        ("Avg Inference Time (s)", "avg_inference_time_seconds"),
        ("Parse Success Rate", "parse_success_rate"),
    ]

    for label, key in metric_keys:
        row = [label]
        for c in configs:
            m = c.get("summary_metrics", {})
            if isinstance(key, tuple):
                val = m.get(key[0], {}).get(key[1], "N/A")
            else:
                val = m.get(key, "N/A")
            row.append(f"{val:.4f}" if isinstance(val, (int, float)) else str(val))
        rows.append(row)

    # Print table
    col_widths = [max(len(str(row[i])) for row in [headers] + rows) + 2 for i in range(len(headers))]
    header_line = "".join(str(h).ljust(w) for h, w in zip(headers, col_widths))
    print(f"\n  {header_line}")
    print("  " + "-" * sum(col_widths))
    for row in rows:
        line = "".join(str(v).ljust(w) for v, w in zip(row, col_widths))
        print(f"  {line}")

    print("\n" + "=" * 80)


# ============================================
# CLI
# ============================================

def main():
    parser = argparse.ArgumentParser(description="Guard Agent - Evaluation")
    parser.add_argument("--results", type=str, help="Path to results JSON")
    parser.add_argument("--compare", nargs="+", help="Compare multiple result files")
    parser.add_argument("--visualize", action="store_true", help="Generate visualization script")
    args = parser.parse_args()

    if args.compare:
        compare_configurations(args.compare)
    elif args.results:
        report = generate_full_report(args.results)
        print_detailed_report(report)
        if args.visualize:
            output_dir = str(Path(args.results).parent)
            generate_visualization_script(args.results, output_dir)
    else:
        print("Usage:")
        print("  python -m src.utils.evaluation --results data/results/baseline_llm_results.json")
        print("  python -m src.utils.evaluation --results data/results/baseline_llm_results.json --visualize")
        print("  python -m src.utils.evaluation --compare baseline.json rag.json guard.json")


if __name__ == "__main__":
    main()
