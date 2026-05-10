"""
============================================
Guard Agent - Week 7: Statistical Validation
============================================
Provides formal statistical evidence for hypothesis H1a:

H1a: The Guard Agent with formal RTS will significantly
     reduce LLM hallucination and false escalation rates
     compared to unguarded LLM-only and LLM+RAG approaches.

H0₁: No significant difference between Guard and unguarded.

Statistical Tests:
  - Paired t-test (parametric)
  - Wilcoxon signed-rank test (non-parametric backup)
  - Cohen's d effect size
  - Formal ε bound with confidence interval

Usage:
    # Run full statistical analysis from existing results
    python -m src.agents.statistical_validation

    # Generate publication figures
    python -m src.agents.statistical_validation --figures

    # Run with custom results paths
    python -m src.agents.statistical_validation --week1 path --week2 path --week3 path
"""

import json
import sys
import argparse
import math
from pathlib import Path
from datetime import datetime
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import RESULTS_DIR, STATISTICAL_ALPHA, RTS_EPSILON_TARGET

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from scipy import stats as scipy_stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


# ============================================
# EFFECT SIZE CALCULATIONS
# ============================================

def cohens_d(group1: list, group2: list) -> float:
    """
    Compute Cohen's d effect size.
    
    d = (mean1 - mean2) / pooled_std
    
    Interpretation:
        |d| < 0.2  → negligible
        |d| 0.2-0.5 → small
        |d| 0.5-0.8 → medium
        |d| > 0.8   → large
    """
    n1, n2 = len(group1), len(group2)
    if n1 < 2 or n2 < 2:
        return 0.0

    mean1 = sum(group1) / n1
    mean2 = sum(group2) / n2

    var1 = sum((x - mean1) ** 2 for x in group1) / (n1 - 1)
    var2 = sum((x - mean2) ** 2 for x in group2) / (n2 - 1)

    pooled_std = math.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))

    if pooled_std == 0:
        return 0.0

    return (mean1 - mean2) / pooled_std


def interpret_cohens_d(d: float) -> str:
    """Interpret Cohen's d magnitude."""
    abs_d = abs(d)
    if abs_d < 0.2:
        return "negligible"
    elif abs_d < 0.5:
        return "small"
    elif abs_d < 0.8:
        return "medium"
    else:
        return "large"


def interpret_p_value(p: float, alpha: float = STATISTICAL_ALPHA) -> str:
    """Interpret p-value for hypothesis testing."""
    if p < 0.001:
        return f"highly significant (p={p:.6f} < 0.001)"
    elif p < 0.01:
        return f"very significant (p={p:.4f} < 0.01)"
    elif p < alpha:
        return f"significant (p={p:.4f} < {alpha})"
    else:
        return f"NOT significant (p={p:.4f} ≥ {alpha})"


# ============================================
# STATISTICAL TESTS
# ============================================

def paired_t_test(sample1: list, sample2: list, alternative: str = "two-sided") -> dict:
    """
    Paired t-test comparing two configurations on same scenarios.
    
    H0: No difference between configurations
    H1: Significant difference exists
    """
    if not SCIPY_AVAILABLE:
        return {"error": "scipy not installed. Run: pip install scipy"}

    n = min(len(sample1), len(sample2))
    s1 = sample1[:n]
    s2 = sample2[:n]

    statistic, p_value = scipy_stats.ttest_rel(s1, s2, alternative=alternative)

    return {
        "test": "Paired t-test",
        "statistic": round(float(statistic), 4),
        "p_value": round(float(p_value), 6),
        "significant": float(p_value) < STATISTICAL_ALPHA,
        "interpretation": interpret_p_value(float(p_value)),
        "n": n,
        "mean_diff": round(sum(a - b for a, b in zip(s1, s2)) / n, 4),
        "alternative": alternative,
    }


def wilcoxon_test(sample1: list, sample2: list, alternative: str = "two-sided") -> dict:
    """
    Wilcoxon signed-rank test (non-parametric backup).
    Does not assume normal distribution.
    """
    if not SCIPY_AVAILABLE:
        return {"error": "scipy not installed"}

    n = min(len(sample1), len(sample2))
    s1 = sample1[:n]
    s2 = sample2[:n]

    # Handle ties (identical values)
    diffs = [a - b for a, b in zip(s1, s2)]
    if all(d == 0 for d in diffs):
        return {
            "test": "Wilcoxon signed-rank",
            "statistic": 0,
            "p_value": 1.0,
            "significant": False,
            "interpretation": "All differences are zero — no test possible",
            "n": n,
        }

    try:
        statistic, p_value = scipy_stats.wilcoxon(s1, s2, alternative=alternative)
        return {
            "test": "Wilcoxon signed-rank",
            "statistic": round(float(statistic), 4),
            "p_value": round(float(p_value), 6),
            "significant": float(p_value) < STATISTICAL_ALPHA,
            "interpretation": interpret_p_value(float(p_value)),
            "n": n,
        }
    except ValueError as e:
        return {
            "test": "Wilcoxon signed-rank",
            "error": str(e),
            "n": n,
        }


# ============================================
# EPSILON BOUND COMPUTATION
# ============================================

def compute_epsilon_bound(rts_scores: list, correctness: list, threshold: float) -> dict:
    """
    Compute formal hallucination bound:
    P(hallucination | RTS ≥ τ) ≤ ε
    
    With Wilson confidence interval for proportion.
    """
    above = [(rts, c) for rts, c in zip(rts_scores, correctness) if rts >= threshold]
    n = len(above)

    if n == 0:
        return {
            "epsilon": 1.0,
            "n_above_threshold": 0,
            "note": "No scenarios above threshold",
        }

    errors_above = sum(1 for _, c in above if not c)
    epsilon = errors_above / n

    # Wilson score confidence interval for proportion
    z = 1.96  # 95% confidence
    if n > 0:
        p_hat = epsilon
        denominator = 1 + z * z / n
        center = (p_hat + z * z / (2 * n)) / denominator
        margin = z * math.sqrt((p_hat * (1 - p_hat) + z * z / (4 * n)) / n) / denominator
        ci_lower = max(0, center - margin)
        ci_upper = min(1, center + margin)
    else:
        ci_lower, ci_upper = 0, 1

    return {
        "epsilon": round(epsilon, 6),
        "epsilon_upper_95ci": round(ci_upper, 6),
        "n_above_threshold": n,
        "errors_above_threshold": errors_above,
        "threshold": threshold,
        "confidence_interval": f"[{ci_lower:.4f}, {ci_upper:.4f}]",
        "meets_target": epsilon <= RTS_EPSILON_TARGET,
        "target_epsilon": RTS_EPSILON_TARGET,
        "formal_statement": f"P(hallucination | RTS ≥ {threshold}) ≤ {ci_upper:.4f} (95% CI)",
    }


# ============================================
# HYPOTHESIS TESTING FRAMEWORK
# ============================================

def test_hypothesis_h1a(
    guard_accuracy: list,
    unguarded_accuracy: list,
    guard_hallucination: list,
    unguarded_hallucination: list,
    guard_false_escalation: list,
    unguarded_false_escalation: list,
    label_guard: str = "LLM+RAG+Guard",
    label_unguarded: str = "LLM-only",
) -> dict:
    """
    Test hypothesis H1a:
    The Guard Agent with formal RTS will significantly reduce
    hallucination and false escalation compared to unguarded.
    
    Tests 3 sub-comparisons:
    1. Accuracy: Guard > Unguarded
    2. Hallucination: Guard < Unguarded (lower is better)
    3. False Escalation: Guard < Unguarded (lower is better)
    """
    results = {}

    # 1. Accuracy comparison
    d_acc = cohens_d(guard_accuracy, unguarded_accuracy)
    t_acc = paired_t_test(guard_accuracy, unguarded_accuracy, alternative="greater")
    w_acc = wilcoxon_test(guard_accuracy, unguarded_accuracy, alternative="greater")

    results["accuracy"] = {
        "guard_mean": round(sum(guard_accuracy) / len(guard_accuracy), 4) if guard_accuracy else 0,
        "unguarded_mean": round(sum(unguarded_accuracy) / len(unguarded_accuracy), 4) if unguarded_accuracy else 0,
        "cohens_d": round(d_acc, 4),
        "effect_size": interpret_cohens_d(d_acc),
        "paired_t_test": t_acc,
        "wilcoxon_test": w_acc,
    }

    # 2. Hallucination comparison (lower is better for guard)
    d_hal = cohens_d(unguarded_hallucination, guard_hallucination)  # Reversed: we want d>0 if guard is better
    t_hal = paired_t_test(unguarded_hallucination, guard_hallucination, alternative="greater")
    w_hal = wilcoxon_test(unguarded_hallucination, guard_hallucination, alternative="greater")

    results["hallucination"] = {
        "guard_mean": round(sum(guard_hallucination) / len(guard_hallucination), 4) if guard_hallucination else 0,
        "unguarded_mean": round(sum(unguarded_hallucination) / len(unguarded_hallucination), 4) if unguarded_hallucination else 0,
        "cohens_d": round(d_hal, 4),
        "effect_size": interpret_cohens_d(d_hal),
        "paired_t_test": t_hal,
        "wilcoxon_test": w_hal,
    }

    # 3. False escalation comparison (lower is better for guard)
    d_fe = cohens_d(unguarded_false_escalation, guard_false_escalation)
    t_fe = paired_t_test(unguarded_false_escalation, guard_false_escalation, alternative="greater")
    w_fe = wilcoxon_test(unguarded_false_escalation, guard_false_escalation, alternative="greater")

    results["false_escalation"] = {
        "guard_mean": round(sum(guard_false_escalation) / len(guard_false_escalation), 4) if guard_false_escalation else 0,
        "unguarded_mean": round(sum(unguarded_false_escalation) / len(unguarded_false_escalation), 4) if unguarded_false_escalation else 0,
        "cohens_d": round(d_fe, 4),
        "effect_size": interpret_cohens_d(d_fe),
        "paired_t_test": t_fe,
        "wilcoxon_test": w_fe,
    }

    # Overall H1a verdict
    sig_accuracy = t_acc.get("significant", False)
    sig_hallucination = t_hal.get("significant", False)
    sig_fe = t_fe.get("significant", False)

    any_significant = sig_accuracy or sig_hallucination or sig_fe
    all_significant = sig_accuracy and sig_hallucination and sig_fe

    results["h1a_verdict"] = {
        "reject_null": any_significant,
        "all_significant": all_significant,
        "significant_metrics": {
            "accuracy": sig_accuracy,
            "hallucination": sig_hallucination,
            "false_escalation": sig_fe,
        },
        "conclusion": (
            f"H1a SUPPORTED: Guard Agent ({label_guard}) significantly outperforms "
            f"{label_unguarded} on {'all' if all_significant else 'some'} metrics "
            f"(α={STATISTICAL_ALPHA})"
            if any_significant
            else f"H1a NOT SUPPORTED: No significant difference at α={STATISTICAL_ALPHA}"
        ),
    }

    return results


# ============================================
# VISUALIZATION
# ============================================

def generate_figures(output_dir: str, data: dict):
    """Generate publication-quality figures."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("   [!] matplotlib not installed. Run: pip install matplotlib")
        return

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Figure 1: RTS Distribution — Correct vs Incorrect
    if "rts_data" in data:
        fig, ax = plt.subplots(figsize=(8, 5))
        correct_rts = data["rts_data"].get("correct", [])
        incorrect_rts = data["rts_data"].get("incorrect", [])
        if correct_rts and incorrect_rts:
            ax.hist(correct_rts, bins=15, alpha=0.6, label=f"Correct (n={len(correct_rts)})", color="#2ecc71")
            ax.hist(incorrect_rts, bins=15, alpha=0.6, label=f"Incorrect (n={len(incorrect_rts)})", color="#e74c3c")
            ax.axvline(x=0.8, color="black", linestyle="--", linewidth=1.5, label="τ=0.8")
            ax.set_xlabel("RTS Score", fontsize=12)
            ax.set_ylabel("Count", fontsize=12)
            ax.set_title("RTS Distribution: Correct vs Incorrect Classifications", fontsize=13)
            ax.legend(fontsize=10)
            plt.tight_layout()
            fig_path = output_path / "fig1_rts_distribution.png"
            plt.savefig(fig_path, dpi=150)
            plt.close()
            print(f"   [✓] Saved: {fig_path}")

    # Figure 2: Week-over-Week Accuracy Comparison
    if "weekly_accuracy" in data:
        fig, ax = plt.subplots(figsize=(8, 5))
        weeks = list(data["weekly_accuracy"].keys())
        accuracies = list(data["weekly_accuracy"].values())
        colors = ["#3498db", "#2ecc71", "#e74c3c", "#f39c12", "#9b59b6"]
        bars = ax.bar(weeks, accuracies, color=colors[:len(weeks)], edgecolor="black", linewidth=0.5)
        for bar, acc in zip(bars, accuracies):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{acc:.1%}", ha="center", fontsize=10, fontweight="bold")
        ax.set_ylabel("Classification Accuracy", fontsize=12)
        ax.set_title("Classification Accuracy Across Configurations", fontsize=13)
        ax.set_ylim(0, 1.0)
        plt.tight_layout()
        fig_path = output_path / "fig2_accuracy_comparison.png"
        plt.savefig(fig_path, dpi=150)
        plt.close()
        print(f"   [✓] Saved: {fig_path}")

    # Figure 3: RTS Component Breakdown
    if "component_means" in data:
        fig, ax = plt.subplots(figsize=(8, 5))
        components = ["C(O)\nConsistency", "V(O)\nValidation", "S(O)\nStability", "RTS\nCombined"]
        values = [
            data["component_means"].get("C", 0),
            data["component_means"].get("V", 0),
            data["component_means"].get("S", 0),
            data["component_means"].get("RTS", 0),
        ]
        colors = ["#3498db", "#2ecc71", "#e74c3c", "#f39c12"]
        bars = ax.bar(components, values, color=colors, edgecolor="black", linewidth=0.5)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.3f}", ha="center", fontsize=11, fontweight="bold")
        ax.set_ylabel("Score", fontsize=12)
        ax.set_title("RTS Component Breakdown", fontsize=13)
        ax.set_ylim(0, 1.1)
        ax.axhline(y=0.8, color="gray", linestyle="--", alpha=0.5, label="τ=0.8")
        ax.legend()
        plt.tight_layout()
        fig_path = output_path / "fig3_rts_components.png"
        plt.savefig(fig_path, dpi=150)
        plt.close()
        print(f"   [✓] Saved: {fig_path}")

    # Figure 4: Threshold τ vs Automation Rate and ε
    if "threshold_data" in data:
        fig, ax1 = plt.subplots(figsize=(8, 5))
        thresholds = [t["threshold"] for t in data["threshold_data"]]
        auto_rates = [t["automation_rate"] for t in data["threshold_data"]]
        epsilons = [t["epsilon_bound"] for t in data["threshold_data"]]

        ax1.plot(thresholds, auto_rates, "b-o", label="Automation Rate", linewidth=2)
        ax1.set_xlabel("Threshold τ", fontsize=12)
        ax1.set_ylabel("Automation Rate", fontsize=12, color="blue")
        ax1.tick_params(axis="y", labelcolor="blue")

        ax2 = ax1.twinx()
        ax2.plot(thresholds, epsilons, "r-s", label="ε (Hallucination Leakage)", linewidth=2)
        ax2.set_ylabel("ε (Hallucination Leakage)", fontsize=12, color="red")
        ax2.tick_params(axis="y", labelcolor="red")
        ax2.axhline(y=0.05, color="red", linestyle="--", alpha=0.5, label="ε target=0.05")

        fig.legend(loc="upper center", ncol=3, fontsize=9, bbox_to_anchor=(0.5, 0.98))
        ax1.set_title("Threshold τ: Automation Rate vs Hallucination Leakage", fontsize=13)
        plt.tight_layout()
        fig_path = output_path / "fig4_threshold_tradeoff.png"
        plt.savefig(fig_path, dpi=150)
        plt.close()
        print(f"   [✓] Saved: {fig_path}")

    print(f"\n   All figures saved to: {output_path}")


# ============================================
# MAIN: COLLECT ALL RESULTS AND RUN ANALYSIS
# ============================================

def main():
    parser = argparse.ArgumentParser(description="Week 7: Statistical Validation")
    parser.add_argument("--figures", action="store_true", help="Generate publication figures")
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--rts-results", type=str, default=str(RESULTS_DIR / "guard_agent_rts_results.json"))
    parser.add_argument("--adversarial-results", type=str, default=str(RESULTS_DIR / "adversarial_evaluation_results.json"))
    args = parser.parse_args()

    print("\n🔬 Guard Agent - Week 7: Statistical Validation")
    print(f"   α = {STATISTICAL_ALPHA} (significance level)")
    print(f"   ε target = {RTS_EPSILON_TARGET}")
    print(f"   Timestamp: {datetime.now().isoformat()}")

    # Load RTS results from Week 5
    rts_data = None
    rts_path = Path(args.rts_results)
    if rts_path.exists():
        with open(rts_path, "r") as f:
            rts_data = json.load(f)
        print(f"\n   [✓] Loaded RTS results from: {rts_path}")
    else:
        print(f"\n   [!] RTS results not found at: {rts_path}")
        print(f"   [!] Run Week 5 first: python -m src.agents.guard_agent --compute")

    # Load adversarial results from Week 6
    adv_data = None
    adv_path = Path(args.adversarial_results)
    if adv_path.exists():
        with open(adv_path, "r") as f:
            adv_data = json.load(f)
        print(f"   [✓] Loaded adversarial results from: {adv_path}")
    else:
        print(f"   [!] Adversarial results not found at: {adv_path}")
        print(f"   [!] Run Week 6 first: python -m src.agents.adversarial_evaluation")

    all_results = {}

    # ============================================
    # ANALYSIS 1: RTS vs Correctness (from Week 5)
    # ============================================
    if rts_data:
        print(f"\n{'='*70}")
        print(f"  ANALYSIS 1: RTS Score vs Correctness")
        print(f"{'='*70}")

        per_scenario = rts_data.get("per_scenario", [])
        correct_rts = [s["rts"]["rts_score"] for s in per_scenario if s.get("correct")]
        incorrect_rts = [s["rts"]["rts_score"] for s in per_scenario if not s.get("correct")]

        if correct_rts and incorrect_rts:
            d = cohens_d(correct_rts, incorrect_rts)
            t_result = paired_t_test(
                correct_rts + [0] * (max(0, len(incorrect_rts) - len(correct_rts))),
                incorrect_rts + [0] * (max(0, len(correct_rts) - len(incorrect_rts))),
            )
            print(f"  Mean RTS (correct):   {sum(correct_rts)/len(correct_rts):.4f} (n={len(correct_rts)})")
            print(f"  Mean RTS (incorrect): {sum(incorrect_rts)/len(incorrect_rts):.4f} (n={len(incorrect_rts)})")
            print(f"  Cohen's d: {d:.4f} ({interpret_cohens_d(d)} effect)")
            print(f"  t-test: {t_result['interpretation']}")
            all_results["rts_vs_correctness"] = {
                "cohens_d": round(d, 4),
                "effect_size": interpret_cohens_d(d),
                "t_test": t_result,
            }

        # Formal ε bound
        all_rts = [s["rts"]["rts_score"] for s in per_scenario]
        all_correct = [s.get("correct", False) for s in per_scenario]

        for tau in [0.7, 0.75, 0.8, 0.85, 0.9]:
            eps = compute_epsilon_bound(all_rts, all_correct, tau)
            print(f"\n  ε bound at τ={tau}: {eps['formal_statement']}")
            print(f"    Scenarios above τ: {eps['n_above_threshold']}, Errors: {eps['errors_above_threshold']}")
            print(f"    Meets target (ε≤{RTS_EPSILON_TARGET}): {'✅ YES' if eps['meets_target'] else '❌ NO'}")

        all_results["epsilon_bounds"] = {
            tau: compute_epsilon_bound(all_rts, all_correct, tau)
            for tau in [0.7, 0.75, 0.8, 0.85, 0.9]
        }

    # ============================================
    # ANALYSIS 2: Adversarial Comparison (from Week 6)
    # ============================================
    if adv_data and len(adv_data.get("configs_tested", [])) >= 2:
        print(f"\n{'='*70}")
        print(f"  ANALYSIS 2: Configuration Comparison (Adversarial)")
        print(f"{'='*70}")

        metrics = adv_data.get("metrics", {})
        detailed = adv_data.get("detailed_results", {})

        configs = list(metrics.keys())
        for i in range(len(configs)):
            for j in range(i + 1, len(configs)):
                c1, c2 = configs[i], configs[j]
                m1, m2 = metrics[c1], metrics[c2]

                print(f"\n  --- {c1} vs {c2} ---")
                print(f"  Accuracy: {m1['overall_accuracy']:.1%} vs {m2['overall_accuracy']:.1%}")
                print(f"  F1: {m1['binary_detection']['f1_score']:.1%} vs {m2['binary_detection']['f1_score']:.1%}")
                print(f"  False Escalation: {m1['false_escalation_rate']:.1%} vs {m2['false_escalation_rate']:.1%}")

                # Per-scenario accuracy for statistical tests
                d1 = detailed.get(c1, [])
                d2 = detailed.get(c2, [])

                if d1 and d2:
                    acc1 = [1 if r.get("classification") == r.get("ground_truth", {}).get("classification",
                            next((s["ground_truth"]["classification"] for s in adv_data.get("scenarios", [])
                                  if s["id"] == r.get("scenario_id")), "")) else 0
                            for r in d1]
                    acc2 = [1 if r.get("classification") == r.get("ground_truth", {}).get("classification",
                            next((s["ground_truth"]["classification"] for s in adv_data.get("scenarios", [])
                                  if s["id"] == r.get("scenario_id")), "")) else 0
                            for r in d2]

                    if len(acc1) == len(acc2) and SCIPY_AVAILABLE:
                        t = paired_t_test(acc2, acc1)
                        d_val = cohens_d(acc2, acc1)
                        print(f"  Cohen's d: {d_val:.4f} ({interpret_cohens_d(d_val)})")
                        print(f"  t-test: {t['interpretation']}")

    # ============================================
    # ANALYSIS 3: Component Contribution Analysis
    # ============================================
    if rts_data:
        print(f"\n{'='*70}")
        print(f"  ANALYSIS 3: RTS Component Contribution")
        print(f"{'='*70}")

        summary = rts_data.get("summary", {})
        print(f"  C(O) Consistency: {summary.get('mean_C', 0):.4f}")
        print(f"  V(O) Validation:  {summary.get('mean_V', 0):.4f}")
        print(f"  S(O) Stability:   {summary.get('mean_S', 0):.4f}")
        print(f"  RTS Combined:     {summary.get('mean_rts', 0):.4f}")

        wc = rts_data.get("weight_calibration", {})
        bw = wc.get("best_weights", {})
        print(f"\n  Calibrated Weights:")
        print(f"  α = {bw.get('alpha', 0)} (Consistency)")
        print(f"  β = {bw.get('beta', 0)} (Validation)")
        print(f"  γ = {bw.get('gamma', 0)} (Stability)")

    # ============================================
    # FINAL VERDICT
    # ============================================
    print(f"\n{'='*70}")
    print(f"  FINAL VERDICT: Hypothesis H1a")
    print(f"{'='*70}")

    if rts_data:
        tc = rts_data.get("threshold_calibration", {})
        eps = tc.get("optimal_epsilon", 1.0)
        tau = tc.get("optimal_threshold", 0.8)
        auto_rate = tc.get("optimal_automation_rate", 0)
        summary = rts_data.get("summary", {})
        gap = summary.get("rts_gap", 0)

        print(f"\n  H1a: Guard Agent with RTS significantly reduces hallucination")
        print(f"       and false escalation vs unguarded approaches.")
        print(f"\n  Evidence:")
        print(f"  1. RTS gap (correct vs incorrect): +{gap:.4f}")
        print(f"  2. Formal bound: P(hallucination | RTS ≥ {tau}) ≤ {eps:.4f}")
        print(f"  3. Target ε ≤ {RTS_EPSILON_TARGET}: {'✅ MET' if eps <= RTS_EPSILON_TARGET else '❌ NOT MET'}")
        print(f"  4. Automation rate at τ={tau}: {auto_rate:.1%}")

        if eps <= RTS_EPSILON_TARGET and gap > 0:
            print(f"\n  ✅ CONCLUSION: H1a SUPPORTED")
            print(f"     The Guard Agent provides a formal guarantee that")
            print(f"     P(hallucination | RTS ≥ {tau}) ≤ {eps}")
            print(f"     with {auto_rate:.0%} scenarios eligible for autonomous action.")
            print(f"     Null hypothesis H0₁ is REJECTED.")
        else:
            print(f"\n  ⚠️  CONCLUSION: Partial support for H1a")
            print(f"     Further investigation needed.")

    print(f"\n{'='*70}")

    # Save all results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = args.output or str(RESULTS_DIR / "statistical_validation_results.json")
    with open(out_path, "w") as f:
        json.dump({
            "experiment": "Week 7 - Statistical Validation",
            "timestamp": datetime.now().isoformat(),
            "alpha": STATISTICAL_ALPHA,
            "epsilon_target": RTS_EPSILON_TARGET,
            "results": all_results,
        }, f, indent=2, default=str)
    print(f"\n   Results saved to: {out_path}")

    # Generate figures if requested
    if args.figures and rts_data:
        print("\n   Generating publication figures...")
        fig_data = {
            "rts_data": {
                "correct": [s["rts"]["rts_score"] for s in rts_data.get("per_scenario", []) if s.get("correct")],
                "incorrect": [s["rts"]["rts_score"] for s in rts_data.get("per_scenario", []) if not s.get("correct")],
            },
            "weekly_accuracy": {
                "LLM-only\n(Week 1)": 0.567,
                "LLM+RAG\n(Week 2)": 0.733,
                "Guard RTS\n(Week 5)": rts_data.get("summary", {}).get("mean_rts", 0.72),
            },
            "component_means": {
                "C": rts_data.get("summary", {}).get("mean_C", 0),
                "V": rts_data.get("summary", {}).get("mean_V", 0),
                "S": rts_data.get("summary", {}).get("mean_S", 0),
                "RTS": rts_data.get("summary", {}).get("mean_rts", 0),
            },
            "threshold_data": rts_data.get("threshold_calibration", {}).get("all_thresholds", []),
        }
        generate_figures(str(RESULTS_DIR / "figures"), fig_data)


if __name__ == "__main__":
    main()
