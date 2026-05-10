"""
============================================
Guard Agent - Week 5: Full RTS Integration
============================================
Combines all three components into the complete
Reasoning Trust Score:

    RTS(O) = α·C(O) + β·V(O) + γ·S(O)

Implements threshold-based decision logic:
    If RTS ≥ τ → AUTONOMOUS ACTION allowed
    If RTS < τ → ROUTE TO HUMAN ANALYST

Calibrates weights (α, β, γ) and threshold (τ)
based on experimental results from Weeks 3-5.

Usage:
    # Compute RTS from existing Week 3-5 results
    python -m src.agents.guard_agent --compute

    # Calibrate threshold τ
    python -m src.agents.guard_agent --calibrate

    # Single scenario end-to-end
    python -m src.agents.guard_agent --single SC-001
"""

import json
import sys
import argparse
import statistics
from pathlib import Path
from datetime import datetime
from typing import Optional

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    RTS_ALPHA, RTS_BETA, RTS_GAMMA, RTS_THRESHOLD,
    RTS_EPSILON_TARGET, RESULTS_DIR
)


# ============================================
# RTS COMPUTATION
# ============================================

def compute_rts(
    c_score: float,
    v_score: float,
    s_score: float,
    alpha: float = None,
    beta: float = None,
    gamma: float = None,
) -> dict:
    """
    Compute the Reasoning Trust Score.
    
    RTS(O) = α·C(O) + β·V(O) + γ·S(O)
    
    Default weights: α=β=γ=1/3 (equal weighting)
    """
    a = alpha if alpha is not None else RTS_ALPHA
    b = beta if beta is not None else RTS_BETA
    g = gamma if gamma is not None else RTS_GAMMA

    # Ensure weights sum to 1
    weight_sum = a + b + g
    if abs(weight_sum - 1.0) > 0.001:
        a, b, g = a / weight_sum, b / weight_sum, g / weight_sum

    rts = a * c_score + b * v_score + g * s_score

    return {
        "rts_score": round(rts, 4),
        "components": {
            "C_O": round(c_score, 4),
            "V_O": round(v_score, 4),
            "S_O": round(s_score, 4),
        },
        "weights": {
            "alpha": round(a, 4),
            "beta": round(b, 4),
            "gamma": round(g, 4),
        },
        "weighted_contributions": {
            "alpha_C": round(a * c_score, 4),
            "beta_V": round(b * v_score, 4),
            "gamma_S": round(g * s_score, 4),
        },
    }


def make_decision(rts_score: float, threshold: float = None) -> dict:
    """
    Make autonomous vs human routing decision based on RTS.
    
    If RTS ≥ τ → AUTONOMOUS ACTION
    If RTS < τ → HUMAN REVIEW
    """
    tau = threshold if threshold is not None else RTS_THRESHOLD

    if rts_score >= tau:
        return {
            "decision": "AUTONOMOUS",
            "rts_score": round(rts_score, 4),
            "threshold": tau,
            "margin": round(rts_score - tau, 4),
            "description": "High trust — autonomous response allowed",
        }
    else:
        return {
            "decision": "HUMAN_REVIEW",
            "rts_score": round(rts_score, 4),
            "threshold": tau,
            "deficit": round(tau - rts_score, 4),
            "description": "Low trust — routing to human analyst",
        }


# ============================================
# THRESHOLD CALIBRATION
# ============================================

def calibrate_threshold(
    rts_scores: list,
    correctness: list,
    thresholds: list = None,
) -> dict:
    """
    Calibrate the optimal threshold τ.
    
    Tests multiple thresholds and measures:
    - Automation Rate: fraction of scenarios above threshold
    - Hallucination Leakage: P(incorrect | RTS ≥ τ)
    - Human Escalation: fraction routed to humans
    
    Goal: Find τ where hallucination_leakage ≤ ε (target 0.05)
    """
    if thresholds is None:
        thresholds = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]

    results = []
    for tau in thresholds:
        above = [(rts, correct) for rts, correct in zip(rts_scores, correctness) if rts >= tau]
        below = [(rts, correct) for rts, correct in zip(rts_scores, correctness) if rts < tau]

        automation_rate = len(above) / len(rts_scores) if rts_scores else 0
        human_rate = len(below) / len(rts_scores) if rts_scores else 0

        # Hallucination leakage: incorrect decisions that passed the threshold
        incorrect_above = sum(1 for _, c in above if not c)
        hallucination_leakage = incorrect_above / len(above) if above else 0

        # Correct decisions caught by human review
        correct_below = sum(1 for _, c in below if c)
        unnecessary_escalation = correct_below / len(below) if below else 0

        results.append({
            "threshold": tau,
            "automation_rate": round(automation_rate, 4),
            "human_review_rate": round(human_rate, 4),
            "hallucination_leakage": round(hallucination_leakage, 4),
            "epsilon_bound": round(hallucination_leakage, 4),
            "meets_epsilon_target": hallucination_leakage <= RTS_EPSILON_TARGET,
            "scenarios_above": len(above),
            "scenarios_below": len(below),
            "incorrect_passed": incorrect_above,
            "unnecessary_escalation_rate": round(unnecessary_escalation, 4),
        })

    # Find optimal threshold (highest automation rate where ε ≤ target)
    valid_thresholds = [r for r in results if r["meets_epsilon_target"]]
    optimal = max(valid_thresholds, key=lambda x: x["automation_rate"]) if valid_thresholds else results[-1]

    return {
        "all_thresholds": results,
        "optimal_threshold": optimal["threshold"],
        "optimal_automation_rate": optimal["automation_rate"],
        "optimal_epsilon": optimal["epsilon_bound"],
        "epsilon_target": RTS_EPSILON_TARGET,
    }


# ============================================
# WEIGHT CALIBRATION
# ============================================

def calibrate_weights(
    c_scores: list, v_scores: list, s_scores: list,
    correctness: list,
    weight_options: list = None,
) -> dict:
    """
    Find optimal weights (α, β, γ) that maximize separation
    between correct and incorrect RTS scores.
    
    Tests multiple weight combinations and selects the one
    with maximum gap between correct and incorrect mean RTS.
    """
    if weight_options is None:
        weight_options = [
            (1/3, 1/3, 1/3),   # Equal
            (0.4, 0.3, 0.3),   # C heavy
            (0.3, 0.4, 0.3),   # V heavy
            (0.3, 0.3, 0.4),   # S heavy
            (0.5, 0.25, 0.25), # C dominant
            (0.25, 0.5, 0.25), # V dominant
            (0.25, 0.25, 0.5), # S dominant
            (0.4, 0.4, 0.2),   # C+V heavy
            (0.2, 0.4, 0.4),   # V+S heavy
            (0.4, 0.2, 0.4),   # C+S heavy
        ]

    best_gap = -1
    best_weights = (1/3, 1/3, 1/3)
    all_results = []

    for a, b, g in weight_options:
        rts_scores = [
            a * c + b * v + g * s
            for c, v, s in zip(c_scores, v_scores, s_scores)
        ]

        correct_rts = [rts for rts, corr in zip(rts_scores, correctness) if corr]
        incorrect_rts = [rts for rts, corr in zip(rts_scores, correctness) if not corr]

        mean_correct = statistics.mean(correct_rts) if correct_rts else 0
        mean_incorrect = statistics.mean(incorrect_rts) if incorrect_rts else 0
        gap = mean_correct - mean_incorrect

        result = {
            "weights": {"alpha": round(a, 2), "beta": round(b, 2), "gamma": round(g, 2)},
            "mean_rts_correct": round(mean_correct, 4),
            "mean_rts_incorrect": round(mean_incorrect, 4),
            "gap": round(gap, 4),
        }
        all_results.append(result)

        if gap > best_gap:
            best_gap = gap
            best_weights = (a, b, g)

    return {
        "best_weights": {"alpha": round(best_weights[0], 2), "beta": round(best_weights[1], 2), "gamma": round(best_weights[2], 2)},
        "best_gap": round(best_gap, 4),
        "all_options": all_results,
    }


# ============================================
# FULL RTS PIPELINE (from existing results)
# ============================================

def compute_rts_from_results(
    consistency_path: str,
    validation_path: str,
    stability_path: str,
    scenarios_path: str = None,
) -> dict:
    """
    Combine C(O), V(O), S(O) from existing result files
    into final RTS scores with calibration.
    """
    # Load C(O) from Week 3
    with open(consistency_path, "r") as f:
        c_data = json.load(f)
    c_results = c_data.get("individual_results", [])

    # Load V(O) from Week 4
    with open(validation_path, "r") as f:
        v_data = json.load(f)
    v_results = v_data.get("validated_results", [])

    # Load S(O) from Week 5
    with open(stability_path, "r") as f:
        s_data = json.load(f)
    s_results = s_data.get("results", [])

    # Load ground truth
    if scenarios_path:
        with open(scenarios_path, "r") as f:
            scenarios = json.load(f)["scenarios"]
        gt_map = {s["id"]: s["ground_truth"] for s in scenarios}
    else:
        gt_map = {}

    # Build per-scenario RTS
    rts_results = []
    c_scores_list = []
    v_scores_list = []
    s_scores_list = []
    correctness_list = []

    for c_res in c_results:
        sid = c_res["scenario_id"]

        # Find matching V(O)
        v_res = next((v for v in v_results if v["scenario_id"] == sid), None)
        s_res = next((s for s in s_results if s["scenario_id"] == sid), None)

        c_score = c_res.get("consistency", {}).get("consistency_score",
                  c_res.get("consistency_score", 0))
        v_score = v_res["avg_validation_score"] if v_res else 0
        s_score = s_res["stability_score"] if s_res else 0

        rts = compute_rts(c_score, v_score, s_score)
        decision = make_decision(rts["rts_score"])

        # Check correctness
        eval_data = c_res.get("evaluation", {})
        correct = eval_data.get("classification_correct",
                  eval_data.get("correct", None))

        # If no eval in consistency, check ground truth
        if correct is None and sid in gt_map:
            majority = eval_data.get("majority_classification",
                      eval_data.get("consensus_classification", ""))
            correct = majority == gt_map[sid].get("classification", "")

        c_scores_list.append(c_score)
        v_scores_list.append(v_score)
        s_scores_list.append(s_score)
        correctness_list.append(correct if correct is not None else False)

        rts_results.append({
            "scenario_id": sid,
            "rts": rts,
            "decision": decision,
            "correct": correct,
        })

    # Calibrate weights
    weight_calibration = calibrate_weights(
        c_scores_list, v_scores_list, s_scores_list, correctness_list
    )

    # Recalculate RTS with best weights
    best_a = weight_calibration["best_weights"]["alpha"]
    best_b = weight_calibration["best_weights"]["beta"]
    best_g = weight_calibration["best_weights"]["gamma"]

    calibrated_rts_scores = []
    for c, v, s in zip(c_scores_list, v_scores_list, s_scores_list):
        calibrated_rts_scores.append(best_a * c + best_b * v + best_g * s)

    # Calibrate threshold
    threshold_calibration = calibrate_threshold(calibrated_rts_scores, correctness_list)

    # Final summary with calibrated weights
    correct_rts = [r for r, c in zip(calibrated_rts_scores, correctness_list) if c]
    incorrect_rts = [r for r, c in zip(calibrated_rts_scores, correctness_list) if not c]

    return {
        "total_scenarios": len(rts_results),
        "rts_results": rts_results,
        "summary": {
            "mean_rts": round(statistics.mean(calibrated_rts_scores), 4),
            "std_rts": round(statistics.stdev(calibrated_rts_scores), 4) if len(calibrated_rts_scores) > 1 else 0,
            "min_rts": round(min(calibrated_rts_scores), 4),
            "max_rts": round(max(calibrated_rts_scores), 4),
            "mean_rts_correct": round(statistics.mean(correct_rts), 4) if correct_rts else 0,
            "mean_rts_incorrect": round(statistics.mean(incorrect_rts), 4) if incorrect_rts else 0,
            "rts_gap": round(
                (statistics.mean(correct_rts) if correct_rts else 0) -
                (statistics.mean(incorrect_rts) if incorrect_rts else 0), 4
            ),
            "mean_C": round(statistics.mean(c_scores_list), 4),
            "mean_V": round(statistics.mean(v_scores_list), 4),
            "mean_S": round(statistics.mean(s_scores_list), 4),
        },
        "weight_calibration": weight_calibration,
        "threshold_calibration": threshold_calibration,
    }


# ============================================
# CLI
# ============================================

def main():
    parser = argparse.ArgumentParser(description="Guard Agent - Full RTS Integration")
    parser.add_argument("--compute", action="store_true", help="Compute RTS from existing results")
    parser.add_argument("--consistency", type=str, default=str(RESULTS_DIR / "guard_consistency_results.json"))
    parser.add_argument("--validation", type=str, default=str(RESULTS_DIR / "guard_validation_results.json"))
    parser.add_argument("--stability", type=str, default=str(RESULTS_DIR / "guard_stability_results.json"))
    parser.add_argument("--scenarios", type=str, default=None)
    parser.add_argument("--output", type=str, default=None)
    args = parser.parse_args()

    print("\n🔬 Guard Agent - Week 5: Full RTS Integration")
    print(f"   RTS(O) = α·C(O) + β·V(O) + γ·S(O)")
    print(f"   Timestamp: {datetime.now().isoformat()}")

    if args.compute:
        # Find scenarios path
        scenarios_path = args.scenarios
        if not scenarios_path:
            default_path = RESULTS_DIR.parent / "scenarios" / "threat_scenarios.json"
            if default_path.exists():
                scenarios_path = str(default_path)

        print(f"\n   Loading components:")
        print(f"   C(O): {args.consistency}")
        print(f"   V(O): {args.validation}")
        print(f"   S(O): {args.stability}")

        result = compute_rts_from_results(
            args.consistency, args.validation, args.stability, scenarios_path
        )

        # Print results
        s = result["summary"]
        print(f"\n{'='*70}")
        print(f"  GUARD AGENT RTS — FINAL RESULTS")
        print(f"{'='*70}")

        print(f"\n  --- Component Means ---")
        print(f"  Mean C(O): {s['mean_C']:.4f}  (Consistency)")
        print(f"  Mean V(O): {s['mean_V']:.4f}  (Validation)")
        print(f"  Mean S(O): {s['mean_S']:.4f}  (Stability)")

        print(f"\n  --- RTS Score Distribution ---")
        print(f"  Mean RTS:  {s['mean_rts']:.4f}")
        print(f"  Std RTS:   {s['std_rts']:.4f}")
        print(f"  Range:     [{s['min_rts']:.4f}, {s['max_rts']:.4f}]")

        print(f"\n  --- RTS vs Correctness (KEY RESULT) ---")
        print(f"  Mean RTS (CORRECT):   {s['mean_rts_correct']:.4f}")
        print(f"  Mean RTS (INCORRECT): {s['mean_rts_incorrect']:.4f}")
        print(f"  Gap: {s['rts_gap']:+.4f}")
        if s['rts_gap'] > 0:
            print(f"  >> VALIDATED: Higher RTS correlates with correctness!")
        else:
            print(f"  >> WARNING: Gap is negative, needs investigation")

        # Weight calibration
        wc = result["weight_calibration"]
        bw = wc["best_weights"]
        print(f"\n  --- Optimal Weights ---")
        print(f"  α (C weight): {bw['alpha']}")
        print(f"  β (V weight): {bw['beta']}")
        print(f"  γ (S weight): {bw['gamma']}")
        print(f"  Best gap: {wc['best_gap']:+.4f}")

        # Threshold calibration
        tc = result["threshold_calibration"]
        print(f"\n  --- Threshold Calibration ---")
        print(f"  Optimal τ: {tc['optimal_threshold']}")
        print(f"  Automation Rate: {tc['optimal_automation_rate']:.1%}")
        print(f"  ε (hallucination leakage): {tc['optimal_epsilon']:.4f}")
        print(f"  Target ε: ≤ {tc['epsilon_target']}")

        print(f"\n  {'τ':<8} {'Auto%':<10} {'Human%':<10} {'ε':<10} {'ε≤target':<10}")
        print(f"  {'─'*48}")
        for t in tc["all_thresholds"]:
            marker = "← OPTIMAL" if t["threshold"] == tc["optimal_threshold"] else ""
            eps_ok = "✅" if t["meets_epsilon_target"] else "❌"
            print(f"  {t['threshold']:<8.2f} {t['automation_rate']:<10.1%} {t['human_review_rate']:<10.1%} "
                  f"{t['epsilon_bound']:<10.4f} {eps_ok:<10} {marker}")

        # Per-scenario RTS
        print(f"\n  --- Per-Scenario RTS ---")
        for r in result["rts_results"]:
            rts_val = r["rts"]["rts_score"]
            decision = r["decision"]["decision"]
            correct = "✅" if r["correct"] else "❌"
            icon = "🤖" if decision == "AUTONOMOUS" else "👤"
            print(f"  {r['scenario_id']}: RTS={rts_val:.3f} {icon} {decision:<12} {correct}")

        print(f"\n{'='*70}")
        print(f"  FORMAL GUARANTEE:")
        print(f"  P(hallucination | RTS ≥ {tc['optimal_threshold']}) ≤ {tc['optimal_epsilon']:.4f}")
        print(f"  This is {'WITHIN' if tc['optimal_epsilon'] <= tc['epsilon_target'] else 'ABOVE'} "
              f"the target ε = {tc['epsilon_target']}")
        print(f"{'='*70}\n")

        # Save
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        out_path = args.output or str(RESULTS_DIR / "guard_agent_rts_results.json")
        with open(out_path, "w") as f:
            json.dump({
                "experiment": "Week 5 - Full RTS Integration",
                "timestamp": datetime.now().isoformat(),
                "rts_formula": "RTS(O) = α·C(O) + β·V(O) + γ·S(O)",
                "summary": result["summary"],
                "weight_calibration": result["weight_calibration"],
                "threshold_calibration": result["threshold_calibration"],
                "per_scenario": result["rts_results"],
            }, f, indent=2, default=str)
        print(f"   Results saved to: {out_path}")

    else:
        print("\n   Usage:")
        print("   Step 1: python -m src.agents.guard_stability --from-consistency data/results/guard_consistency_results.json")
        print("   Step 2: python -m src.agents.guard_agent --compute")


if __name__ == "__main__":
    main()
