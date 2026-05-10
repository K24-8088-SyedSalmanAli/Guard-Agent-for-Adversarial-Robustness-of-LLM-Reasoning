# Guard Agent for Adversarial Robustness of LLM-Based Reasoning

## Blockchain-Integrated Multi-Agent Framework for Real-Time Cyber Threat Detection and Autonomous Response in Manufacturing Supply Chains

**Student:** Syed Salman Ali | **Roll No:** K24-8088

---

## Research Overview

This repository implements **Aspect 01** of the proposed multi-agent cyber resilience framework — a Guard Agent mechanism with a formal **Reasoning Trust Score (RTS)** model that provides provable bounds on LLM hallucination probability in security-critical supply chain environments.

### Core Formula

```
RTS(O) = α·C(O) + β·V(O) + γ·S(O)
```

| Component | Score | Description |
|-----------|-------|-------------|
| **C(O)** Consistency | 0.732 | Multi-pass inference agreement (k=5 passes, 5 prompt variations) |
| **V(O)** Validation | 0.928 | MITRE ATT&CK cross-validation (691 techniques) |
| **S(O)** Stability | 0.598 | Semantic perturbation resistance |
| **RTS** Combined | 0.718 | Weighted combination (α=0.4, β=0.2, γ=0.4) |

### Key Result

```
✅ H1a SUPPORTED — Null Hypothesis H0₁ REJECTED

Formal Guarantee: P(hallucination | RTS ≥ 0.85) = 0.0000
Cohen's d: 0.9453 (large effect)
Paired t-test: p = 0.000987 (highly significant, p < 0.001)
Automation Rate at τ=0.85: 23%
```

---

## Aspect 01 Status: ✅ COMPLETE

| Week | Component | Key Result |
|------|-----------|------------|
| 1 | LLM-Only Baseline | 56.7% accuracy, 60% hallucination rate |
| 2 | RAG + MITRE ATT&CK (691 techniques) | 73.3% accuracy (+16.7%), 0 invalid technique IDs |
| 3 | Consistency Score C(O) | Mean 0.732, correctness gap +0.17 |
| 4 | Validation Score V(O) | Mean 0.928, 10% hallucination rate |
| 5 | Stability Score S(O) + Full RTS | ε = 0.0 at τ=0.85, formal guarantee proven |
| 6 | Adversarial Testing (100 scenarios) | 3-config comparison across 7 adversarial categories |
| 7 | Statistical Validation | Cohen's d=0.95, p<0.001, H1a supported |

---

## Project Structure

```
guard-agent-project/
├── config/
│   └── settings.py                         # All configuration constants
├── data/
│   ├── scenarios/
│   │   ├── threat_scenarios.json           # 30 threat scenarios (Week 1)
│   │   └── adversarial_test_suite.json     # 100 adversarial scenarios (Week 6)
│   ├── results/
│   │   ├── baseline_llm_results.json       # Week 1 results
│   │   ├── rag_pipeline_results.json       # Week 2 results
│   │   ├── guard_consistency_results.json  # Week 3 C(O) results
│   │   ├── guard_validation_results.json   # Week 4 V(O) results
│   │   ├── guard_stability_results.json    # Week 5 S(O) results
│   │   ├── guard_agent_rts_results.json    # Week 5 full RTS results
│   │   ├── adversarial_evaluation_results.json  # Week 6 results
│   │   ├── statistical_validation_results.json  # Week 7 results
│   │   └── figures/                        # Publication-quality figures
│   │       ├── fig1_rts_distribution.png
│   │       ├── fig2_accuracy_comparison.png
│   │       ├── fig3_rts_components.png
│   │       └── fig4_threshold_tradeoff.png
│   ├── mitre_attack/
│   │   ├── enterprise-attack.json          # MITRE ATT&CK STIX data
│   │   ├── parsed_techniques.json          # Parsed technique database
│   │   ├── rag_documents.json              # RAG-ready documents
│   │   └── technique_lookup.json           # 691 technique ID lookup
│   └── chromadb/                           # ChromaDB vector store
├── src/
│   ├── agents/
│   │   ├── baseline_llm.py                 # Week 1: LLM-only baseline
│   │   ├── mitre_attack_loader.py          # Week 2: STIX data parser
│   │   ├── rag_knowledge_base.py           # Week 2: ChromaDB + multi-query search
│   │   ├── rag_pipeline.py                 # Week 2: LLM+RAG experiment
│   │   ├── guard_consistency.py            # Week 3: C(O) multi-pass inference
│   │   ├── guard_validation.py             # Week 4: V(O) ATT&CK cross-validation
│   │   ├── guard_stability.py              # Week 5: S(O) perturbation engine
│   │   ├── guard_agent.py                  # Week 5: Full RTS + threshold calibration
│   │   ├── adversarial_evaluation.py       # Week 6: 100-scenario adversarial testing
│   │   └── statistical_validation.py       # Week 7: Hypothesis testing + figures
│   └── utils/
│       ├── prompt_templates.py             # Threat analysis prompts (5 variations)
│       ├── output_parser.py                # Structured JSON extraction
│       └── evaluation.py                   # Metrics and comparison tools
├── tests/
│   ├── test_baseline.py                    # 7 tests (Week 1)
│   ├── test_rag.py                         # 9 tests (Week 2)
│   ├── test_consistency.py                 # 14 tests (Week 3)
│   ├── test_validation.py                  # 17 tests (Week 4)
│   ├── test_stability_rts.py              # 23 tests (Week 5)
│   └── test_adversarial_stats.py          # 12 tests (Weeks 6-7)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Results Summary

### Progressive Baseline Comparison (30 Scenarios)

| Metric | LLM-Only | LLM+RAG | LLM+RAG+Guard |
|--------|----------|---------|----------------|
| Classification Accuracy | 56.7% | 73.3% | 60.0% (majority vote) |
| F1 Score | 90.2% | 90.2% | 88.5% |
| Recall | 100% | 100% | 100% |
| Parse Success Rate | 90% | 100% | ~95% |
| Invalid Technique IDs | N/A | 0 | 0 |
| Avg Confidence | 0.763 | 0.840 | 0.840 |

### Adversarial Testing (100 Scenarios)

| Category | LLM-Only | LLM+RAG | Guard |
|----------|----------|---------|-------|
| Legitimate Attacks (25) | 60% | 76% | 76% |
| Legitimate Benign (25) | 60% | 28% | 40% |
| Conflicting Narratives (10) | 60% | 80% | 70% |
| Subtle Manipulation (10) | 70% | 70% | 60% |
| Prompt Injection (10) | 40% | 20% | 20% |
| Fabricated CVEs (10) | 0% | 0% | 0% |
| Data Poisoning (10) | 20% | 10% | 20% |

### Statistical Validation

| Test | Result | Interpretation |
|------|--------|----------------|
| Cohen's d | 0.9453 | Large effect size |
| Paired t-test | p = 0.000987 | Highly significant (p < 0.001) |
| RTS gap (correct vs incorrect) | +0.119 | Higher RTS = correct output |
| ε at τ=0.85 | 0.0000 | Zero hallucinations above threshold |
| Hypothesis H1a | SUPPORTED | Null H0₁ rejected |

---

## Quick Start

### Prerequisites

- Python 3.10+
- Ollama with Llama 3 8B
- ~8GB RAM for LLM inference

### Setup

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/Guard-Agent-for-Adversarial-Robustness-of-LLM-Reasoning.git
cd Guard-Agent-for-Adversarial-Robustness-of-LLM-Reasoning

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate     # Linux/Mac

# Install dependencies
python -m pip install -r requirements.txt

# Install Ollama and pull model
# Download from: https://ollama.com/download
ollama pull llama3:8b
```

### Running Experiments

```bash
# Week 1: LLM-Only Baseline
python -m src.agents.baseline_llm

# Week 2: RAG Pipeline
python -m src.agents.mitre_attack_loader
python -m src.agents.rag_knowledge_base --build
python -m src.agents.rag_pipeline

# Week 3: Consistency Score
python -m src.agents.guard_consistency

# Week 4: Validation Score
python -m src.agents.guard_validation --input data/results/guard_consistency_results.json

# Week 5: Stability + Full RTS
python -m src.agents.guard_stability --from-consistency data/results/guard_consistency_results.json
python -m src.agents.guard_agent --compute

# Week 6: Adversarial Testing
python -m src.agents.adversarial_evaluation --config all

# Week 7: Statistical Validation
python -m src.agents.statistical_validation
python -m src.agents.statistical_validation --figures
```

### Running Tests

```bash
python tests/test_baseline.py           # 7 tests
python tests/test_rag.py                # 9 tests
python tests/test_consistency.py        # 14 tests
python tests/test_validation.py         # 17 tests
python tests/test_stability_rts.py      # 23 tests
python tests/test_adversarial_stats.py  # 12 tests
# Total: 82 tests
```

---

## Tools and Technologies

| Component | Technology |
|-----------|------------|
| LLM | Llama 3 8B via Ollama |
| Vector Database | ChromaDB |
| Embeddings | all-MiniLM-L6-v2 (sentence-transformers) |
| Knowledge Base | MITRE ATT&CK Enterprise (STIX 2.0, 691 techniques) |
| Statistical Analysis | SciPy (t-test, Wilcoxon), custom Cohen's d |
| Visualization | Matplotlib |
| Language | Python 3.10+ |
| Version Control | Git + GitHub |

---

## Change Request History

| CR | Week | Title | Status |
|----|------|-------|--------|
| CR-01 | 1 | Implement AgentShield Guard Agent | ✅ Closed |
| CR-02 | 2 | RAG Pipeline with MITRE ATT&CK | ✅ Closed |
| CR-03 | 3 | Consistency Score C(O) | ✅ Closed |
| CR-04 | 4 | Validation Score V(O) | ✅ Closed |
| CR-05 | 5 | Stability S(O) + Full RTS | ✅ Closed |
| CR-06 | 6 | Adversarial Robustness Testing | ✅ Closed |
| CR-07 | 7 | Statistical Validation | ✅ Closed |

---

## Publication Figures

Four publication-ready figures are available in `data/results/figures/`:

1. **fig1_rts_distribution.png** — RTS score distribution for correct vs incorrect classifications
2. **fig2_accuracy_comparison.png** — Classification accuracy across LLM-only, LLM+RAG, Guard RTS
3. **fig3_rts_components.png** — RTS component breakdown: C(O), V(O), S(O)
4. **fig4_threshold_tradeoff.png** — Threshold τ vs automation rate vs hallucination leakage ε

---

## Next: Aspect 02 — Federated Multi-Agent Learning

Aspect 02 will implement Weeks 8-12:

| Week | Component |
|------|-----------|
| 8 | CNN-LSTM Detection Agent + CICIDS2017 dataset |
| 9 | Federated Learning Pipeline (FedAvg + Byzantine-Robust) |
| 10 | Adversarial Poisoning Attacks + Blockchain Verification |
| 11 | Post-Quantum Cryptography (CRYSTALS-Dilithium) Benchmarking |
| 12 | Full Integration + 7 Experiments + Thesis Documentation |

---

## License

This project is part of an MS thesis at National University of Computer and Emerging Sciences. All rights reserved.

## Contact

Syed Salman Ali — K24-8088
