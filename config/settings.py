"""
============================================
Guard Agent - Configuration Settings
============================================
Central configuration for all modules.
Update these values as you progress through weeks.
"""

from pathlib import Path

# ============================================
# PATH CONFIGURATION
# ============================================
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SCENARIOS_DIR = DATA_DIR / "scenarios"
RESULTS_DIR = DATA_DIR / "results"
MITRE_DATA_DIR = DATA_DIR / "mitre_attack"  # Week 2

# ============================================
# LLM CONFIGURATION
# ============================================
LLM_MODEL = "llama3:8b"
OLLAMA_BASE_URL = "http://localhost:11434"
LLM_TEMPERATURE = 0.7          # For multi-pass inference
LLM_TEMPERATURE_BASELINE = 0.1 # For deterministic baseline
LLM_MAX_TOKENS = 2048
LLM_REQUEST_TIMEOUT = 120       # seconds

# ============================================
# GUARD AGENT CONFIGURATION (Weeks 3-5)
# ============================================
# Multi-pass inference
GUARD_NUM_PASSES = 5            # k=5 independent reasoning passes
GUARD_PROMPT_VARIATIONS = 5     # Number of prompt rephrasings

# RTS Weights: α·C(O) + β·V(O) + γ·S(O) = RTS(O)
# Start with equal weights, calibrate in Week 5
RTS_ALPHA = 1/3                 # Consistency weight
RTS_BETA = 1/3                  # Validation weight
RTS_GAMMA = 1/3                 # Stability weight

# RTS Threshold τ — outputs below this go to human analyst
RTS_THRESHOLD = 0.7

# Hallucination bound ε
RTS_EPSILON_TARGET = 0.05       # Target: P(hallucination | RTS ≥ τ) ≤ 0.05

# ============================================
# RAG CONFIGURATION (Week 2)
# ============================================
CHROMA_COLLECTION_NAME = "mitre_attack_enterprise"
CHROMA_PERSIST_DIR = str(DATA_DIR / "chromadb")
RAG_TOP_K = 5                   # Number of retrieved techniques
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# ============================================
# DETECTION AGENT (Week 8 - Aspect 02)
# ============================================
CNN_LSTM_HIDDEN_SIZE = 128
CNN_LSTM_NUM_LAYERS = 2
CNN_LSTM_DROPOUT = 0.3
BATCH_SIZE = 64
LEARNING_RATE = 0.001
EPOCHS = 50

# ============================================
# FEDERATED LEARNING (Week 9 - Aspect 02)
# ============================================
FL_NUM_ORGANIZATIONS = 5
FL_ROUNDS = 50
FL_LOCAL_EPOCHS = 5
FL_GRADIENT_CLIP_MULTIPLIER = 1.5
FL_COSINE_SIMILARITY_THRESHOLD = -0.3

# ============================================
# EVALUATION CONFIGURATION
# ============================================
NUM_EXPERIMENT_RUNS = 30        # For statistical significance
STATISTICAL_ALPHA = 0.05        # p-value threshold
RANDOM_SEED = 42

# ============================================
# THREAT SEVERITY LEVELS
# ============================================
SEVERITY_LEVELS = {
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical"
}

# ============================================
# THREAT CATEGORIES
# ============================================
THREAT_CATEGORIES = [
    "BEC Payment Fraud",
    "Invoice Fraud",
    "Data Tampering",
    "Network Intrusion",
    "Insider Threat",
    "Ransomware",
    "Phishing",
    "DDoS",
    "Brute Force",
    "Benign/Normal"
]

# ============================================
# MITRE ATT&CK TECHNIQUES (Commonly Referenced)
# Full DB loaded in Week 2 via RAG
# ============================================
COMMON_ATTACK_TECHNIQUES = {
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1534": "Internal Spearphishing",
    "T1486": "Data Encrypted for Impact",
    "T1565": "Data Manipulation",
    "T1565.001": "Stored Data Manipulation",
    "T1133": "External Remote Services",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1498": "Network Denial of Service",
    "T1071": "Application Layer Protocol",
    "T1059": "Command and Scripting Interpreter",
    "T1027": "Obfuscated Files or Information",
    "T1036": "Masquerading",
    "T1053": "Scheduled Task/Job",
    "T1047": "Windows Management Instrumentation",
}
