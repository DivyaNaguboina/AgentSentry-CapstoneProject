# detection/retrain_on_agent_traces.py
#
# MODULE 3: Training & Calibration on Genuine Agent Traces
#
# Two-mode featurization:
#   PRIMARY:  Sentence-BERT (all-MiniLM-L6-v2) → 384-dim embeddings
#             (matches the original proposal and supports the SBERT
#             cosine-baseline ablation condition in Module 4)
#   FALLBACK: 6 hand-engineered behavioral features
#             (used when sentence-transformers is not installed —
#             the existing production model uses this path)
#
# The output is always isolation_forest.joblib + feature_config.json
# in the detection/ directory, regardless of which path ran, so
# api/server.py picks it up automatically with zero code changes.
#
# Run:
#   python detection/retrain_on_agent_traces.py [path/to/public_benign_train.json]

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import make_scorer
import joblib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
DETECTION_DIR = Path(__file__).resolve().parent

BENIGN_TRAIN_PATH = DATA_DIR / "public_benign_train.json"
MODEL_OUTPUT      = DETECTION_DIR / "isolation_forest.joblib"
CONFIG_OUTPUT     = DETECTION_DIR / "feature_config.json"

# ── Feature Extraction ────────────────────────────────────────────────────

def _try_import_sbert():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except ImportError:
        return None


def action_history_to_text(trace: dict) -> str:
    """Converts a trace into a text string for SBERT encoding.
    Encodes the full action sequence including the current tool call,
    user role, and argument keys — preserving behavioral semantics."""
    history = trace.get("action_history", [])
    tool_name = trace.get("tool_name", "unknown")
    role = trace.get("user_role", "user")
    arg_keys = list(trace.get("arguments", {}).keys())
    full_seq = history + [tool_name]
    return (
        f"role:{role} "
        f"sequence:{' '.join(full_seq)} "
        f"args:{' '.join(str(k) for k in arg_keys)}"
    )


def extract_sbert_features(traces: list[dict], model) -> np.ndarray:
    """384-dimensional SBERT embeddings of action sequences."""
    texts = [action_history_to_text(t) for t in traces]
    embeddings = model.encode(texts, batch_size=32, show_progress_bar=True)
    return embeddings.astype(np.float32)


def extract_handengineered_features(traces: list[dict]) -> np.ndarray:
    """6-dimensional behavioral features (fallback when SBERT unavailable)."""
    rows = []
    for t in traces:
        history = t.get("action_history", []) + [t.get("tool_name", "unknown")]
        n = len(history)
        unique = len(set(history))
        max_repeat = max(history.count(h) for h in set(history)) if history else 1
        # Use turn_index as a proxy for timing when real timestamps aren't available
        avg_gap = t.get("turn_index", 0) / max(n - 1, 1)
        rows.append([n, unique, avg_gap, avg_gap * 1.5, max_repeat, avg_gap * n])
    return np.array(rows, dtype=np.float32)


FeatureMode = Literal["sbert", "handengineered"]


def extract_features(traces: list[dict]) -> tuple[np.ndarray, FeatureMode]:
    """Tries SBERT first, falls back to hand-engineered features."""
    sbert = _try_import_sbert()
    if sbert:
        print("[Featurizer] Using SBERT all-MiniLM-L6-v2 (384-dim)")
        return extract_sbert_features(traces, sbert), "sbert"
    else:
        print("[Featurizer] SBERT not available — using 6 hand-engineered features")
        print("             Install sentence-transformers to use SBERT embeddings.")
        return extract_handengineered_features(traces), "handengineered"

# ── Sensitivity Sweep (tune contamination to keep FPR ≤ 0.05) ───────────

def tune_contamination(
    X: np.ndarray,
    contamination_values: list[float] = [0.005, 0.01, 0.02, 0.03, 0.05],
    n_estimators: int = 150,
) -> float:
    """
    Fits IsolationForest at several contamination values on the benign
    training set and returns the highest value where the self-predicted
    FPR stays ≤ 0.05 (5% of benign training samples flagged as outliers).
    """
    best_c = 0.01
    print("\n[Calibration] Contamination sensitivity sweep:")
    for c in contamination_values:
        model = IsolationForest(n_estimators=n_estimators, contamination=c, random_state=42)
        model.fit(X)
        preds = model.predict(X)  # on training data (all benign)
        self_fpr = (preds == -1).mean()
        flag = "✓" if self_fpr <= 0.05 else "✗"
        print(f"  contamination={c:.3f} → self-FPR={self_fpr:.3f} {flag}")
        if self_fpr <= 0.05:
            best_c = c
    print(f"[Calibration] Selected contamination: {best_c}")
    return best_c

# ── Training ──────────────────────────────────────────────────────────────

def train(
    benign_traces: list[dict],
    n_estimators: int = 150,
) -> tuple[IsolationForest, FeatureMode, np.ndarray]:
    print(f"\n[Training] Featurizing {len(benign_traces)} benign traces...")
    t0 = time.time()
    X, mode = extract_features(benign_traces)
    print(f"[Training] Feature matrix: {X.shape} in {time.time()-t0:.1f}s")

    best_c = tune_contamination(X, n_estimators=n_estimators)

    print(f"\n[Training] Fitting IsolationForest (n_estimators={n_estimators}, contamination={best_c})...")
    model = IsolationForest(n_estimators=n_estimators, contamination=best_c, random_state=42)
    model.fit(X)

    joblib.dump(model, MODEL_OUTPUT)
    config = {
        "feature_mode": mode,
        "n_features": X.shape[1],
        "n_training_samples": len(benign_traces),
        "n_estimators": n_estimators,
        "contamination": best_c,
        "benchmark_source": list(set(t.get("benchmark_source", "unknown") for t in benign_traces)),
    }
    CONFIG_OUTPUT.write_text(json.dumps(config, indent=2))

    print(f"[Training] Model saved → {MODEL_OUTPUT}")
    print(f"[Training] Config saved → {CONFIG_OUTPUT}")
    return model, mode, X


# ── Capture Real Traces via Live Agent ────────────────────────────────────

def capture_agent_traces(
    benign_train_traces: list[dict],
    max_tasks: int = 20,
) -> list[dict]:
    """
    Feeds benign benchmark tasks through the live LangGraph agent and
    captures the resulting tool call sequences. These are REAL traces
    generated by an actual AI agent's reasoning, not scripted sequences.

    Falls back gracefully if AgentSentry or the LLM is unavailable,
    returning the input traces directly so the pipeline can still run.
    """
    try:
        import sys
        sys.path.insert(0, str(PROJECT_ROOT))
        from integrations.langgraph.langgraph_agent import run_agent, ENTERPRISE_TOOLS

        captured = []
        tasks = [
            "Check the company account balance.",
            "Send a status update to the team.",
            "Look up the Q3 financial report.",
            "Execute a query to get order counts.",
            "Transfer $500 to account CORP-002.",
        ]

        for i, task in enumerate(tasks[:max_tasks]):
            print(f"  [Capture] Running task {i+1}/{len(tasks)}: {task[:50]}")
            try:
                result = run_agent(
                    task=task,
                    session_id=f"capture_{i:03d}",
                    user_role="analyst",
                )
                history = result.get("action_history", [])
                for j, tool_name in enumerate(history):
                    captured.append({
                        "benchmark_source": "LiveAgent",
                        "session_id": f"capture_{i:03d}",
                        "turn_index": j,
                        "user_role": "analyst",
                        "tool_name": tool_name,
                        "arguments": {},
                        "action_history": history[:j],
                        "ground_truth_label": 0,
                        "threat_type": "BENIGN",
                    })
            except Exception as e:
                print(f"  [Capture] Task {i+1} failed: {e}")

        if captured:
            print(f"[Capture] Captured {len(captured)} real tool-call traces.")
            return captured

    except Exception as e:
        print(f"[Capture] Live agent unavailable ({e}). Using benchmark traces directly.")

    return benign_train_traces


# ── Main ──────────────────────────────────────────────────────────────────

def run(train_json: str | None = None, use_live_agent: bool = False):
    train_path = Path(train_json) if train_json else BENIGN_TRAIN_PATH

    if not train_path.exists():
        print(f"[ERROR] Training data not found at {train_path}")
        print("Run: python benchmarks/benchmark_loader.py first")
        sys.exit(1)

    traces = json.loads(train_path.read_text())
    print(f"[Retrain] Loaded {len(traces)} benign traces from {train_path}")

    if use_live_agent:
        print("[Retrain] Capturing real agent traces (requires api/server.py + OPA running)...")
        traces = capture_agent_traces(traces)

    model, mode, X = train(traces)

    print(f"\n=== Retraining Complete ===")
    print(f"  Feature mode     : {mode}")
    print(f"  Feature dimensions: {X.shape[1]}")
    print(f"  Training samples  : {X.shape[0]}")
    print(f"  Model artifact    : {MODEL_OUTPUT}")
    print(f"  Config            : {CONFIG_OUTPUT}")
    return model, mode


if __name__ == "__main__":
    train_json = sys.argv[1] if len(sys.argv) > 1 else None
    use_live = "--live" in sys.argv
    run(train_json, use_live_agent=use_live)
