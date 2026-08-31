# evaluation/run_paper_evaluation.py
#
# MODULE 4: Mandatory 4-Way Scientific Ablation Suite
#
# Runs the reserved public benchmark test set through 4 experimental
# conditions and produces publication-ready metrics tables.
#
# Run: python evaluation/run_paper_evaluation.py
# (Does NOT require OPA or api/server.py running — evaluates directly
#  against the detection/policy engines in-process for reproducibility.)

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Literal

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

PROJECT_ROOT  = Path(__file__).resolve().parent.parent
DATA_DIR      = PROJECT_ROOT / "data"
DETECTION_DIR = PROJECT_ROOT / "detection"
RESULTS_DIR   = PROJECT_ROOT / "evaluation"

BENCHMARK_TEST_PATH = DATA_DIR / "public_benchmark_test.json"
MODEL_PATH          = DETECTION_DIR / "isolation_forest.joblib"
CONFIG_PATH         = DETECTION_DIR / "feature_config.json"

sys.path.insert(0, str(PROJECT_ROOT))
from core.aggregator import decide

# ── Feature Extraction (mirrors detection/retrain_on_agent_traces.py) ─────

def _try_import_sbert():
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except ImportError:
        return None


def action_history_to_text(trace: dict) -> str:
    history = trace.get("action_history", []) + [trace.get("tool_name", "unknown")]
    role    = trace.get("user_role", "user")
    arg_keys = list(trace.get("arguments", {}).keys())
    return f"role:{role} sequence:{' '.join(history)} args:{' '.join(str(k) for k in arg_keys)}"


def extract_features_for_trace(trace: dict, sbert_model) -> np.ndarray:
    if sbert_model:
        return sbert_model.encode([action_history_to_text(trace)])[0]
    # Hand-engineered fallback
    history = trace.get("action_history", []) + [trace.get("tool_name", "unknown")]
    n = len(history)
    unique = len(set(history))
    max_repeat = max(history.count(h) for h in set(history)) if history else 1
    avg_gap = trace.get("turn_index", 0) / max(n - 1, 1)
    return np.array([n, unique, avg_gap, avg_gap * 1.5, max_repeat, avg_gap * n], dtype=np.float32)

# ── OPA Policy Simulation (in-process, no network call) ──────────────────
# Mirrors the actual rules.rego logic for offline evaluation.

_ALLOWED_ROLES = {
    "execute_sql_query":       ["admin"],
    "send_email":              ["agent", "analyst", "admin"],
    "send_enterprise_email":   ["agent", "analyst", "admin"],
    "query_database":          ["admin"],
    "issue_refund":            ["agent", "analyst", "admin"],
    "check_weather":           ["guest", "user", "agent", "analyst", "admin"],
    "read_user_profile":       ["guest", "user", "agent", "analyst", "admin"],
    "get_order_status":        ["guest", "user", "agent", "analyst", "admin"],
    "get_balance":             ["user", "analyst", "admin"],
    "send_money":              ["user", "analyst", "admin"],
    "get_iban":                ["user", "analyst", "admin"],
    "get_transactions":        ["user", "analyst", "admin"],
    "execute_sql":             ["admin"],
    "read_file":               ["user", "analyst", "admin"],
    "transfer_funds":          ["admin"],
    "transfer_corporate_funds":["admin"],
    "search_files":            ["user", "analyst", "admin"],
    "get_emails":              ["user", "analyst", "admin"],
    "read_document_knowledge_base": ["user", "analyst", "admin"],
    "fetch_external_web_page": ["analyst", "admin"],
    "execute_sql_query":       ["admin"],
}

_DESTRUCTIVE_KEYWORDS = [
    "drop ", "drop\t", "delete from", "truncate", "grant all",
    "insert into admin", "attacker", "evil.com", "malware"
]


def opa_evaluate(trace: dict) -> bool:
    """Returns True (allowed) or False (denied). Mirrors rules.rego logic."""
    tool    = trace.get("tool_name", "").lower()
    role    = trace.get("user_role", "guest").lower()
    args_str = json.dumps(trace.get("arguments", {})).lower()

    # Destructive keyword check (IPI detection via OPA)
    for kw in _DESTRUCTIVE_KEYWORDS:
        if kw in args_str:
            return False

    # Role-based access control
    allowed_roles = _ALLOWED_ROLES.get(tool, [])
    if not allowed_roles:
        return False  # Unknown tool → deny by default
    return role in allowed_roles

# ── SBERT Cosine Baseline (Condition 2) ──────────────────────────────────

class SBERTCosineBaseline:
    """
    Computes cosine similarity against a benign centroid embedding.
    Flags as anomalous when similarity drops below threshold.
    Used for Condition 2 (SBERT Cosine Baseline alone, no OPA, no IF).
    """
    def __init__(self, threshold: float = 0.6):
        self.centroid: np.ndarray | None = None
        self.threshold = threshold

    def fit(self, features: np.ndarray):
        self.centroid = features.mean(axis=0)

    def is_outlier(self, feature_vec: np.ndarray) -> bool:
        if self.centroid is None:
            return True
        norm_a = np.linalg.norm(self.centroid)
        norm_b = np.linalg.norm(feature_vec)
        if norm_a == 0 or norm_b == 0:
            return True
        sim = float(np.dot(self.centroid, feature_vec) / (norm_a * norm_b))
        return sim < self.threshold

# ── Metrics ───────────────────────────────────────────────────────────────

def compute_metrics(y_true: list[int], y_pred: list[int]) -> dict:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return dict(TP=tp, FP=fp, TN=tn, FN=fn,
                Precision=precision, Recall=recall, F1=f1, FPR=fpr)

# ── Evaluation Runner ─────────────────────────────────────────────────────

def run_ablation(test_traces: list[dict]) -> dict[str, dict]:
    config = {}
    if CONFIG_PATH.exists():
        config = json.loads(CONFIG_PATH.read_text())

    sbert = _try_import_sbert()
    if sbert:
        print("[Ablation] SBERT loaded — using 384-dim embeddings")
    else:
        print("[Ablation] SBERT not available — using 6 hand-engineered features")

    # Load trained IsolationForest
    if not MODEL_PATH.exists():
        print(f"[ERROR] Model not found at {MODEL_PATH}. Run retrain_on_agent_traces.py first.")
        sys.exit(1)
    iso_forest: IsolationForest = joblib.load(MODEL_PATH)

    # Build benign centroid for SBERT cosine baseline
    benign_train_path = DATA_DIR / "public_benign_train.json"
    cosine_baseline = SBERTCosineBaseline(threshold=0.6)
    if benign_train_path.exists():
        train_traces = json.loads(benign_train_path.read_text())
        train_feats = np.array([extract_features_for_trace(t, sbert) for t in train_traces])
        cosine_baseline.fit(train_feats)

    y_true = [t["ground_truth_label"] for t in test_traces]

    conditions: dict[str, dict] = {}

    for condition_name, desc in [
        ("C1_OPA_Only",          "OPA Rules Only (no anomaly engine)"),
        ("C2_SBERT_Cosine",      "SBERT Cosine Baseline Only (no OPA, no IF)"),
        ("C3_IsolationForest",   "Isolation Forest Only (no OPA)"),
        ("C4_AgentSentry_Full",  "AgentSentry Full Pipeline (OPA + SBERT + IF)"),
    ]:
        print(f"\n[Ablation] Running {condition_name}: {desc}")
        y_pred = []
        latencies_ms = []

        for trace in test_traces:
            t0 = time.perf_counter()

            feat = extract_features_for_trace(trace, sbert)
            feat_2d = feat.reshape(1, -1)

            if condition_name == "C1_OPA_Only":
                opa_ok = opa_evaluate(trace)
                detected = 0 if opa_ok else 1

            elif condition_name == "C2_SBERT_Cosine":
                detected = 1 if cosine_baseline.is_outlier(feat) else 0

            elif condition_name == "C3_IsolationForest":
                pred = iso_forest.predict(feat_2d)[0]
                detected = 1 if pred == -1 else 0

            elif condition_name == "C4_AgentSentry_Full":
                opa_ok = opa_evaluate(trace)
                if_pred = iso_forest.predict(feat_2d)[0]
                is_outlier = if_pred == -1
                verdict, _ = decide(
                    opa_allowed=opa_ok,
                    opa_error=False,
                    is_outlier=is_outlier,
                )
                detected = 0 if verdict == "ALLOW" else 1

            latencies_ms.append((time.perf_counter() - t0) * 1000)
            y_pred.append(detected)

        metrics = compute_metrics(y_true, y_pred)
        lat = sorted(latencies_ms)
        n = len(lat)
        metrics["p50_ms"]  = lat[int(n * 0.50)]
        metrics["p95_ms"]  = lat[int(n * 0.95)]
        metrics["p99_ms"]  = lat[min(int(n * 0.99), n - 1)]
        metrics["description"] = desc
        conditions[condition_name] = metrics

        print(
            f"  TP={metrics['TP']} FP={metrics['FP']} TN={metrics['TN']} FN={metrics['FN']} "
            f"F1={metrics['F1']:.3f} FPR={metrics['FPR']:.3f} p95={metrics['p95_ms']:.2f}ms"
        )

    return conditions

# ── Publication Table Formatters ──────────────────────────────────────────

def format_ascii_table(results: dict[str, dict]) -> str:
    sep = "+" + "+".join(["-" * 28, "-" * 6, "-" * 6, "-" * 8, "-" * 8, "-" * 8, "-" * 8, "-" * 10]) + "+"
    header = "| {:<26} | {:>4} | {:>4} | {:>6} | {:>6} | {:>6} | {:>6} | {:>8} |".format(
        "Condition", "TP", "FP", "Prec", "Rec", "F1", "FPR", "p95(ms)"
    )
    lines = [sep, header, sep]
    for name, m in results.items():
        lines.append(
            "| {:<26} | {:>4} | {:>4} | {:>6.3f} | {:>6.3f} | {:>6.3f} | {:>6.3f} | {:>8.2f} |".format(
                name[:26], m["TP"], m["FP"],
                m["Precision"], m["Recall"], m["F1"], m["FPR"], m["p95_ms"]
            )
        )
    lines.append(sep)
    return "\n".join(lines)


def format_markdown_table(results: dict[str, dict]) -> str:
    header = "| Condition | TP | FP | Precision | Recall | F1 | FPR | p95 (ms) |"
    sep    = "|---|---|---|---|---|---|---|---|"
    rows   = [header, sep]
    for name, m in results.items():
        desc = m.get("description", name)
        rows.append(
            f"| {desc} | {m['TP']} | {m['FP']} | "
            f"{m['Precision']:.3f} | {m['Recall']:.3f} | "
            f"{m['F1']:.3f} | {m['FPR']:.3f} | {m['p95_ms']:.2f} |"
        )
    return "\n".join(rows)


def format_ieee_latex(results: dict[str, dict]) -> str:
    """LaTeX table ready to paste into an IEEE paper."""
    lines = [
        r"\begin{table}[ht]",
        r"\centering",
        r"\caption{AgentSentry 4-Way Ablation Study}",
        r"\label{tab:ablation}",
        r"\begin{tabular}{lccccccc}",
        r"\toprule",
        r"Condition & TP & FP & Precision & Recall & F1 & FPR & p95 (ms) \\",
        r"\midrule",
    ]
    for name, m in results.items():
        desc = m.get("description", name).replace("&", r"\&")
        lines.append(
            f"{desc} & {m['TP']} & {m['FP']} & "
            f"{m['Precision']:.3f} & {m['Recall']:.3f} & "
            f"{m['F1']:.3f} & {m['FPR']:.3f} & {m['p95_ms']:.2f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines)

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    if not BENCHMARK_TEST_PATH.exists():
        print(f"[ERROR] Test data not found at {BENCHMARK_TEST_PATH}")
        print("Run: python benchmarks/benchmark_loader.py first")
        sys.exit(1)

    test_traces = json.loads(BENCHMARK_TEST_PATH.read_text())
    print(f"[Ablation] Loaded {len(test_traces)} test traces "
          f"({sum(1 for t in test_traces if t['ground_truth_label']==1)} malicious, "
          f"{sum(1 for t in test_traces if t['ground_truth_label']==0)} benign)")

    results = run_ablation(test_traces)

    ascii_table    = format_ascii_table(results)
    markdown_table = format_markdown_table(results)
    latex_table    = format_ieee_latex(results)

    print("\n\n" + "=" * 70)
    print("ABLATION RESULTS — ASCII TABLE")
    print("=" * 70)
    print(ascii_table)

    print("\n" + "=" * 70)
    print("ABLATION RESULTS — MARKDOWN (paste into paper draft)")
    print("=" * 70)
    print(markdown_table)

    print("\n" + "=" * 70)
    print("ABLATION RESULTS — IEEE LaTeX (paste into paper)")
    print("=" * 70)
    print(latex_table)

    # Save all outputs
    out_path = RESULTS_DIR / "ablation_results.json"
    out_path.write_text(json.dumps(results, indent=2))

    md_path = RESULTS_DIR / "ablation_results.md"
    md_path.write_text(f"# AgentSentry Ablation Results\n\n{markdown_table}\n\n{latex_table}")

    print(f"\n[Done] Results saved to {out_path} and {md_path}")


if __name__ == "__main__":
    main()
