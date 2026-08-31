"""
detection/anomaly_model.py

Trains an Isolation Forest on ONLY normal session features, then scores
new sessions (normal or attack) at inference time.

Run standalone to see it correctly separate normal vs. injected-attack
sessions it never saw during training:
    python anomaly_model.py
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

FEATURE_COLUMNS = [
    "n_actions",
    "n_unique_tools",
    "avg_gap_seconds",
    "max_gap_seconds",
    "max_single_tool_repeat",
    "session_duration_seconds",
]


def train_model(normal_csv: str = "normal_sessions.csv") -> IsolationForest:
    df = pd.read_csv(normal_csv)
    X_train = df[FEATURE_COLUMNS].values

    # contamination = expected proportion of outliers in training data.
    # Since this is ALL normal data, keep this low (0.01) — it mostly
    # controls the internal decision threshold, not "how many attacks to find."
    model = IsolationForest(
        n_estimators=200,
        contamination=0.01,
        random_state=42,
    )
    model.fit(X_train)
    joblib.dump(model, "isolation_forest.joblib")
    print(f"Trained on {len(X_train)} normal sessions. Model saved to isolation_forest.joblib")
    return model


def score_session(model: IsolationForest, session_features: dict) -> dict:
    """
    session_features: dict with the same keys as FEATURE_COLUMNS,
    computed live from an in-progress session (see feature extraction note below).
    """
    x = np.array([[session_features[c] for c in FEATURE_COLUMNS]])

    # score_samples: higher = more normal, lower (more negative) = more anomalous.
    # predict: -1 = anomaly, 1 = normal, based on the contamination threshold.
    raw_score = model.score_samples(x)[0]
    is_outlier = model.predict(x)[0] == -1

    # Normalize raw_score to a 0-1 "anomaly score" for easier thresholding
    # in the Decision Aggregator (1.0 = max anomalous in this simple scaling).
    anomaly_score = float(np.clip(-raw_score, 0, 1))

    return {
        "anomaly_score": round(anomaly_score, 3),
        "is_outlier": bool(is_outlier),
    }


if __name__ == "__main__":
    model = train_model()

    # A normal-looking session (should score low)
    normal_example = {
        "n_actions": 3, "n_unique_tools": 2, "avg_gap_seconds": 4.5,
        "max_gap_seconds": 6.0, "max_single_tool_repeat": 1,
        "session_duration_seconds": 13.5,
    }

    # Scenario 1 from your scope doc: 4 refund calls in ~90 seconds — same
    # tool repeated unusually often, short gaps. Model never saw this in training.
    attack_example = {
        "n_actions": 4, "n_unique_tools": 1, "avg_gap_seconds": 22.0,
        "max_gap_seconds": 25.0, "max_single_tool_repeat": 4,
        "session_duration_seconds": 88.0,
    }

    print("\nNormal session ->", score_session(model, normal_example))
    print("Attack session  ->", score_session(model, attack_example))
