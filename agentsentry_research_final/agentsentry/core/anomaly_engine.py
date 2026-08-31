# core/anomaly_engine.py
#
# The other half of "Detection + Policy Evaluation" -- the behavioral
# half. Wraps the trained Isolation Forest (built and validated in
# detection/anomaly_model.py) for runtime scoring. This module owns
# NO training logic -- training is a separate, offline step (see
# detection/anomaly_model.py). At runtime this only ever loads an
# already-trained model and scores new sessions against it.

import sys
from pathlib import Path

import numpy as np
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detection.anomaly_model import FEATURE_COLUMNS  # noqa: E402
from core.config import MODEL_PATH  # noqa: E402


class AnomalyEngine:
    def __init__(self, model_path: Path = MODEL_PATH):
        try:
            self.model = joblib.load(model_path)
            self.loaded = True
        except Exception as e:
            print(f"[AgentSentry] WARNING: could not load anomaly model: {e}")
            self.model = None
            self.loaded = False

    def score(self, features: dict) -> dict:
        """Returns {'anomaly_score': float 0-1, 'is_outlier': bool}.
        Fails CLOSED: if the model isn't loaded, every session is
        treated as anomalous rather than silently skipping this
        engine -- a missing engine should never look like a pass."""
        if not self.loaded:
            return {"anomaly_score": 1.0, "is_outlier": True}

        x = np.array([[features[c] for c in FEATURE_COLUMNS]])
        raw_score = self.model.score_samples(x)[0]
        is_outlier = self.model.predict(x)[0] == -1
        anomaly_score = float(np.clip(-raw_score, 0, 1))
        return {"anomaly_score": round(anomaly_score, 3), "is_outlier": bool(is_outlier)}
