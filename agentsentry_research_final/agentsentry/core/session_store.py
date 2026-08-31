# core/session_store.py
#
# This is the "Normalize / Analyze" stage of the architecture. It has
# no idea what OPA or Isolation Forest are -- its only job is: given a
# raw tool-call event, turn it into the 6 numeric behavioral features
# the detection engine needs, by tracking each session's history over
# time. This is deliberately separate from the API layer so it can be
# unit-tested (or swapped for Redis-backed storage later) without
# touching FastAPI or the decision logic at all.

import time
import threading
from collections import defaultdict, deque

import numpy as np

from core.config import MAX_SESSION_HISTORY


class SessionStore:
    def __init__(self, max_history: int = MAX_SESSION_HISTORY):
        self._lock = threading.Lock()
        self._sessions: dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))

    def record_and_extract_features(self, session_id: str, tool_name: str) -> dict:
        """Append this action to the session's history and compute the
        live features in the shape the detection engine expects."""
        now = time.time()
        with self._lock:
            history = self._sessions[session_id]
            history.append((tool_name, now))
            actions = list(history)

        timestamps = [t for _, t in actions]
        tool_names = [n for n, _ in actions]
        n_actions = len(actions)

        if n_actions > 1:
            gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, n_actions)]
            avg_gap = float(np.mean(gaps))
            max_gap = float(np.max(gaps))
            duration = timestamps[-1] - timestamps[0]
        else:
            avg_gap = max_gap = duration = 0.0

        max_repeat = max(tool_names.count(t) for t in set(tool_names))

        return {
            "n_actions": n_actions,
            "n_unique_tools": len(set(tool_names)),
            "avg_gap_seconds": avg_gap,
            "max_gap_seconds": max_gap,
            "max_single_tool_repeat": max_repeat,
            "session_duration_seconds": duration,
        }
