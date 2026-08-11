"""
detection/generate_synthetic_data.py

Generates synthetic "normal" agent session traces and extracts numeric
features from them. This is TRAINING data for the Isolation Forest —
it must contain ONLY normal, legitimate behavior. Never mix attack
examples in here, or the model stops being able to flag them as unusual.

Run: python generate_synthetic_data.py
Output: normal_sessions.csv (one row per session, ready for anomaly_model.py)
"""

import random
import numpy as np
import pandas as pd

random.seed(42)
np.random.seed(42)

TOOLS = ["check_weather", "send_email", "query_database", "issue_refund", "get_order_status"]

def generate_normal_session(session_id: int) -> dict:
    """
    Simulates one plausible, legitimate agent session.
    Varies length, tool choice, and timing to build a realistic 'normal' distribution
    — variety here matters more than volume. A dataset of 100 near-identical
    sessions teaches the model almost nothing useful.
    """
    n_actions = np.random.randint(1, 8)  # most real sessions are short
    tools_used = random.choices(TOOLS, k=n_actions)

    # Simulate realistic, human-paced gaps between actions (seconds)
    gaps = np.random.exponential(scale=4.0, size=n_actions)

    # A normal session rarely calls the *same* tool many times in a row
    max_single_tool_repeat = max(tools_used.count(t) for t in set(tools_used))

    return {
        "session_id": session_id,
        "n_actions": n_actions,
        "n_unique_tools": len(set(tools_used)),
        "avg_gap_seconds": float(np.mean(gaps)) if n_actions > 1 else 0.0,
        "max_gap_seconds": float(np.max(gaps)) if n_actions > 1 else 0.0,
        "max_single_tool_repeat": max_single_tool_repeat,
        "session_duration_seconds": float(np.sum(gaps)),
    }

if __name__ == "__main__":
    N_SESSIONS = 200  # more than the ~100 minimum for a bit of headroom
    sessions = [generate_normal_session(i) for i in range(N_SESSIONS)]
    df = pd.DataFrame(sessions)
    df.to_csv("normal_sessions.csv", index=False)
    print(f"Generated {len(df)} synthetic normal sessions -> normal_sessions.csv")
    print(df.describe())
