# telemetry/logger.py
#
# Week 3: Minimal telemetry / audit trail.
#
# Deliberately NOT Redis Streams + PostgreSQL yet. The proposal's final
# design calls for that, but building the async queue before the core
# decision logic is proven end-to-end is the wrong order of operations
# for an 8-week timeline. This gives you a real, queryable audit trail
# today; swap the storage backend later without touching interceptor.py,
# since everything goes through log_verdict() / read_recent().

import sqlite3
import json
import time
from pathlib import Path
from threading import Lock

DB_PATH = Path(__file__).parent / "audit_log.db"
_lock = Lock()  # SQLite + multiple threads under uvicorn needs this


def _get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            session_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            user_role TEXT,
            verdict TEXT NOT NULL,
            reason TEXT,
            opa_allowed INTEGER,
            anomaly_score REAL,
            is_outlier INTEGER,
            latency_ms REAL,
            session_features TEXT
        )
        """
    )
    conn.commit()
    return conn


def log_verdict(record: dict) -> None:
    """Append one verdict event to the audit log. Never raises — a
    logging failure must not take down the request path (fail-open
    for telemetry specifically, since losing a log line is much
    lower-stakes than losing an enforcement decision)."""
    try:
        with _lock:
            conn = _get_connection()
            conn.execute(
                """
                INSERT INTO verdicts
                (timestamp, session_id, tool_name, user_role, verdict, reason,
                 opa_allowed, anomaly_score, is_outlier, latency_ms, session_features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    time.time(),
                    record.get("session_id", "unknown"),
                    record.get("tool_name", "unknown"),
                    record.get("user_role"),
                    record.get("verdict"),
                    record.get("reason"),
                    int(bool(record.get("opa_allowed"))),
                    record.get("anomaly_score"),
                    int(bool(record.get("is_outlier"))),
                    record.get("latency_ms"),
                    json.dumps(record.get("session_features", {})),
                ),
            )
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[telemetry] WARNING: failed to log verdict: {e}")


def read_recent(limit: int = 50) -> list[dict]:
    """Used by the dashboard (Week 6) and by manual inspection now."""
    with _lock:
        conn = _get_connection()
        cur = conn.execute(
            "SELECT timestamp, session_id, tool_name, user_role, verdict, reason, "
            "opa_allowed, anomaly_score, is_outlier, latency_ms, session_features "
            "FROM verdicts ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        cols = [c[0] for c in cur.description]
        rows = [dict(zip(cols, row)) for row in cur.fetchall()]
        conn.close()
    return rows


if __name__ == "__main__":
    # Quick manual smoke test
    log_verdict({
        "session_id": "manual_test", "tool_name": "check_weather",
        "user_role": "guest", "verdict": "ALLOW", "reason": "test entry",
        "opa_allowed": True, "anomaly_score": 0.2, "is_outlier": False,
        "latency_ms": 5.1, "session_features": {"n_actions": 1},
    })
    print(read_recent(5))
