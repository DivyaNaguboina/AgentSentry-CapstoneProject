# core/config.py
#
# Single source of truth for paths and connection settings. Nothing
# else in this project should hardcode a port, URL, or file path --
# they should import it from here. This is what lets you change, say,
# the OPA port or the model path in exactly one place.

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --- Policy engine (OPA) ---
OPA_URL = "http://127.0.0.1:8181/v1/data/agentsentry/authz/allow"

# --- Detection engine (Isolation Forest) ---
MODEL_PATH = PROJECT_ROOT / "detection" / "isolation_forest.joblib"

# --- Session tracking ---
MAX_SESSION_HISTORY = 50  # cap per-session memory (in-memory store, single-process)

# --- API server ---
API_HOST = "127.0.0.1"
API_PORT = 8000
API_URL = f"http://{API_HOST}:{API_PORT}/v1/governance/evaluate"

# --- Telemetry ---
AUDIT_DB_PATH = PROJECT_ROOT / "telemetry" / "audit_log.db"
