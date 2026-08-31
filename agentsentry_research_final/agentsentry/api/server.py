# api/server.py
#
# This is the ONLY agent-facing entrypoint -- the "AgentSentry
# Middleware" box in the architecture diagram. Deliberately thin: it
# does not decide anything itself. It just receives the raw request,
# passes it through core/session_store -> core/anomaly_engine +
# core/policy_client -> core/aggregator, in that order, logs the
# result, and returns it.
#
# Because ALL the real logic lives in core/ and is transport-agnostic,
# this file could be swapped for a gRPC server, a message-queue
# consumer, or anything else without touching the detection or policy
# logic at all -- which is exactly what makes this "generic
# middleware" rather than "a FastAPI app that happens to do security."
#
# Run: python api/server.py  (from the project root)
# Requires: OPA running with policy/rules.rego loaded first.

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn

from core.config import API_HOST, API_PORT
from core.session_store import SessionStore
from core.anomaly_engine import AnomalyEngine
from core.policy_client import evaluate_policy
from core.aggregator import decide
from telemetry.logger import log_verdict

app = FastAPI(title="AgentSentry Middleware")

# Instantiated once at process startup -- session history and the
# loaded model persist for the life of the server process.
session_store = SessionStore()
anomaly_engine = AnomalyEngine()


class ToolCallRequest(BaseModel):
    """The one contract every agent integration speaks, regardless of
    framework. Nothing in this schema is LangGraph-specific -- it's
    just: what tool, with what arguments, as whom, in which session."""
    tool_name: str
    arguments: dict
    user_role: str = "guest"
    session_id: str = "default"


@app.post("/v1/governance/evaluate")
async def evaluate_action(request: ToolCallRequest):
    start = time.perf_counter()

    # Stage 1: Normalize / Analyze -- turn raw event into live features
    features = session_store.record_and_extract_features(request.session_id, request.tool_name)

    # Stage 2: Detection + Policy Evaluation (independent engines)
    opa_allowed, opa_error = evaluate_policy(request.tool_name, request.arguments, request.user_role)
    anomaly = anomaly_engine.score(features)

    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    # Stage 3: Risk / Security Decision
    verdict, reason = decide(opa_allowed, opa_error, anomaly["is_outlier"])

    result = {
        "verdict": verdict,
        "reason": reason,
        "opa_allowed": opa_allowed,
        "anomaly_score": anomaly["anomaly_score"],
        "is_outlier": anomaly["is_outlier"],
        "session_features": features,
        "latency_ms": latency_ms,
    }

    # Stage 4: Telemetry (fire-and-forget, never blocks the verdict)
    log_verdict({
        "session_id": request.session_id,
        "tool_name": request.tool_name,
        "user_role": request.user_role,
        **result,
    })

    return result


if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT)
