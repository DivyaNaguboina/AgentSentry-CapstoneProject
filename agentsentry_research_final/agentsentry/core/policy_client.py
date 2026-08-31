# core/policy_client.py
#
# Thin client for the deterministic policy engine (OPA). This is one
# half of "Detection + Policy Evaluation" in the architecture -- the
# rule-based half. It knows nothing about sessions, behavior, or
# scoring; it only asks OPA one question: "does this specific action,
# right now, pass the rules?"

import requests

from core.config import OPA_URL


def evaluate_policy(tool_name: str, arguments: dict, user_role: str) -> tuple[bool, bool]:
    """Returns (allowed, error). `error=True` means OPA itself could
    not be reached -- callers should treat this as fail-closed, not
    as an implicit allow."""
    payload = {
        "input": {
            "tool_name": tool_name,
            "arguments": arguments,
            "user_role": user_role,
        }
    }
    try
        response = requests.post(OPA_URL, json=payload, timeout=1.0)
        allowed = response.json().get("result", False)
        return allowed, False
    except Exception as e:
        print(f"[AgentSentry] OPA connection error: {e}")
        return False, True
