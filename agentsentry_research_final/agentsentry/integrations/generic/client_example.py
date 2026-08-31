# integrations/generic/client_example.py
#
# The SECOND integration in this project, deliberately using no agent
# framework at all -- just plain function calls and one HTTP request.
# This exists specifically to demonstrate that AgentSentry's contract
# does not require LangGraph: any code that can propose a tool call
# and make an HTTP request can be protected the same way.
#
# This is the pattern a real integration would follow: before your
# tool function actually runs, ask AgentSentry first.
#
# Run: python integrations/generic/client_example.py
# Requires: api/server.py + OPA already running.

import requests

AGENTSENTRY_URL = "http://127.0.0.1:8000/v1/governance/evaluate"


def agent_sentry_guard(tool_name: str, arguments: dict, user_role: str, session_id: str) -> dict:
    """Call this before executing ANY tool, regardless of what
    framework (or no framework) is proposing the call."""
    payload = {
        "tool_name": tool_name, "arguments": arguments,
        "user_role": user_role, "session_id": session_id,
    }
    try:
        resp = requests.post(AGENTSENTRY_URL, json=payload, timeout=2.0)
        return resp.json()
    except Exception as e:
        return {"verdict": "BLOCK", "reason": f"AgentSentry unreachable ({e}) — fail-closed."}


# --- Example tool functions a plain (non-LangGraph) agent might have ---

def read_user_profile(user_id: int) -> str:
    return f"Success: Retrieved profile for user {user_id}."


def execute_sql_query(query: str) -> str:
    return f"Success: Query executed -> {query}"


def guarded_tool_call(tool_fn, tool_name, arguments, user_role, session_id):
    """Wraps any plain Python function with an AgentSentry pre-execution check."""
    result = agent_sentry_guard(tool_name, arguments, user_role, session_id)
    print(f"[AgentSentry] Tool: '{tool_name}' | Verdict: {result['verdict']} | Reason: {result['reason']}")
    if result["verdict"] == "ALLOW":
        return tool_fn(**arguments)
    elif result["verdict"] == "FLAG":
        return "EXECUTION_HELD: Action flagged for human review, not executed."
    else:
        return "EXECUTION_BLOCKED: Governance policy denied this action."


if __name__ == "__main__":
    print("--- Testing a plain, framework-free agent integration ---\n")
    session = "generic_client_demo"

    output = guarded_tool_call(
        read_user_profile, "read_user_profile", {"user_id": 1082}, "guest", session)
    print("Agent Output:", output, "\n")

    output = guarded_tool_call(
        execute_sql_query, "execute_sql_query", {"query": "DROP TABLE users"}, "guest", session)
    print("Agent Output:", output)
