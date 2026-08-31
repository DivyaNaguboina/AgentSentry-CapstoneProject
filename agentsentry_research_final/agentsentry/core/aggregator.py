# core/aggregator.py
#
# The "Risk / Security Decision" stage. This is the actual thesis of
# AgentSentry: combining an independent rule-based verdict and an
# independent behavior-based verdict into one explainable decision.
#
# Deliberately a pure function -- no network calls, no session state,
# no side effects. Given the same three inputs it always returns the
# same verdict, which means it can be unit-tested directly (see
# evaluation/ for exactly that) without OPA or the trained model
# running at all.

def decide(opa_allowed: bool, opa_error: bool, is_outlier: bool) -> tuple[str, str]:
    """Returns (verdict, reason). verdict is one of ALLOW / FLAG / BLOCK."""
    if opa_error:
        return "BLOCK", "Governance System Error (Fail-Closed)."
    if not opa_allowed:
        return "BLOCK", "OPA Rego Policy Violation: Action Denied."
    if is_outlier:
        return "FLAG", "OPA passed, but behavior flagged as anomalous — pending review."
    return "ALLOW", "OPA Rego Policy Passed; behavior within normal range."
