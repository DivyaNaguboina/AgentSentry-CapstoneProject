package agentsentry.authz

default allow = false

# --- Original rules (kept as-is, updated to Rego v1 syntax) ---
#
# NOTE: current OPA releases (v0.59+) default to "Rego v1", which
# requires the `if` keyword before every rule body. Older OPA binaries
# (like whatever opa.exe you already had) may have accepted the
# no-`if` syntax. If you're using an older opa.exe and this causes a
# parse error in the OTHER direction, either keep your old binary or
# add `import rego.v1` — but the syntax below works with any current
# OPA release, which is the safer default for a fresh download.

# Allow safe read-only actions for everyone
allow if {
    input.tool_name == "read_user_profile"
}

# Allow high-risk tools ONLY if user_role is "admin" and query does NOT
# contain a destructive keyword
allow if {
    input.tool_name == "execute_sql_query"
    input.user_role == "admin"
    not contains_drop_keyword
}

# Helper rule to check for destructive keywords
contains_drop_keyword if {
    contains(lower(input.arguments.query), "drop")
}

# --- New rules (Week 1-4 additions) ---
#
# These extend RBAC coverage to the tool vocabulary the anomaly
# detector (detection/generate_synthetic_data.py) was trained against
# — check_weather, send_email, query_database, issue_refund,
# get_order_status. Without these, OPA would BLOCK every one of them
# by default, and the behavioral anomaly engine would never get a
# chance to run (the Decision Aggregator only reaches the anomaly
# check when OPA already allows). Extending RBAC here is what makes
# the FLAG verdict actually reachable end-to-end.

allow if {
    input.tool_name == "check_weather"
}

allow if {
    input.tool_name == "get_order_status"
}

allow if {
    input.tool_name == "send_email"
    input.user_role != "guest"
}

allow if {
    input.tool_name == "query_database"
    input.user_role == "admin"
}

# issue_refund is the tool used in your repeated-refund RE (resource
# exhaustion) scenario. OPA allows it for the "agent" role by design —
# the *rate* at which it's called is exactly what the Isolation Forest
# is responsible for catching, not OPA. This is a deliberate division
# of labor: OPA governs WHO can call WHAT; the anomaly engine governs
# HOW OFTEN/HOW UNUSUAL the pattern of calls looks.
allow if {
    input.tool_name == "issue_refund"
    input.user_role == "agent"
}
