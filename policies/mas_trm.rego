# MAS TRM Deployment Gate (reference only)
#
# This Rego file documents the INTENT of policies/mas_trm.edn for
# reviewers who think in OPA/Rego. It is NOT parsed or evaluated by
# bridge-gate-clj — the tool evaluates the .edn spec with its
# pure-Clojure engine (bridge.policy) so it runs with zero external
# dependencies (no `opa` binary required).
#
# Invariant: any rule added here MUST have an equivalent rule in
# policies/mas_trm.edn, which is the single source of truth.

package mas_trm

default allow := false

# Deny on any critical finding.
deny[msg] {
	some f in input.findings
	f.severity == "critical"
	msg := sprintf("critical finding: plugin %v on %v (%v)", [f.plugin_id, f.host, f.name])
}

# Deny on any high finding.
deny[msg] {
	some f in input.findings
	f.severity == "high"
	msg := sprintf("high finding: plugin %v on %v (%v)", [f.plugin_id, f.host, f.name])
}

# Deny when medium findings exceed the budget.
deny[msg] {
	mediums := [f | some f in input.findings; f.severity == "medium"]
	count(mediums) > 50
	msg := sprintf("%v medium findings exceed budget of 50", [count(mediums)])
}

# Deny on explicitly blocked plugins (e.g. unsupported OS, known-exploited).
deny[msg] {
	some f in input.findings
	f.plugin_id in {10001, 20002}
	msg := sprintf("blocked plugin %v on %v (%v)", [f.plugin_id, f.host, f.name])
}

# Deny when required fields are missing.
deny[msg] {
	some f in input.findings
	not f.host
	msg := "finding missing required field: host"
}

deny[msg] {
	some f in input.findings
	not f.plugin_id
	msg := "finding missing required field: plugin_id"
}

deny[msg] {
	some f in input.findings
	not f.severity
	msg := "finding missing required field: severity"
}

allow {
	count(deny) == 0
}
