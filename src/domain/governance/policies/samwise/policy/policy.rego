package samwise.governance

import rego.v1

# Rules operate on server-classified facts, never raw agent authority claims.
default verdict := {"decision": "deny", "reason": "SW_DEFAULT_DENY"}

verdict := {"decision": "allow", "reason": "SW_CANONICAL_ALLOW"} if {
  input.intervention_point == "pre_tool_call"
  a := input.policy_target.value
  a.schema == "samwise.action/v1"
  a.policy_version == "2026-10-10.1"
  is_string(a.actor_id)
  count(a.actor_id) == 64
  is_string(a.capability_class)
  a.capability_class != ""
  count(violations) == 0
}

# I1,I2,I3,I10: agents/models may not own canonical authority.
violations contains "SW_I1_I2_I3_I10" if {
  a := input.policy_target.value
  a.actor_kind == "agent"
  a.authority_owner != "none"
}
violations contains "SW_I2" if {
  a := input.policy_target.value
  a.resource_kind == "canonical_memory"
  a.resource_owner != "yantrikdb"
}
# I4: human intent has one designated owner.
violations contains "SW_I4" if {
  a := input.policy_target.value
  a.operation == "human_intent"
  a.resource_owner != "openclaw"
}
# I5/I16: OmniRoute owns governed event streams and trace conversion.
violations contains "SW_I5" if {
  a := input.policy_target.value
  a.trace_owner != "omniroute"
}
violations contains "SW_I16" if {
  a := input.policy_target.value
  a.operation == "trace_to_asset"
  a.resource_owner != "omniroute"
}
# I6-I9: owner-specific capability routes.
component_owners := {
  "browser_state": "tandem",
  "visual_discovery": "midscene",
  "workflow": "n8n",
  "device_mesh": "tailscale",
  "canonical_memory": "yantrikdb"
}
violations contains "SW_I6_I9" if {
  a := input.policy_target.value
  expected := component_owners[a.resource_kind]
  a.resource_owner != expected
}
# I11: compounding is the only authorized optimization objective.
violations contains "SW_I11" if {
  a := input.policy_target.value
  a.operation == "configure_optimizer"
  a.objective != "compounding"
}
# I13: immutable assets and append-only relationships cannot be mutated.
immutable_kinds := {"asset", "evaluation", "evidence_link", "relation", "policy_decision"}
violations contains "SW_I13" if {
  a := input.policy_target.value
  a.resource_kind in immutable_kinds
  a.operation in {"update", "delete", "overwrite", "replace"}
}
# I14: learning operates on projections, never authoritative history.
violations contains "SW_I14" if {
  a := input.policy_target.value
  a.operation == "learn"
  a.resource_kind != "projection"
}
violations contains "SW_I14_HISTORY" if {
  a := input.policy_target.value
  a.operation == "learn"
  not a.history_digest
}
# I15: partial evidence or human/model perturbations cannot promote authority.
violations contains "SW_I15_PARTIAL" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  a.proposed_authority == "eligible"
  a.completeness != "complete"
}
violations contains "SW_I15_ORIGIN" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  a.proposed_authority == "eligible"
  a.evidence_class in {"human_trace", "model_output"}
}
# I17: provider names are never capability classes.
violations contains "SW_I17" if {
  a := input.policy_target.value
  a.model != ""
  a.capability_class == a.model
}
# Closed action vocabulary. Unknown operations are denied.
valid_operations := {"read", "model_route", "execute", "append", "submit_evidence"}
valid_origins := {"skill", "builtin", "a2a", "omniroute_evidence"}
violations contains "SW_UNKNOWN_OPERATION" if {
  a := input.policy_target.value
  not a.operation in valid_operations
}
violations contains "SW_UNKNOWN_ORIGIN" if {
  a := input.policy_target.value
  not a.origin in valid_origins
}
violations contains "SW_UNCLASSIFIED" if {
  a := input.policy_target.value
  a.capability_class == "unclassified"
}
violations contains "SW_NONREAD_TOOL" if {
  a := input.policy_target.value
  a.origin in {"skill", "builtin"}
  a.operation != "read"
}
violations contains "SW_EXEC_DENIED" if {
  a := input.policy_target.value
  a.operation == "execute"
  a.capability_class != "safe_execution"
}
violations contains "SW_EVIDENCE_KIND" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  a.resource_kind != "canonical_memory"
}
violations contains "SW_EVIDENCE_ORIGIN" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  a.origin != "omniroute_evidence"
}
violations contains "SW_EVIDENCE_TRACE" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  not a.trace_id
}
violations contains "SW_EVIDENCE_OWNER" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  a.resource_owner != "yantrikdb"
}
violations contains "SW_EVIDENCE_CLASS" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  not a.evidence_class in {"tool_result", "human_trace", "model_output"}
}
violations contains "SW_EVIDENCE_AUTHORITY" if {
  a := input.policy_target.value
  a.operation == "submit_evidence"
  not a.proposed_authority in {"none", "eligible"}
}
