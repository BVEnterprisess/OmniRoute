import { createHash } from "node:crypto";
export type SamwiseOrigin = "skill" | "builtin" | "a2a" | "omniroute_evidence";
export type SamwiseAction = {
  schema: "samwise.action/v1";
  policy_version: "2026-10-10.1";
  actor_id: string;
  actor_kind: "agent" | "service";
  origin: SamwiseOrigin;
  operation: string;
  capability_class: string;
  authority_owner: string;
  resource_kind: string;
  resource_owner: string;
  trace_owner: "omniroute";
  trace_id: string;
  tool_name: string;
  model: string;
  completeness: "complete" | "partial" | "unknown";
  evidence_class: string;
  proposed_authority: "none" | "eligible";
  history_digest: string;
  objective: string;
};
// Only code-reviewed capabilities may be classified as safe.
const READ_BUILTINS = new Set(["web_search", "web_fetch"]);
const READ_A2A = new Set(["list-capabilities", "cost-analysis", "health-report", "provider-discovery"]);
const ROUTE_A2A = new Set(["smart-routing"]);
const READ_SKILLS = new Set<string>([]);

export function classifySamwiseAction(
  origin: SamwiseOrigin, name: string, input: Record<string, unknown>, actorId: string,
): SamwiseAction {
  let operation = "forbidden", capability_class = "unclassified";
  if (origin === "builtin" && READ_BUILTINS.has(name)) {
    operation = "read"; capability_class = "read_only";
  } else if (origin === "builtin" && name === "http_request") {
    const method = typeof input.method === "string" ? input.method.toUpperCase() : "";
    if (method === "GET" || method === "HEAD") {
      operation = "read"; capability_class = "read_only";
    }
  } else if (origin === "a2a" && READ_A2A.has(name)) {
    operation = "read"; capability_class = "read_only";
  } else if (origin === "a2a" && ROUTE_A2A.has(name)) {
    operation = "model_route"; capability_class = "model_routing";
  } else if (origin === "skill" && READ_SKILLS.has(name)) {
    operation = "read"; capability_class = "read_only";
  }
  return {
    schema: "samwise.action/v1", policy_version: "2026-10-10.1",
    actor_id: actorId, actor_kind: "agent", origin, operation, capability_class,
    authority_owner: "none", resource_kind: "external_tool",
    resource_owner: "omniroute", trace_owner: "omniroute", trace_id: "",
    tool_name: name, model: "", completeness: "unknown",
    evidence_class: "", proposed_authority: "none", history_digest: "", objective: "",
  };
}
export function classifyEvidenceSubmission(
  principal: string, traceId: string,
  evidenceClass: "tool_result" | "human_trace" | "model_output",
  completeness: "complete" | "partial" | "unknown",
  proposedAuthority: "none" | "eligible",
): SamwiseAction {
  return {
    schema: "samwise.action/v1", policy_version: "2026-10-10.1",
    actor_id: createHash("sha256").update(principal).digest("hex"),
    actor_kind: "service", origin: "omniroute_evidence", operation: "submit_evidence",
    capability_class: "append_only_evidence", authority_owner: "none",
    resource_kind: "canonical_memory", resource_owner: "yantrikdb",
    trace_owner: "omniroute", trace_id: traceId, tool_name: "yantrikdb.remember",
    model: "", completeness, evidence_class: evidenceClass,
    proposed_authority: proposedAuthority, history_digest: "", objective: "",
  };
}
