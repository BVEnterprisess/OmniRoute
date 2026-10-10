import { authorizeSamwiseAction } from "./samwiseGate";
import { classifyEvidenceSubmission } from "./samwiseActions";
export type SamwiseEvidence = Readonly<{
  traceId:string;text:string;domain:string;
  evidenceClass:"tool_result"|"human_trace"|"model_output";
  completeness:"complete"|"partial"|"unknown";
  proposedAuthority:"none"|"eligible";
}>;
/** Governed OmniRoute submission. YantrikDB independently owns actual admission. */
export async function submitSamwiseEvidence(e:SamwiseEvidence,serverPrincipal:string):Promise<unknown> {
  if (!serverPrincipal || !e.traceId || !e.text) throw Error("SW_EVIDENCE_MALFORMED");
  const decisionHash = await authorizeSamwiseAction(
    classifyEvidenceSubmission(serverPrincipal,e.traceId,e.evidenceClass,e.completeness,e.proposedAuthority)
  );
  const url = process.env.YANTRIKDB_HTTP_URL;
  const token = process.env.YANTRIKDB_TOKEN;
  if (!url || !token) throw Error("SW_YANTRIKDB_UNCONFIGURED");
  const endpoint = new URL(url);
  if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      endpoint.pathname !== "/" || !["http:","https:"].includes(endpoint.protocol))
    throw Error("SW_YANTRIKDB_ENDPOINT_INVALID");
  const response = await fetch(new URL("/v1/remember",endpoint), {
    method:"POST",headers:{"Authorization":"Bearer "+token,"Content-Type":"application/json"},
    body:JSON.stringify({text:e.text,domain:e.domain,metadata:{
      samwise_trace_id:e.traceId,samwise_decision_hash:decisionHash,
      samwise_evidence_class:e.evidenceClass,samwise_completeness:e.completeness,
      samwise_proposed_authority:e.proposedAuthority,
    }}),signal:AbortSignal.timeout(10000),cache:"no-store",
  });
  if (!response.ok) throw Error("SW_YANTRIKDB_WRITE_REJECTED");
  return response.json();
}
