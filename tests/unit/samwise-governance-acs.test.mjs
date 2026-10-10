import test from "node:test";
import assert from "node:assert/strict";
import {createRequire} from "node:module";
import {resolve} from "node:path";
import {readFileSync} from "node:fs";
const sdk = createRequire(resolve(process.cwd(),"package.json"))("agent-control-specification");
const root = resolve("src/domain/governance/policies/samwise");
const manifest = readFileSync(resolve(root,"manifest.yaml"),"utf8");
const rego = readFileSync(resolve(root,"policy/policy.rego"),"utf8");
function action(override={}) {return {
  schema:"samwise.action/v1",policy_version:"2026-10-10.1",
  actor_id:"a".repeat(64),actor_kind:"agent",origin:"builtin",
  operation:"read",capability_class:"read_only",authority_owner:"none",
  resource_kind:"external_tool",resource_owner:"omniroute",trace_owner:"omniroute",
  trace_id:"",tool_name:"web_search",model:"",completeness:"unknown",
  evidence_class:"",proposed_authority:"none",history_digest:"",objective:"",
  ...override,
};}
async function decide(acs,args) {return acs.evaluateInterventionPoint("pre_tool_call",{
  tool_call:{id:"stable-id",name:"samwise_action",args}
},"enforce");}
test("manifest and Rego validate",async()=>{
  const check=await sdk.validateArtifacts(manifest,{"policy.rego":rego});
  assert.equal(check.valid,true,JSON.stringify(check.diagnostics));
});
test("same complete input yields same ACS decision and action identity",async()=>{
  const acs=sdk.AgentControl.fromPath(resolve(root,"manifest.yaml"));
  const a=await decide(acs,action()),b=await decide(acs,action());
  assert.equal(a.verdict.decision,"allow");
  assert.deepEqual(a.verdict,b.verdict);
  assert.equal(a.actionIdentity,b.actionIdentity);
});
test("invariants reject mutable history and unauthorized memory",async()=>{
  const acs=sdk.AgentControl.fromPath(resolve(root,"manifest.yaml"));
  for(const invalid of [
    {resource_kind:"asset",operation:"update"},
    {resource_kind:"evaluation",operation:"overwrite"},
    {resource_kind:"canonical_memory",resource_owner:"agent"},
    {trace_owner:"agent"},{operation:"forbidden",capability_class:"unclassified"},
  ]) assert.equal((await decide(acs,action(invalid))).verdict.decision,"deny");
});
test("only complete non-human evidence may be offered as eligible",async()=>{
  const acs=sdk.AgentControl.fromPath(resolve(root,"manifest.yaml"));
  const e={origin:"omniroute_evidence",actor_kind:"service",
    operation:"submit_evidence",capability_class:"append_only_evidence",
    resource_kind:"canonical_memory",resource_owner:"yantrikdb",trace_id:"OMNI-1",
    proposed_authority:"eligible",completeness:"complete",evidence_class:"tool_result"};
  assert.equal((await decide(acs,action(e))).verdict.decision,"allow");
  for(const x of [
    {...e,completeness:"partial"},{...e,evidence_class:"human_trace"},
    {...e,evidence_class:"model_output"},{...e,trace_id:""},
  ]) assert.equal((await decide(acs,action(x))).verdict.decision,"deny");
});
