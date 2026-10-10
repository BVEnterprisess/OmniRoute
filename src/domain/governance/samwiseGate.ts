import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { appendSamwiseDecision } from "./samwiseJournal";
import { classifySamwiseAction, type SamwiseAction, type SamwiseOrigin } from "./samwiseActions";
type AcsResult = {verdict:{decision:string;reason?:string|null};inputIdentity?:string;actionIdentity?:string};
type Control = {
  evaluateInterventionPoint(p:string, snapshot:Record<string,unknown>, mode:string):Promise<AcsResult>;
  enforce(p:string,result:AcsResult,mode:string):Promise<void>;
};
let cached: {digest:string;control:Control} | undefined;
const ROOT = "src/domain/governance/policies/samwise";
function sha256(s:string) { return createHash("sha256").update(s).digest("hex"); }
function runtime(): {digest:string;control:Control} {
  if (cached) return cached;
  const dir = resolve(process.cwd(),ROOT);
  const manifest = readFileSync(resolve(dir,"manifest.yaml"),"utf8");
  const rego = readFileSync(resolve(dir,"policy/policy.rego"),"utf8");
  const digest = sha256(manifest + "\n" + rego);
  if (!process.env.SAMWISE_POLICY_SHA256 || process.env.SAMWISE_POLICY_SHA256 !== digest) {
    throw Error("SW_POLICY_INTEGRITY_FAILURE");
  }
  const sdk = createRequire(resolve(process.cwd(),"package.json"))("agent-control-specification") as {
    AgentControl:{fromPath(p:string):Control};
  };
  cached = {digest,control:sdk.AgentControl.fromPath(resolve(dir,"manifest.yaml"))};
  return cached;
}
export class SamwiseGovernanceDenied extends Error {
  constructor(public readonly code:string) {super(code);this.name="SamwiseGovernanceDenied";}
}
export async function authorizeSamwiseAction(action:SamwiseAction):Promise<string> {
  const id = randomUUID();
  let result:AcsResult|undefined;
  let policyDigest = "unavailable";
  try {
    const acs = runtime();
    policyDigest = acs.digest;
    result = await acs.control.evaluateInterventionPoint("pre_tool_call", {
      tool_call:{id,name:"samwise_action",args:action},
    },"enforce");
    const decision = result.verdict?.decision;
    const auditHash = appendSamwiseDecision({
      id,policyDigest,actionIdentity:result.actionIdentity??result.inputIdentity??"",
      decision:decision??"deny",reason:result.verdict?.reason??"SW_DENY",
    });
    if (decision !== "allow") throw new SamwiseGovernanceDenied(result.verdict?.reason??"SW_DENY");
    await acs.control.enforce("pre_tool_call",result,"enforce");
    return auditHash;
  } catch (err) {
    if (!result) {
      try {appendSamwiseDecision({id,policyDigest,decision:"deny",reason:"SW_RUNTIME_ERROR"});}
      catch { /* a failed journal never permits an action */ }
    }
    if (err instanceof SamwiseGovernanceDenied) throw err;
    throw new SamwiseGovernanceDenied("SW_GOVERNANCE_UNAVAILABLE");
  }
}
export async function authorizeSamwiseTool(
  origin:SamwiseOrigin, name:string, input:Record<string,unknown>, actor:string,
):Promise<void> {
  if (!actor || actor === "anonymous") throw new SamwiseGovernanceDenied("SW_UNAUTHENTICATED");
  const action = classifySamwiseAction(origin,name,input,sha256(actor));
  await authorizeSamwiseAction(action);
}
