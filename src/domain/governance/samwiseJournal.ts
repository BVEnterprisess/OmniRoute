import { createHash } from "node:crypto";
import { getDbInstance } from "../../lib/db/core";
function digest(x: string) { return createHash("sha256").update(x).digest("hex"); }
function canonical(x: unknown): string {
  if (x === null || typeof x === "boolean" || typeof x === "string") return JSON.stringify(x);
  if (typeof x === "number" && Number.isFinite(x)) return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map(canonical).join(",") + "]";
  if (x && typeof x === "object") {
    const o = x as Record<string, unknown>;
    return "{" + Object.keys(o).sort().map(k => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
  }
  throw Error("SW_NON_CANONICAL_AUDIT_ENTRY");
}
const DDL = [
 "CREATE TABLE IF NOT EXISTS samwise_governance_decisions(",
 "seq INTEGER PRIMARY KEY AUTOINCREMENT, previous_hash TEXT NOT NULL,",
 "entry_hash TEXT NOT NULL, entry_json TEXT NOT NULL);",
 "CREATE TRIGGER IF NOT EXISTS samwise_decision_no_update",
 "BEFORE UPDATE ON samwise_governance_decisions BEGIN",
 "SELECT RAISE(ABORT, 'SW_APPEND_ONLY'); END;",
 "CREATE TRIGGER IF NOT EXISTS samwise_decision_no_delete",
 "BEFORE DELETE ON samwise_governance_decisions BEGIN",
 "SELECT RAISE(ABORT, 'SW_APPEND_ONLY'); END;"
].join("\n");
export function appendSamwiseDecision(entry: Record<string, unknown>): string {
  const db = getDbInstance();
  db.exec(DDL);
  const payload = canonical(entry);
  let hash = "";
  db.immediate(() => {
    const row = db.prepare("SELECT entry_hash FROM samwise_governance_decisions ORDER BY seq DESC LIMIT 1")
      .get() as {entry_hash:string} | undefined;
    const previous = row?.entry_hash ?? "GENESIS";
    hash = digest(previous + "\n" + payload);
    db.prepare("INSERT INTO samwise_governance_decisions(previous_hash,entry_hash,entry_json) VALUES(?,?,?)")
      .run(previous, hash, payload);
  });
  return hash;
}
export function verifySamwiseDecisionChain(): boolean {
  const db = getDbInstance();
  const rows = db.prepare("SELECT previous_hash,entry_hash,entry_json FROM samwise_governance_decisions ORDER BY seq")
    .all() as Array<{previous_hash:string; entry_hash:string; entry_json:string}>;
  let previous = "GENESIS";
  for (const row of rows) {
    if (row.previous_hash !== previous || digest(previous + "\n" + row.entry_json) !== row.entry_hash) return false;
    previous = row.entry_hash;
  }
  return true;
}
