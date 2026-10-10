# SAMWISE ACS governance integration

Source of architectural authority: https://github.com/Samwise-x/core/blob/main/CONTEXT.md

## Design
This implementation uses AGT's **agent-control-specification Node host SDK**,
backed by the upstream ACS Rust engine and OPA/Rego. It is not the unrelated
general-purpose AGT TypeScript PolicyEngine.

Canonical invariant numbers 1-17 are tracked in invariants.json. Runtime
predicates govern executable actions. Build, deployment, projection replay and
independent memory admission remain separate obligations. The mechanics of CEI-1
and CEI-2 are intentionally unspecified.

The server derives tool classes. Unrecognized skills, dangerous memory
mutations and unknown operations default to denied. Governed builtin and skill
executions and A2A message dispatch pass through the same ACS host gate.
OmniRoute writes pre-execution decisions to its operational SQLite journal.

## Install and pin
The pinned ACS Node compatibility package must be installed in the WSL2
OmniRoute image before enabling this branch. This is deliberately not silently
installed on import:

    npm install --save-exact agent-control-specification@0.3.1-beta.0

Commit the resulting package-lock.json and verify npm ci in the actual target.
OPA/native package availability is required.

Policy integrity pin: compute SHA256 over the concatenated UTF-8 contents of
manifest.yaml, a single LF, and policy/policy.rego. Provide that SHA in the
protected deployment environment as SAMWISE_POLICY_SHA256. Missing or mismatched
pins deny every evaluated action.

ACS native test execution after package installation:

    node --test tests/unit/samwise-governance-acs.test.mjs

## Incomplete production conditions
This is a staged source integration and **not yet a proven totality claim**.
Unmediated raw proxy, MCP, and REST actions may still exist. An end-to-end
coverage inventory, source verification, full typecheck, and AGT conformance
suite must pass before production exposure. The container must restrict direct
YantrikDB HTTP access and authenticate its server-side admission boundary.
OmniRoute submission is not independent YantrikDB cryptographic verification.
The local hash-chained decision journal needs external anchoring to provide
strong tamper evidence against privileged database replacement.

Nothing in this patch adds a second persistent-truth owner or makes YantrikDB
autonomous internal maintenance depend on OmniRoute.
