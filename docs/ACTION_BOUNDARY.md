# Action boundary

The MCP tool gate (`cloakpipe mcp-proxy --manifest release.yaml`) decides
whether the agent's release may call a tool: only the tools the release
declares pass. The action boundary narrows that to whether **this exact
call** may run. The model proposes a call; CloakPipe decides using only
trusted inputs (the release, its tool contracts, and a task context written
by the orchestrator). Nothing the agent sends can change those inputs.

The gate needs no certification: the release only has to declare its tools
and bind its contracts (code, prompt, model and runtime pins are optional).
A complete example, with a prompt-injected `send_email` refused, is in
[`examples/support-agent/`](../examples/support-agent).

The files under [`examples/action-boundary/`](../examples/action-boundary)
are loaded by the test suite, so they stay in step with the code.

## Tool contracts

A tool contract lists, for each tool it covers, the arguments a call may carry
and what each may hold.
[`crm-tools.contract.yaml`](../examples/action-boundary/crm-tools.contract.yaml):

```yaml
apiVersion: cloakpipe.co/v1alpha1
kind: ToolContract
metadata:
  name: crm-tools
spec:
  tools:
    crm.patch:
      sideEffect: true          # track operation outcomes
      requiresApproval: true    # needs a signed approval receipt
      arguments:                # closed by default: unknown argument -> denial
        tenant: { bindTo: task.tenant }
        record: { bindTo: task.record }
        patch:
          type: object
          minProperties: 1
          additionalProperties: false
          properties:
            stage: { enum: [qualified, review] }
            note:  { type: string, maxLength: 280 }
      required: [tenant, record, patch]
```

JSON schema: [`schemas/tool-contract.schema.json`](../schemas/tool-contract.schema.json).

### Constraint language

A small, deterministic subset of JSON Schema, implemented in CloakPipe:

| Keyword | Meaning |
| --- | --- |
| `type` | `string`, `integer`, `number`, `boolean`, `object`, `array` or `null` (one type) |
| `enum`, `const` | JSON equality |
| `minLength`, `maxLength` | counted in Unicode scalar values |
| `pattern` | `regex` crate syntax, matched against the **whole** string |
| `minimum`, `maximum` | inclusive; exact for integers |
| `properties`, `required` | nested object members |
| `additionalProperties` | `true` or `false`; **default `false`** |
| `minProperties`, `maxProperties`, `items`, `minItems`, `maxItems` | as in JSON Schema |
| `bindTo: task.<key>` | the value must equal the task context's value at `<key>` (dots reach nested keys) |

A tool's `arguments` are closed: a call may carry only the arguments listed.
The reader fails closed: an unknown keyword, a duplicate key (in JSON too), a
constraint that restricts nothing (`{}`), keywords of another type (a
`maxLength` next to `type: integer`), an empty `enum`, an uncompilable
`pattern` or a `required` name that is not declared is a parse error. A
keyword only accepts values of its own type: `maxLength: 3` rejects the
number `5`.

### Binding a contract to a release

The contract digest is

```
SHA-256( "cloakpipe.co/tool-contract/v1" || "\n" || JCS(contract) )
```

over the RFC 8785 encoding of the document as written (YAML and JSON
spellings of one document share a digest; no Unicode normalisation is
applied, so contracts that behave differently never share one). The release
binds it in `spec.policies`:

```yaml
policies:
  - ref: policy:tool-contract/crm-tools@sha256:27dfd9d14c9344b6c4364a22a159276f0aa4af6b3adc4b4e995828437cac9a2b
```

([`release.yaml`](../examples/action-boundary/release.yaml)). The contract is
therefore part of the release hash, and so of every certification about it,
with no change to the manifest schema. The `tool-contract/` name prefix marks
the entry as a contract binding, so the gate can tell which policies it must
be given. The proxy prints the reference to use when it refuses a contract
the release does not bind.

### The task context

The orchestrator that starts the agent writes the task context, a JSON object
such as [`task-context.json`](../examples/action-boundary/task-context.json):

```json
{"taskId": "t-981", "tenant": "demo-co", "record": "lead-42"}
```

It reaches the gate only through `--task-context <file>` (or
`CLOAKPIPE_TASK_CONTEXT=<file>`). It is never read from MCP messages:
`_meta`, arguments and everything else the agent sends cannot change it.

### Running the gate with contracts

```bash
cloakpipe mcp-proxy --upstream "npx -y @acme/crm-mcp" \
  --manifest release.yaml \
  --tool-contract crm-tools.contract.yaml --task-context task-context.json
```

The proxy refuses to start (exit 2) when a supplied contract is not bound by
the release, when the release binds a contract that was not supplied, when
two contracts cover one tool, or when the flags are given without
`--manifest`. An unreadable contract or a task context that is not a JSON
object is invalid input (exit 1).

For each `tools/call` to a tool a contract covers, after the release checks
(declared tool, certification), the gate validates the **raw** arguments, as
the agent sent them, before PII masking. Declared tools that no contract
covers behave as before. Refusals use the usual JSON-RPC error `-32001`:

```json
{"jsonrpc":"2.0","id":4,"error":{"code":-32001,"message":"tool call refused by CloakPipe: argument_invalid",
 "data":{"reason":"argument_invalid","path":"/patch/stage","tool":"crm.patch","release":"sha256:…"}}}
```

| Reason | When | `path` |
| --- | --- | --- |
| `argument_missing` | a required argument is absent | the missing argument |
| `argument_not_allowed` | an argument the contract does not list | the object holding it (none at the top level); the name is never echoed |
| `argument_invalid` | a value breaks its constraint, or the arguments are not an object | the contract path |
| `scope_mismatch` | a `bindTo` value differs from the task context | the argument |
| `task_context_missing` | a `bindTo` needs a task context, or a key it does not have | the argument |
| `approval_required` | the tool has `requiresApproval: true` and there is no receipt for this exact call | — |
| `approval_invalid` | the receipt is malformed, not signed by a trusted approver, or for another release, tool, task or call | — |
| `approval_expired` | the receipt's `notAfter` has passed | — |
| `contract_missing` | the release binds a contract the gate was not given (library use only; the CLI refuses to start) | — |

Checks run in a fixed order whatever the order of the arguments: unknown
arguments, then missing ones, then each declared argument by name.

The ledger stays PII-free: the refusal hop carries `gate_denial=<reason>` and,
where one applies, `gate_path=<contract path>`. Paths are built from the
contract, never from the call, and never include a value. If the ledger's
opaque-id check rejects a path (a property named `phone`, say), the hop is
still recorded with `gate_denial` alone. `--gate warn` forwards the call and
records `gate_violation` and `gate_path`.

## Approval receipts

A contract tool with `requiresApproval: true` runs only with a signed approval
receipt for **this exact call**. A person (or a system acting for one) approves
the call out of band; the gate checks the receipt offline.

### The call fingerprint

A receipt is about one call, identified by its fingerprint:

```
SHA-256( "cloakpipe.co/tool-call/v1" || "\n" ||
         JCS({"release": "sha256:<release hash>", "tool": "<name>", "arguments": <raw arguments>}) )
```

The arguments are the raw ones, exactly as the agent sends them (key order
and whitespace do not matter, but every value does; no Unicode
normalisation). Any change to the arguments is a different call, which has no
receipt. Print it with:

```bash
cloakpipe action fingerprint --manifest release.yaml --tool crm.patch --args call.json
# sha256:5b0c…
```

The fingerprint is a plain hash of the arguments, so low-entropy values could
be recovered from it by brute force. It names receipt files and stays with the
operator; it is never written to the ledger.

### Signing a receipt

Approver keys are ordinary CloakPipe signing keys (`cloakpipe release keygen
--out approver.json`).

```bash
cloakpipe approve --manifest release.yaml --tool crm.patch --args call.json \
  --task-context task-context.json --key approver.json \
  [--expires 15m] [--operation-id <id>] --out approvals/
```

This writes `approvals/<fingerprint hex>.approval.json` and prints the
receipt path, the fingerprint, the receipt digest (`sha256` of the file
bytes), the operation id, the approver and `notAfter`. `--expires` takes
`<n>s`, `<n>m`, `<n>h` or `<n>d` (default `15m`). `--operation-id` defaults
to a fresh UUID v4; an explicit one is 1 to 128 ASCII letters, digits, `-`,
`_`, `.` or `:`, and must not contain (in any case) `aadhaar`, `pan`,
`ifsc`, `gstin`, `ssn`, `phone` or `email`: the evidence ledger refuses
those in an opaque id, so the operation's hops could not be recorded. The tool must be declared by the release, the arguments must
be JSON without duplicate keys, and the task context must carry a string
`taskId`.

The receipt is a DSSE envelope (`payloadType`
`application/vnd.in-toto+json`, Ed25519, the same envelope as a
certification) around an in-toto Statement:

```json
{ "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "tool-call:crm.patch", "digest": { "sha256": "<fingerprint hex>" } }],
  "predicateType": "https://cloakpipe.co/attestations/approval/v1alpha1",
  "predicate": { "release": "sha256:…", "tool": "crm.patch", "taskId": "t-981",
                 "operationId": "2b0f8f9e-…", "approver": "ed25519:…",
                 "approvedAt": "2026-10-11T11:55:00Z", "notAfter": "2026-10-11T12:10:00Z" } }
```

`approver` is the keyid of the signing key.

### Running the gate with approvals

```bash
cloakpipe mcp-proxy --upstream "npx -y @acme/crm-mcp" \
  --manifest release.yaml \
  --tool-contract crm-tools.contract.yaml --task-context task-context.json \
  --approvals approvals/ --approver-key approver.pub.json
```

`--approver-key` is repeatable and takes a key file (the public part is
enough). `--approvals` and `--approver-key` must be given together, and the
directory must exist; otherwise the proxy refuses to start (exit 2). Without
them every call to an approval-gated tool is refused as `approval_required`.

For such a call, after the contract checks pass (an approval never widens the
contract), the gate computes the fingerprint, reads
`<fingerprint hex>.approval.json` and accepts it only if:

- a signature verifies under a trusted approver key with a matching keyid,
  and `approver` is that keyid;
- the subject digest is the recomputed fingerprint, and `release`, `tool` and
  `taskId` equal the gate's release, the called tool and the task context's
  `taskId`;
- `operationId` is a valid operation id, both times are RFC 3339 and
  `notAfter` is after `approvedAt`;
- `approvedAt` is no more than 60 seconds ahead of the gate's clock (the same
  allowance as `cloakpipe anchor --clock-skew-secs`), and `notAfter` has not
  passed.

No file means `approval_required`. A file that fails any check is
`approval_invalid`, except a receipt whose only fault is a passed `notAfter`,
which is `approval_expired`. A task context with no `taskId` cannot match any
receipt: `task_context_missing`.

### What the ledger records

On an approved call, the `mcp_tool_call` hop carries
`approval=<sha256 of the receipt file bytes>` (a hash value) and
`operation_id=<the receipt's operationId>`. The receipt itself stays with the
operator: an auditor holding it hashes the file and finds the hop. The ledger
never holds the arguments or their fingerprint.

A receipt is not single-use: the same approved call can run again until
`notAfter`. Replays of one operation are handled by operation tracking
(`sideEffect: true`, [below](#operations-identity-and-outcome-states)),
keyed on the receipt's `operationId`.

## Operations: identity and outcome states

A contract tool with `sideEffect: true` changes something outside the agent
(a CRM record, a payment, an email). Tools fail in the middle: the effect can
land and the reply be lost. A naive retry then does it twice. With
`sideEffect: true`, every call is an **operation** the gate tracks in a
durable store, so a call whose outcome is unknown is never re-run silently.

### The operations store

```bash
cloakpipe mcp-proxy --upstream "npx -y @acme/crm-mcp" \
  --manifest release.yaml \
  --tool-contract crm-tools.contract.yaml --task-context task-context.json \
  --approvals approvals/ --approver-key approver.pub.json \
  --operations-db operations.db
```

`--operations-db <path>` (or `CLOAKPIPE_OPERATIONS_DB=<path>`) is a SQLite
file the operator owns:

```sql
operations(operation_id TEXT PRIMARY KEY, tool TEXT, call_digest BLOB,
           state TEXT, result TEXT, updated_at TEXT)
operation_id_key(id INTEGER PRIMARY KEY, key BLOB)  -- one row
```

`call_digest` is the call fingerprint and `result` the tool's result as it
left the tool (masked, before rehydration). `operation_id_key` holds 32
bytes from the operating system's CSPRNG, made when the database is created
(a key already stored is kept): the key for derived operation ids. All
three are local operator state and never go into the ledger.

So `operations.result` keeps a local copy of each completed side-effecting
call's upstream result. It is masked (PII the detector found is
pseudonymized, never raw), but it is still the tool's output, and with the
vault it can be rehydrated. Protect the database like the vault: on unix a
new operations database (and its `<db>.lock`) is created with mode `0600`;
keep it that way (`chmod 600` an existing one, which CloakPipe leaves as it
finds it) and off shared or synced storage. Set a retention policy too: a
`done` row's result is only needed to replay a retry of that call, so rows
past your retry horizon can be deleted while no proxy runs (`DELETE FROM
operations WHERE state = 'done' AND updated_at < '…'`); a later retry of a
deleted call runs again.

The proxy refuses to start (exit 2) when a supplied contract has a
`sideEffect: true` tool and no operations database is given. One proxy per
database: a running proxy holds an exclusive OS lock on `<db>.lock` beside
the database for as long as it runs, and a second proxy on the same
database refuses to start (exit 2) instead of marking the first one's live
`in_flight` operations `unknown`. `cloakpipe operations list` and
`reconcile` take no lock and work while a proxy runs.

### Operation ids

The model never supplies the operation id. It is the approval receipt's
`operationId` when the tool requires approval; otherwise it is derived from
the task and the call:

```
op- + first 32 hex of HMAC-SHA256(key, "cloakpipe.co/operation/v1" + "\n" + taskId + "\n" + fingerprint hex)
```

where `key` is the operations database's `operation_id_key`. So the same
call in the same task is the same operation (for that database). The id goes
into the ledger beside the release hash, and task ids are guessable: keying
it means a ledger holder cannot test guesses of the arguments (a phone
number, say) against it, as they could against a plain hash. A side-effecting call
needs the task context's `taskId` (`task_context_missing` without it) and a
JSON-RPC request id (a notification is refused as `request_id_missing`,
because its outcome could never be settled).

### States

| State | Meaning | A retry of the same call |
| --- | --- | --- |
| `in_flight` | forwarded, no reply yet | refused: `reconcile_before_retry` |
| `done` | the tool answered with a result | not forwarded: the stored result is replayed |
| `failed` | the tool answered with `isError: true` or a JSON-RPC error | runs again |
| `unknown` | the tool went away before answering: the effect may or may not have happened | refused: `reconcile_before_retry` |
| `not_applied` | an operator found it did not happen | runs again |

Before forwarding, the gate decides in one `BEGIN IMMEDIATE` transaction:

- no row: insert it as `in_flight` and forward;
- a row for a different call (another fingerprint or tool) under the same
  operation id: refuse with `operation_conflict` (`-32001`);
- `done`: do not forward. Answer with the stored result, rehydrated as a live
  reply would be, marked `"_meta": {"cloakpipe": {"replayed": true,
  "operationId": "…"}}`. An operation reconciled as done has no stored
  result: the answer says it already completed;
- `in_flight` or `unknown`: refuse with `reconcile_before_retry` and
  JSON-RPC error code `-32002`:

  ```json
  {"jsonrpc":"2.0","id":2,"error":{"code":-32002,"message":"tool call refused by CloakPipe: reconcile_before_retry",
   "data":{"reason":"reconcile_before_retry","operationId":"op-3c6d…","tool":"crm.patch","release":"sha256:…"}}}
  ```

- `failed` or `not_applied`: set it back to `in_flight` and forward.

The JSON-RPC request id maps the reply to its operation: a `result` without
`isError: true` settles it `done` (the result is stored); `isError: true` or a
JSON-RPC `error` settles it `failed`. A reply to an operation that is no
longer `in_flight` (an operator reconciled it meanwhile) changes nothing and
records no `operation_state`. When the upstream exits or its pipe
breaks with operations still `in_flight`, they become `unknown` and each
waiting request gets a `-32002` error with reason `operation_unknown` and its
`operationId`. An operation an operator already reconciled is left as it is
(no `unknown` hop), and its waiting request still gets a `-32002` error,
with reason `operation_reconciled`, its `operationId` and the reconciled
`state` (`done` or `not_applied`): a request is never left unanswered. When a proxy starts, any row a previous process left
`in_flight` (it crashed) becomes `unknown`. Operation tracking also applies
with `--gate warn`, including to a call that fails the gate and is forwarded
anyway (its id is a verifying receipt's `operationId`, else the derived id):
it is not a release rule.

Other refusals: `request_id_in_use` and `operations_unavailable` (the store
cannot be read or written; fail closed). `request_id_in_use` refuses a
side-effecting call reusing the request id of any agent request still
waiting for its reply, and any agent request (whatever its method) reusing
the request id of a side-effecting call in flight: a reply must map to one
request only. Only a reply settles an operation: a message from the tool
server that carries a `method` (its own request, such as `roots/list` or
`ping`) or has neither `result` nor `error` never does, whatever its id.

### Reconciling

MCP has no standard way to ask a tool whether a call it never answered took
effect, so reconciliation is an explicit operator step: check the system of
record, then settle the operation.

```bash
cloakpipe operations list --state unknown --operations-db operations.db
# [ { "operationId": "op-3c6d…", "tool": "crm.patch", "state": "unknown", "updatedAt": "…" } ]

cloakpipe operations reconcile op-3c6d… --outcome done \
  --operations-db operations.db --ledger-db ledger.db --manifest release.yaml
```

`list` prints ids, tools, states and times only, never the call digest or
the stored result. `reconcile` takes `--outcome done` (it took effect; a retry
replays) or `--outcome not-applied` (it did not; a retry runs). It refuses
(exit 1) unless the operation is `unknown` or `in_flight`, and it refuses
an `in_flight` one (exit 1, with a warning) unless `--force` is given: a
running proxy may still receive that call's reply, and a verdict given now
can contradict what the tool actually did. Use `--force` only once no proxy
can still answer the call (it has stopped, or the system of record is
final). An `unknown` operation needs no flag. With `--ledger-db`
(or `CLOAKPIPE_LEDGER_DB`) it records an `operation_reconciled` hop in the
same transaction, bound to the release given by `--manifest`; if the hop
cannot be written, nothing changes (exit 2). Neither command creates a
missing database (exit 2).

### What the ledger records

| Hop | Metadata |
| --- | --- |
| `mcp_tool_call` (forwarded) | `operation_id` (and `approval` for an approved call) |
| `mcp_tool_call` (refused) | `gate_denial` (`operation_conflict`, `reconcile_before_retry`, …) and `operation_id` |
| `mcp_tool_result` (reply) | `operation_id`, `operation_state=done` or `failed` |
| `mcp_tool_result` (replay) | `operation_id`, `operation_state=done`, `operation_replayed=true` |
| `mcp_tool_result` (exit or start-up sweep) | `operation_id`, `operation_state=unknown` |
| `operation_reconciled` | `operation_id`, `operation_state=done` or `not_applied` |

`operation_reconciled` is its own hop category: the verifier and the auditor
pack count it like any other (`releaseHopsByType`). The ledger never holds
arguments, results or fingerprints.
