# Action boundary

The MCP tool gate (`cloakpipe mcp-proxy`, see
[CERTIFICATION.md](CERTIFICATION.md#runtime-the-mcp-tool-gate)) decides
whether a certified release may call a tool. The action boundary narrows that
to whether **this exact call** may run. The model proposes a call; CloakPipe
decides using only trusted inputs (the certified release, its tool contracts,
and a task context written by the orchestrator). Nothing the agent sends can
change those inputs.

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
  --manifest release.yaml --certification release.cert.dsse.json --trust key.json \
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
`_`, `.` or `:`. The tool must be declared by the release, the arguments must
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
  --manifest release.yaml --certification release.cert.dsse.json --trust key.json \
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
(`sideEffect: true`, below), keyed on the receipt's `operationId`.

## Not yet available

A contract tool with `sideEffect: true` needs operation tracking, which this
version does not provide, so the proxy refuses to start with such a contract.
