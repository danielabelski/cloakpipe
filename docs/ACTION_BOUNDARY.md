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
| `approval_required` | the tool has `requiresApproval: true` | — |
| `contract_missing` | the release binds a contract the gate was not given (library use only; the CLI refuses to start) | — |

Checks run in a fixed order whatever the order of the arguments: unknown
arguments, then missing ones, then each declared argument by name.

The ledger stays PII-free: the refusal hop carries `gate_denial=<reason>` and,
where one applies, `gate_path=<contract path>`. Paths are built from the
contract, never from the call, and never include a value. If the ledger's
opaque-id check rejects a path (a property named `phone`, say), the hop is
still recorded with `gate_denial` alone. `--gate warn` forwards the call and
records `gate_violation` and `gate_path`.

### Not yet available

`requiresApproval: true` tools are refused (`approval_required`) until signed
approval receipts are supported. A contract tool with `sideEffect: true`
needs operation tracking, which this version does not provide, so the proxy
refuses to start with such a contract.
