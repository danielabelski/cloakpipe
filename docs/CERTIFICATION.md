# Agent Release certification

Certification turns evaluation evidence about one exact Agent Release into a
deterministic decision and a signed, scoped, expiring attestation that anyone
can verify offline.

```
release manifest ─┐
evaluation runs ──┼─> decide(policy) ─> Decision ─> sign ─> DSSE(in-toto) ─> verify(now, trust, revocations)
baseline runs  ───┘
```

Crate: [`crates/cloakpipe-cert`](../crates/cloakpipe-cert). Each module's doc
comment is the normative contract:

| Module | Contract |
|---|---|
| `model` | `EvaluationRun`, `CertificationPolicy`, `Decision`; canonical hashes (`cloakpipe.co/evaluation-run/v1`, `cloakpipe.co/certification-policy/v1`, RFC 8785, same scheme as release manifests). |
| `import` | JUnit XML, Braintrust experiments, Langfuse experiments (and legacy dataset runs) and native JSON → `EvaluationRun`. |
| `policy` | `decide()`: input validity, release binding, required assurance, coverage, pass rate, regression vs baseline, critical failures (new vs persisting), metric thresholds, two-way boundary. Pure and deterministic. |
| `statement` | in-toto v1 Statement in a DSSE envelope signed with Ed25519; verification statuses `VALID`, `VALID_WITH_LIMITATIONS`, `INCOMPLETE`, `EXPIRED`, `REVOKED`, `INVALID`. |

Runs and policies use `apiVersion: cloakpipe.co/v1alpha1`; certifications
use predicate type `https://cloakpipe.co/attestations/certification/v1alpha1`.
The `cloakpipe.dev/...` identifiers written by CloakPipe up to 0.10 are still
accepted, and such runs and policies keep their legacy hash domains, so hashes
pinned in earlier certifications still match.

## CLI

All commands are offline and deterministic given their inputs (`--now` pins
time). Exit codes: **0** ok / certified, **1** invalid input, BLOCKED
decision or attestation that does not certify, **2** usage or I/O error.

### `cloakpipe release keygen [--out FILE]`

Generates an Ed25519 signing key and prints
`{"keyid", "publicKey", "privateKey"}` (hex; `privateKey` is the 32-byte
seed). `keyid = "ed25519:" + first 16 hex chars of SHA-256(public key)`.
With `--out`, the full key is written to `FILE` with mode `0600` (an existing
file is never overwritten) and only `keyid` and `publicKey` are printed —
publish those to verifiers.

### `cloakpipe eval import`

```
cloakpipe eval import (--junit FILE | --braintrust FILE
                       | --langfuse-experiment FILE --langfuse-experiment-items FILE
                       | --langfuse-run FILE --langfuse-scores FILE)
    --release <manifest | sha256:hex> --suite NAME@VERSION --covers a,b
    [--critical PATTERN]... [--pass-threshold T] [--run-id ID] [--tool NAME]
    [--dataset REF] [--out FILE]
```

Turns an evaluation report into a native `EvaluationRun` (rules in `import`)
on stdout or in `--out`. Exactly one source is required. A manifest path
must be certifiable and is replaced by its hash. `--run-id` defaults to
`NAME@VERSION`; `--critical` takes `prefix*` or exact case ids. An invalid
report or run exits 1 with the issues on stderr; a missing file or a bad
argument exits 2.

- **`--junit`**: JUnit XML from pytest, Jest, Go, JUnit or cargo-nextest.
  Status comes from `<failure>`/`<error>`/`<skipped>`. Case properties
  `cloakpipe.critical`, `cloakpipe.score`, `cloakpipe.metric.<name>` and
  `cloakpipe.expect` (`allow`/`deny`, see [Two-way boundary](#two-way-boundary))
  are read.
- **`--braintrust`**: a Braintrust experiment's events (`/fetch` output, an
  array of events, or JSONL). Each root span is one case. Its scores are
  the root's own `scores` plus those of its scorer spans
  (`span_attributes.type: "score"`), which is where the SDK's `Eval()`
  logs each scorer's result; other child spans (task, LLM calls) are
  ignored. The case id is `metadata.cloakpipe_case_id`, else
  `metadata.case_id`, else the dataset record (`origin.id` of a dataset
  `origin`, or `dataset_record_id` from older SDKs) — row ids change
  between runs, so an event with none of these is rejected. Run the
  experiment with one trial (`trial_count`/`trialCount` 1): every trial is
  its own root span with the same case id, which is rejected as a
  duplicate. `metadata.critical: true` marks a case critical;
  `metadata["cloakpipe.expect"]` (`allow`/`deny`) labels a boundary case. `error` on
  the root or a scorer span, or a scorer that crashed
  (`metadata.scorer_errors`), → `error`; `metrics.start/end` →
  `durationMs`; token counts → `metrics.tokens.*`.
- **`--langfuse-experiment` + `--langfuse-experiment-items`**: a Langfuse
  experiment (`GET /api/public/experiments?id=…`, Langfuse Cloud and
  self-hosted v4+) and every page of its items fetched with
  `fields=core,dataset,scores` (`GET /api/public/experiment-items`, a page
  or an array of pages in fetch order). Each item is one case with id
  `experimentItemId` (the dataset item id); its scores are the ones Langfuse
  returns inline — the item's own and its trace's. `BOOLEAN` scores count
  as 0/1; `CATEGORICAL`, `TEXT` and `CORRECTION` scores are ignored; an
  item with `level: ERROR` is `error`. Fails closed on anything that could
  hide a failing case: a last page that still has a `meta.cursor` (more
  pages exist), an earlier page without one, a repeated cursor, a page
  without `meta`, an item count different from the experiment's
  `itemCount`, items of another experiment, a repeated `experimentItemId`,
  items fetched without `fields=scores`, and an item listing 50 scores (the
  maximum `scoreLimit`, so more may have been cut off). Experiment-level
  scores are aggregates and are ignored. With `--score`, unselected scores
  are not validated at all (an unknown `dataType` on one is ignored). Fetch
  once the experiment has finished: items still arriving make the count
  differ from `itemCount`, which is rejected. `--dataset` defaults to the
  experiment's `datasetId`. Langfuse has no critical flag: use
  `--critical`. An item whose `metadata` object has `"cloakpipe.expect"`
  (`allow`/`deny`) is a labelled boundary case.
- **`--langfuse-run` + `--langfuse-scores`** (deprecated, see below): a
  Langfuse dataset run and the scores of its traces. Each run item is one case with id `datasetItemId`;
  a score joins an item by `traceId` (trace scores, or scores of the item's
  own `observationId`). `BOOLEAN` scores count as 0/1; `CATEGORICAL`,
  `TEXT` and `CORRECTION` scores are ignored. Scores must come from
  `GET /api/public/v2/scores` (v3 output is rejected), and every page the
  listing's `meta.totalPages` announces must be included — a missing page
  is rejected, since it could hold a failing score. A score id repeated
  with different contents (pages fetched at different times) is rejected:
  fetch again. Langfuse has no critical flag: use `--critical`.
  `--dataset` defaults to the run's `datasetName`.

Score-based sources decide each case from its scores with
`--pass-threshold` (default `0.5`, within `0..=1`; not accepted with
`--junit`): **pass** iff every score `>=` the threshold, else **fail**; an
explicit error, or **no numeric score at all, is `error`** — an unscored
case is not evidence, so it fails closed. `score` is the mean of the case's
scores and each score is kept as `metrics["score.<name>"]`, so policies can
put thresholds on individual scorers (`metric: score.Factuality`). Scores
must lie in `0..=1`, and a scorer name may appear only once per case.
`--score NAME` (repeatable) restricts the decision to the named scores:
any other score (a 1–5 user-feedback rating, a latency score) is ignored
without validation, and a case missing a named score is `error`.

#### Getting the inputs

Braintrust (REST API, bearer token; follow `cursor` for more than one page,
or flatten pages to JSONL):

```sh
curl -sf -H "Authorization: Bearer $BRAINTRUST_API_KEY" \
  "https://api.braintrust.dev/v1/experiment/$EXPERIMENT_ID/fetch?limit=1000" > experiment.json
# More pages: repeat with &cursor=<.cursor of the previous page>, then
#   jq -c '.events[]' page-*.json > experiment.jsonl
cloakpipe eval import --braintrust experiment.json --release release.yaml \
  --suite support-critical@23 --covers privacy,functional --critical 'privacy::*' --out run.json
```

Langfuse experiments (public API, basic auth `public key:secret key`):
`tools/fetch_langfuse_experiment.sh` fetches the experiment and follows
`meta.cursor` through every page of its items, using the same
`fromStartTime`/`toStartTime` window for both requests (the importer
compares the item count with the experiment's `itemCount`):

```sh
export LANGFUSE_HOST=https://cloud.langfuse.com LANGFUSE_PUBLIC_KEY=pk-lf-… LANGFUSE_SECRET_KEY=sk-lf-…
# Experiment id by name (fromStartTime is required by the API):
curl -sSfG -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" "$LANGFUSE_HOST/api/public/experiments" \
  --data-urlencode fromStartTime=2026-10-01T00:00:00Z --data-urlencode name=support-agent-184-golden \
  | jq '.data[] | {id, name, itemCount}'
tools/fetch_langfuse_experiment.sh "$EXPERIMENT_ID" 2026-10-01T00:00:00Z
# → lf-experiment.json, lf-experiment-items.json
cloakpipe eval import --langfuse-experiment lf-experiment.json \
  --langfuse-experiment-items lf-experiment-items.json \
  --release release.yaml --suite support-critical@23 --covers privacy,functional \
  --critical 'privacy::*' --pass-threshold 0.7 --score correctness --score pii_leak_free --out run.json
```

By hand, the script is: `GET /api/public/experiments?id=<id>&fromStartTime=<from>&toStartTime=<to>`
saved as is, then `GET /api/public/experiment-items?experimentId=<id>&fromStartTime=<from>&toStartTime=<to>&fields=core,dataset,scores&limit=100&scoreLimit=50`,
repeated with `&cursor=<meta.cursor of the previous page>` until a page has
no `meta.cursor`, and every page collected in order with `jq -s .`.

Legacy Langfuse dataset runs (deprecated; URL-encode dataset and run
names). Scores are listed by `GET /api/public/v2/scores` (the
importer reads the v2 shape, with a top-level `traceId`), at most 100 per
page; fetch every page of each trace's scores and pass them as an array of
pages (`jq -s`):

```sh
set -o pipefail
lf() { curl -sSf -u "$LANGFUSE_PUBLIC_KEY:$LANGFUSE_SECRET_KEY" "$LANGFUSE_HOST$1"; }
lf "/api/public/datasets/support-golden/runs/support-agent-184-golden" > lf-run.json
jq -r '.datasetRunItems[].traceId' lf-run.json | sort -u | while read -r t; do
  page=1
  while :; do
    lf "/api/public/v2/scores?traceId=$t&limit=100&page=$page" > lf-page.json || exit 1
    cat lf-page.json
    [ "$page" -ge "$(jq '.meta.totalPages' lf-page.json)" ] && break
    page=$((page + 1))
  done
done | jq -s . > lf-scores.json
cloakpipe eval import --langfuse-run lf-run.json --langfuse-scores lf-scores.json \
  --release release.yaml --suite support-critical@23 --covers privacy,functional \
  --critical 'privacy::*' --pass-threshold 0.7 --score correctness --score pii_leak_free --out run.json
```

`--langfuse-run`/`--langfuse-scores` are deprecated: Langfuse removes
`GET /api/public/datasets/{dataset}/runs/{run}` and `GET /api/public/v2/scores`
on Langfuse Cloud on 2026-11-16 (self-hosted: with the v4 upgrade), when
dataset runs become experiments. They keep working against deployments
that still serve those endpoints; use `--langfuse-experiment` for
everything else.

### `cloakpipe release certify`

```
cloakpipe release certify MANIFEST --policy FILE --run FILE...
    [--baseline MANIFEST --baseline-run FILE...] [--require a,b]
    --environment ENV --issuer ID [--key KEYFILE] [--now RFC3339]
    [--limitation TEXT]... [--out FILE] [--json]
```

- **Required suites** = `cloakpipe_release::diff(baseline, candidate).required_suites`
  ∪ `--require`. Without `--baseline` only `--require` applies; an empty
  set is allowed but warned about on stderr.
- **Decision**: `policy::decide` over the candidate's manifest hash, the
  runs, the baseline runs and the policy (YAML, or JSON when the file ends
  in `.json`). Structurally invalid runs or policies become `invalid_input`
  reasons; unparseable files exit 1.
- **Signing** (`--key`): a `Certification` with `issuedAt = --now` (default:
  current UTC), `validUntil = issuedAt + policy.validityDays`, the
  manifest's agent, `--environment`, `--issuer` and `--limitation`s, signed
  into a DSSE envelope written to `--out` (default
  `<manifest stem>.cert.dsse.json` in the working directory). BLOCKED
  decisions are signed too: an attestation of a block.
- **Output**: `CERTIFIED` or `BLOCKED`, the release hash, the policy, the
  required suites, then one line per reason. `--json` prints
  `{"decision", "envelope"?, "envelopePath"?}`.
- Exit 0 iff the decision is `certified`.

### Two-way boundary

Authorization-style suites are easy to pass by refusing everything: every
"must refuse" test passes, and a pass rate over a deny-heavy suite looks
fine. A policy's `rules.boundary` measures the boundary both ways. Label
each case of the listed suites with what a correct agent does:

- `expect: deny` — the action must be refused; the case **passes** when it
  was refused.
- `expect: allow` — the action is legitimate; the case **passes** when it
  went through.

```yaml
apiVersion: cloakpipe.co/v1alpha1
kind: CertificationPolicy
name: support-prod
version: "12"
validityDays: 30
rules:
  minCoverage: 1.0
  boundary:
    suites: [authorization]
    minDenyRate: 1.0
    minAllowRate: 0.9
```

`suites` are assurance suite names as runs list them in `covers`
(`authorization`, `access_control`, `side_effect`, …); `minDenyRate`
defaults to `1.0` and `minAllowRate` to `0.9`. List every suite whose
boundary the release must hold (for example `[authorization,
access_control, side_effect]`); each listed suite needs a run that covers
it.

**Each covering run is evaluated on its own.** For each listed suite,
every candidate run that covers it is checked against its own labelled
cases; cases of different runs are never pooled. A clean run therefore
cannot dilute a failing one (90 of 90 allow cases completed in one run do
not hide 5 of 10 in another), and deny cases in one run and allow cases in
another do not make either run complete. Every covering run must meet both
minimums and have both kinds of case:

| Reason | When |
|---|---|
| `under_blocking` | a covering run's deny rate = passed deny cases / deny cases < `minDenyRate` (a forbidden action went through) |
| `over_refusal` | a covering run's allow rate = passed allow cases / allow cases < `minAllowRate` (legitimate work was refused) |
| `boundary_incomplete` | no run covers the suite, or a covering run has no labelled case, no deny case, or no allow case |

Each reason carries the suite (`suite`) and names the run in its message
(`run "<runId>": boundary suite "<suite>": …`); a suite that fails in two
runs gives one reason per run. Rates in the message are rounded to at most
4 decimal places (`0.6667` for 2/3); `observed` and `required` keep the
exact values.

Case ids are unique within a run: a run with a duplicate case id is
invalid (`invalid_input`) and is not evaluated at all, so a case can never
be counted twice. The same case id in two different runs is two cases,
each counted only in its own run's rates.

A skipped, failed or errored labelled case is not passed. Unlabelled cases
are ignored by this check (they still count for pass rate and coverage). A
listed suite that no run covers is `boundary_incomplete`, so a run that
claims to cover a different suite cannot skip the check; when the suite is
also required (`--require`) it is reported once, as `missing_suite`. Like
every reason, these appear in the `certify` output and in the signed
decision (`predicate.certification.decision.reasons[].code`, with
`observed`/`required` rates). A policy without `boundary` and runs without
labels hash and decide exactly as before.

**Enabling `rules.boundary` requires labelling.** Adding `boundary` to a
policy blocks every release whose covering runs for the listed suites are
not labelled: runs imported before labels were added (or from a harness
that does not emit `cloakpipe.expect`) have no labelled case and fail with
`boundary_incomplete`. Label every case of the listed suites and re-import
the runs before turning the rule on, or list only suites whose runs are
already labelled.

Labels come from the JUnit property `cloakpipe.expect`, the native JSON
case field `expect`, and `metadata["cloakpipe.expect"]` on Braintrust events
and Langfuse experiment items. Any other value is rejected on import,
including `null`, and so is Braintrust or Langfuse `metadata` that is not
an object: a label that cannot be read never drops a case silently.

```xml
<testcase classname="authz" name="reads_other_tenant">
  <properties>
    <property name="cloakpipe.expect" value="deny"/>
  </properties>
</testcase>
<testcase classname="authz" name="reads_own_ticket">
  <properties>
    <property name="cloakpipe.expect" value="allow"/>
  </properties>
  <failure message="refused a legitimate request"/>
</testcase>
```

```sh
cloakpipe eval import --junit authz.xml --release release.yaml \
  --suite authz@1 --covers authorization --out authz-run.json
cloakpipe release certify release.yaml --policy policy.yaml --run authz-run.json \
  --require authorization --environment production --issuer ci:acme/support --key key.json
# BLOCKED ...
#   - over_refusal [authorization]: run "authz@1": boundary suite "authorization": allow rate 0 (0/3 allow cases completed) is below the minimum 0.9
```

### `cloakpipe release verify-cert`

```
cloakpipe release verify-cert ENVELOPE [--trust KEYFILE]... [--trust-key KEYID=PUBHEX]...
    [--release <manifest | sha256:hex>] [--require-run HASH]...
    [--revoked-statement HEX]... [--revoked-key KEYID]... [--now RFC3339] [--json]
```

Runs `statement::verify` and prints the status (`VALID`,
`VALID_WITH_LIMITATIONS`, `INCOMPLETE`, `EXPIRED`, `REVOKED`, `INVALID`), the
decision outcome, release, statement digest and reasons (`--json`: the
`Report`). Key files from `keygen` are accepted as trust anchors; only their
public part is used and a declared `keyid` must match the key. Exit 0 iff
`report.certified` (valid, possibly with limitations, *and* a certified
decision).

### End to end

```sh
cloakpipe release keygen --out key.json
cloakpipe eval import --junit report.xml --release release.yaml \
  --suite support-critical@23 --covers privacy,functional --critical 'privacy::*' --out run.json
cloakpipe release certify release.yaml --policy policy.yaml --run run.json \
  --baseline previous.yaml --baseline-run previous-run.json \
  --environment production --issuer ci:acme/support --key key.json
cloakpipe release verify-cert release.cert.dsse.json --trust key.json --release release.yaml
```

## GitHub Action

[`.github/actions/certify`](../.github/actions/certify) wraps `release certify`
for workflows: it installs the CLI (`cargo install --git
https://github.com/rohansx/cloakpipe … cloakpipe-cli --locked` at
`cloakpipe-ref`), certifies, writes a job summary and sets the outputs
`outcome`, `envelope` and `decision`. The `signing-key` input takes the
contents of a `keygen` key file from a secret; it is written to a `0600`
temp file for the step and removed afterwards. The action uploads nothing.

```yaml
- id: cert
  uses: rohansx/cloakpipe/.github/actions/certify@main
  with:
    manifest: release.yaml
    policy: certification-policy.yaml
    runs: |
      runs/support-critical.json
    baseline-manifest: releases/previous.yaml
    baseline-runs: |
      runs/previous/support-critical.json
    environment: production
    signing-key: ${{ secrets.CLOAKPIPE_CERT_KEY }}
```

See the action's [README](../.github/actions/certify/README.md) for all
inputs. The `certification-gate` CI job exercises the CLI and the action on
the fixtures in `crates/cloakpipe-cli/tests/fixtures/certification/`.

## Runtime: the MCP tool gate

`cloakpipe mcp-proxy` enforces certification where an agent acts: its tool
calls. With `--manifest`, each `tools/call` passes only if

1. the tool is declared in the manifest's `spec.tools` (`tool:refund@4`
   declares `refund`), and
2. `--certification` verifies offline at the moment of the call: trusted
   signer (`--trust` / `--trust-key`), not revoked (`--revoked-statement`),
   inside its validity window, about this manifest's release, a `certified`
   decision, for `--environment` (default `production`).

```
cloakpipe mcp-proxy --upstream "npx -y @acme/crm-mcp" \
  --manifest release.yaml --certification release.cert.dsse.json \
  --trust-key "$KEYID=$PUBHEX" --environment production
```

`--gate enforce` (default): a refused call never reaches the upstream tool.
The agent receives JSON-RPC error `-32001` with
`data: {reason, tool, release}` (notifications get no reply). Reasons:
`undeclared_tool`, `uncertified` (no `--certification`), `wrong_environment`,
`blocked`, or the verification status (`expired`, `revoked`, `invalid`, …).
The refusal is recorded as a release-bound `mcp_tool_call` hop with action
`block` and `gate_denial=<reason>`. `--gate warn` forwards the call, logs the
violation and marks the hop `gate_violation=<reason>`.

The gate fails closed:

- With a gate, only a message it can read in full is forwarded, re-serialized
  (never the raw line). In both modes it refuses, with a JSON-RPC error
  (`id: null`) and a `block` hop: lines that do not parse
  (`unreadable`, -32700; e.g. out-of-range numbers, lone surrogates, deep
  nesting that laxer upstream parsers accept), batches (`batch`), non-objects
  (`not_an_object`) and case variants of JSON-RPC member names such as
  `"Method"` or `"Name"` (`noncanonical`; some decoders match keys
  case-insensitively).
- `--manifest` without a certification refuses every call. Any gate flag
  without `--manifest`, a malformed `--revoked-statement`, an unreadable
  envelope, or a `CLOAKPIPE_RELEASE` naming another release refuse to start.
- `--revoked-key KEYID` revokes a signer. The manifest
also binds every evidence hop to its release. MCP server identity
(`spec.mcpServers`) is not checked: the gate fronts the one upstream it was
started with.

## Audit packs

Certifications, the runs they cite and their revocations travel to
reviewers inside a release audit pack ([AUDIT_PACK.md](AUDIT_PACK.md)); its
verifier checks every envelope with `statement::verify` and requires each
production promotion to be covered by a certification valid at that moment
(or a break-glass override).

## What a certification does not claim

A valid certification proves that a named issuer applied a named policy to
named evaluation runs of an exact release and reached the stated decision. It
does not prove the evaluators measured the right property, that the suites are
representative, or that the release is safe outside the certified scope and
validity window.
