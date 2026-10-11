# Changelog

All notable changes to CloakPipe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
CloakPipe is pre-1.0 and its formats carry `v1alpha1` versions, so minor releases
may contain breaking changes; these are marked **Breaking**.

## [Unreleased]

### Added

- **Agent Release manifests.** A new `cloakpipe-release` crate gives an AI agent
  release an exact, verifiable identity: an `AgentRelease` manifest that only
  accepts immutable references, a canonical hash (RFC 8785), a material-change
  diff that lists the assurance suites a change requires, and in-toto export.
  New commands: `cloakpipe release validate | hash | diff | inspect | register`.
  Ledger records and MCP interceptor hops can be bound to a release hash. Ships
  with a JSON schema, a Python reference implementation of the hash and
  `docs/AGENT_RELEASE.md`.
  ([#12](https://github.com/rohansx/cloakpipe/pull/12))
- **Certification.** A new `cloakpipe-cert` crate makes a deterministic
  certify/block decision for a release from its evaluation runs and a
  certification policy (coverage, pass rate, regressions, critical failures,
  metric thresholds), and signs the result as an in-toto statement in a DSSE
  envelope that verifies offline. New commands: `cloakpipe release keygen`,
  `release certify` (exit 0 only when certified) and `release verify-cert`.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- **Certification GitHub Action.** A reusable `certify` composite action
  (`.github/actions/certify`) lets CI block a release that fails its policy.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- **Evaluation import.** `cloakpipe eval import` turns existing test and eval
  results into evidence for certification: JUnit XML and native JSON
  ([#13](https://github.com/rohansx/cloakpipe/pull/13)), Braintrust experiments
  and Langfuse dataset runs with a configurable `--pass-threshold`
  ([#15](https://github.com/rohansx/cloakpipe/pull/15)). Malformed, duplicate or
  conflicting input is rejected rather than guessed.
- **Langfuse experiments import.** `cloakpipe eval import --langfuse-experiment
  FILE --langfuse-experiment-items FILE` reads the Langfuse experiments API,
  which replaces dataset runs, with cursor pagination, item-count and duplicate
  checks, and `tools/fetch_langfuse_experiment.sh` to download every page.
  ([#20](https://github.com/rohansx/cloakpipe/pull/20))
- **Two-way boundary certification.** A certification policy's optional
  `rules.boundary` stops a release passing authorization by refusing
  everything: cases labelled `expect: allow|deny` (JUnit property
  `cloakpipe.expect`, native JSON `expect`, Braintrust/Langfuse metadata
  `cloakpipe.expect`) are scored both ways per listed suite, and the release
  is blocked with `under_blocking`, `over_refusal` or `boundary_incomplete`.
  Policies and runs without these fields keep their hashes. See
  `docs/CERTIFICATION.md#two-way-boundary`.
- **MCP tool gate.** `cloakpipe mcp-proxy --manifest ... --certification ...`
  only forwards a `tools/call` when the tool is declared in the release manifest
  and the release's certification verifies at the moment of the call (trusted
  signer, not revoked, unexpired, right environment). Refused calls never reach
  the tool, return JSON-RPC error `-32001` and are recorded in the ledger;
  `--gate warn` forwards and flags instead. Input the gate cannot read is
  refused. ([#14](https://github.com/rohansx/cloakpipe/pull/14))
- **Transparent MCP interceptor.** `cloakpipe mcp-proxy --upstream "<cmd>"` sits
  between an agent and an MCP server, pseudonymizes PII in tool-call arguments
  and rehydrates tokens in tool results, so the tool never sees raw PII.
  ([27889ca](https://github.com/rohansx/cloakpipe/commit/27889ca))
- **Evidence ledger and standalone verifier.** A hash-chained, Ed25519-signed
  evidence ledger that never stores PII, the standalone `cloakpipe-verify` CLI,
  Merkle inclusion proofs, signed auditor manifests and the CloakLeak PII-leak
  benchmark. ([#8](https://github.com/rohansx/cloakpipe/pull/8)) The MCP server
  now records a no-PII ledger hop for each masking call when
  `CLOAKPIPE_LEDGER_DB` is set.
  ([9105613](https://github.com/rohansx/cloakpipe/commit/9105613))
- **Real external anchoring.** `cloakpipe anchor <bundle>` seals a ledger export
  and anchors it at an RFC 3161 timestamp authority and Sigstore Rekor.
  `cloakpipe-verify anchors|all --tsa-root ... --rekor-key ...` checks both fully
  offline and fails closed on missing trust inputs, back-dating and downgraded
  bundles. See `docs/ANCHORING.md`.
  ([#16](https://github.com/rohansx/cloakpipe/pull/16))
- **Release audit packs.** `cloakpipe release audit-pack` assembles one signed
  pack per release (manifest, eval runs, certification, governance events and
  the release-bound ledger slice), and `cloakpipe-verify release-pack` verifies
  it offline with separate trust lists per role. It also rejects a re-signed
  false history, such as a promotion before certification. See
  `docs/AUDIT_PACK.md`. ([#17](https://github.com/rohansx/cloakpipe/pull/17))
- **Anthropic Messages API in the proxy.** `/v1/messages` (and the
  `/v1/anthropic/messages` alias) pseudonymize requests to Anthropic and
  rehydrate responses, including streamed text deltas.
  ([#11](https://github.com/rohansx/cloakpipe/pull/11))
- **Nemotron-v2 PII NER backend**, opt-in alongside the existing backends.
  ([129fa8f](https://github.com/rohansx/cloakpipe/commit/129fa8f))
- **CloakPipe Cloud reporting.** A self-hosted proxy with a `[cloud]` config
  section sends heartbeats and no-PII request telemetry to CloakPipe Cloud.
  ([8d03fd4](https://github.com/rohansx/cloakpipe/commit/8d03fd4),
  [56059ea](https://github.com/rohansx/cloakpipe/commit/56059ea))
- `docker-compose.yml` for one-command self-hosting.
  ([f0fb7e4](https://github.com/rohansx/cloakpipe/commit/f0fb7e4))
- `SECURITY.md` with the vulnerability reporting process.
  ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Changed

- **Breaking:** format identifiers moved from the legacy `cloakpipe.dev`
  namespace to `cloakpipe.co` (for example `apiVersion: cloakpipe.co/v1alpha1`,
  hash and signing domains, in-toto predicate types and the schema `$id`).
  Writers now emit `cloakpipe.co/...`. Readers and verifiers still accept legacy
  `cloakpipe.dev/v1alpha1` objects, and every hash and signature issued before
  the move stays valid. Because the `apiVersion` and hash domain are part of the
  release hash, a manifest written in the new namespace has a different release
  hash than the same manifest in the legacy namespace; update any pinned hashes
  when you migrate a manifest. ([#19](https://github.com/rohansx/cloakpipe/pull/19))
- Evidence bundles are now v4: the signed manifest commits to the chain tip, so a
  substituted chain of the same length no longer verifies, and
  `cloakpipe-verify all --trust-key` pins the signer. v3 bundles still verify.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- README rewritten around Evaluate, Certify, Enforce, Prove, with every quick-start
  command verified against `main`; `CONTRIBUTING.md` refreshed.
  ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Deprecated

- Langfuse dataset-run import (`--langfuse-run` / `--langfuse-scores`). Langfuse
  removes those endpoints on Langfuse Cloud on 2026-11-16 (self-hosted: v4); use
  `--langfuse-experiment` instead. ([#20](https://github.com/rohansx/cloakpipe/pull/20))

### Removed

- README claims that could not be backed by the code: benchmark, latency and F1
  tables, the competitor comparison, Cloud pricing tiers, the crates.io and
  Docker Hub badges, and the list of `CLOAKPIPE_*` environment variables (most
  are not read by the CLI). ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Fixed

- Streaming rehydration no longer leaks pseudo-tokens that arrive split across
  SSE chunks, and a token at the very end of a stream is no longer dropped.
  Fixes [#3](https://github.com/rohansx/cloakpipe/issues/3).
  ([1e2ea69](https://github.com/rohansx/cloakpipe/commit/1e2ea69))

## [0.10.0] - 2026-06-04

### Added

- Multi-stage `Dockerfile` and a container config that listens on `0.0.0.0:8900`
  and stores state under `/data`. ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- Release workflow that publishes `ghcr.io/rohansx/cloakpipe` on each version
  tag. ([#7](https://github.com/rohansx/cloakpipe/pull/7))
- Ready-to-use compliance policy configs: `dpdp`, `gdpr`, `hipaa`, `pci-dss` and
  `minimal` (TOML). ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- `Cargo.lock` is committed for reproducible builds.
  ([#5](https://github.com/rohansx/cloakpipe/pull/5))

### Fixed

- Python SDK health check uses the proxy's real `/health` route and default port
  `8900`. ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- Documentation now matches the binary: real CLI subcommands, a working
  build-from-source quick start, the default `127.0.0.1:8900` listen address,
  and the MIT license (previously misstated as Apache-2.0).
  ([#4](https://github.com/rohansx/cloakpipe/pull/4))
- CI is green again (clippy fixes).
  ([#5](https://github.com/rohansx/cloakpipe/pull/5),
  [#6](https://github.com/rohansx/cloakpipe/pull/6))

## [0.9.0] - 2026-03-30

### Added

- DistilBERT-PII NER backend (33 entity types, runs on any CPU).
- nvidia/gliner-PII sidecar support.
- Expanded regex detection patterns.

## [0.8.0] - 2026-03-23

### Added

- Format-preserving pseudonymization: phone numbers, emails, Aadhaar and PAN are
  replaced with fakes of the same format.
- Response scanning: LLM responses are scanned for PII leakage and redacted.
- `cloakpipe scan` to check files and directories for PII before indexing them
  into a vector database.
- LangChain and LlamaIndex packages with drop-in `ChatCloakPipe` and
  `CloakPipeLLM` wrappers.
- Batch detect API in CloakPipe Cloud (`POST /api/detect/batch`, up to 100 texts).
- Compliance policy files for DPDP 2023, GDPR, HIPAA and PCI-DSS.

## [0.7.0] - 2026-03-11

### Added

- Context-aware pseudonymization: session tracking with coreference resolution
  (pronouns, abbreviations, possessives), sensitivity escalation across
  sessions, CLI session commands and an MCP `session_context` tool.
- GLiNER zero-shot NER backend (`backend = "gliner"`): define entity types in
  plain English, no training, pure ONNX Runtime.
- Detection for SSN, Aadhaar, PAN, IPv4, general URLs, natural-language dates,
  `sk-proj`/`sk-live`/`github_pat` secrets and INR/USD/EUR amounts.
- PII benchmark harness (`cargo run -p cloakpipe-core --example pii_benchmark`).
- Admin dashboard with privacy chat, detection feed and compliance views.

### Fixed

- The phone-number pattern no longer matches IP addresses, years or port numbers.

## [0.6.0] - 2026-03-09

### Added

- Fuzzy entity resolution (Jaro-Winkler similarity, prefix matching and
  user-defined alias groups), gated by category so a person and a place with the
  same name are never merged. Works inside the vault with no changes to the
  detection pipeline.

## [0.5.0] - 2026-03-09

### Added

- Industry profiles (`general`, `legal`, `healthcare`, `fintech`) with pre-tuned
  detection settings.
- MCP server with `pseudonymize`, `rehydrate`, `detect`, `vault_stats` and
  `configure` tools.

## [0.4.0] - 2026-03-06

### Added

- ADCPE vector encryption: an orthogonal transform for embedding vectors that
  preserves cosine similarity, with encrypt/decrypt CLI commands.

## [0.3.0] - 2026-03-06

### Added

- SQLite vault and audit backends with per-value AES-256-GCM encryption.
- ONNX BERT-based NER behind the `ner` feature flag.
- Multi-user token scoping.

## [0.2.0] - 2026-03-06

### Added

- CloakTree: vectorless, LLM-driven retrieval for structured documents (PDF and
  Markdown), with parser, tree indexer, search and CLI subcommands.

## [0.1.0] - 2026-03-06

### Added

- First release: privacy middleware for LLM and RAG pipelines.

[Unreleased]: https://github.com/rohansx/cloakpipe/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/rohansx/cloakpipe/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/rohansx/cloakpipe/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/rohansx/cloakpipe/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/rohansx/cloakpipe/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/rohansx/cloakpipe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rohansx/cloakpipe/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rohansx/cloakpipe/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rohansx/cloakpipe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rohansx/cloakpipe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rohansx/cloakpipe/releases/tag/v0.1.0
