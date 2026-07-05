# CloakPipe — Implementation Plan (v2)

## Guiding Principles

1. **Ship the proxy first, CloakTree second.** The proxy + regex detection is the foundation everything else builds on.
2. **CloakTree is the differentiator.** Get it to v0.2 quickly — no competitor has vectorless privacy-first retrieval.
3. **Vault correctness is non-negotiable.** Encryption, consistency, and memory safety right in v0.1.
4. **Feature-gate aggressively.** Default build = regex + vault + proxy. Everything else is opt-in.
5. **Don't attempt TEE, ADCPE, and bijection simultaneously.** Each is a deep project.

---

## What Changed from V1 Plan

| V1 Phase | V2 Phase | Change |
|----------|----------|--------|
| v0.1: Foundation (weeks 1-3) | v0.1: Foundation (weeks 1-3) | Unchanged |
| v0.2: RAG Pipeline (weeks 4-6) | v0.2: **CloakTree** (weeks 4-7) | Swapped — CloakTree is the headline feature |
| v0.3: NER (weeks 7-10) | v0.3: CloakVector + Streaming (weeks 8-10) | V1's v0.2 scope moved here |
| v0.4: Hardening (weeks 11-14) | v0.4: NER + ADCPE (weeks 11-14) | Added vector encryption |
| v0.5: Ecosystem (weeks 15-20) | v0.5: Local-First + TEE (weeks 15-20) | New scope entirely |

**Rationale**: CloakTree is the unique differentiator. Shipping it in v0.2 means we have something no competitor offers by week 7. CloakVector (the v1 pipeline) is still important but becomes v0.3.

---

## Phase 1: Foundation (v0.1) — Weeks 1-3

**Goal**: Working proxy that anonymizes and rehydrates non-streaming chat completions and embeddings using regex detection.

*Unchanged from v1 plan. This is the foundation for everything.*

### Week 1: Core Engine

| Task | Crate | Priority |
|------|-------|----------|
| Set up Cargo workspace (8 crates, most empty initially) | root | P0 |
| Implement regex detection patterns (secrets, emails, IPs, URLs) | core | P0 |
| Implement financial detection (amounts, percentages, fiscal dates) | core | P0 |
| Implement custom TOML rule parser | core | P0 |
| Implement `DetectedEntity` struct and conflict resolution | core | P0 |
| Unit tests + snapshot tests (insta) per detection layer | core | P0 |

### Week 2: Vault + Replacer + Rehydrator

| Task | Crate | Priority |
|------|-------|----------|
| Vault: in-memory store with `Zeroizing` wrappers | core | P0 |
| Vault: AES-256-GCM encryption/decryption | core | P0 |
| Vault: Argon2id key derivation | core | P0 |
| Vault: `get_or_create` with sequential pseudonym generation | core | P0 |
| Vault: `resolve` for reverse lookup | core | P0 |
| Replacer: text + entities + vault → anonymized text | core | P0 |
| Rehydrator: anonymized text + vault → original text | core | P0 |
| Property tests: `rehydrate(replace(text)) == text` | core | P0 |
| Atomic file write for vault persistence | core | P0 |
| OS keyring integration via `keyring` crate | core | P1 |

### Week 3: HTTP Proxy + CLI

| Task | Crate | Priority |
|------|-------|----------|
| axum server with routing | proxy | P0 |
| `/v1/chat/completions` handler (non-streaming) | proxy | P0 |
| `/v1/embeddings` handler | proxy | P0 |
| Passthrough for unknown endpoints | proxy | P0 |
| Request body parsing (extract message content) | proxy | P0 |
| Upstream forwarding with reqwest | proxy | P0 |
| Response rehydration (non-streaming) | proxy | P0 |
| API key passthrough from config/env | proxy | P0 |
| `/health` endpoint | proxy | P1 |
| TOML config loading with `mode` field | cli | P0 |
| `cloakpipe start` command | cli | P0 |
| `cloakpipe init` (generate default config) | cli | P1 |
| `cloakpipe test "sample text"` command | cli | P1 |
| Integration tests with wiremock upstream | proxy | P0 |
| E2E test: OpenAI Python SDK → CloakPipe → mock | proxy | P0 |

### v0.1 Release Criteria

- [ ] `cargo install cloakpipe` works
- [ ] OpenAI SDK works with CloakPipe as `base_url` (chat + embeddings)
- [ ] Regex detects: secrets, emails, IPs, URLs, amounts, percentages, dates
- [ ] Custom TOML rules work
- [ ] Vault is AES-256-GCM encrypted, survives restart
- [ ] `rehydrate(anonymize(text)) == text` passes property tests
- [ ] Memory zeroed on vault drop
- [ ] <5ms latency overhead (benchmarked)

---

## Phase 2: CloakTree (v0.2) — Weeks 4-7 [NEW]

**Goal**: Vectorless, reasoning-based retrieval for structured documents. The headline differentiator.

### Week 4: Document Parsing

| Task | Crate | Priority |
|------|-------|----------|
| PDF parser: extract text with page boundaries | tree | P0 |
| Structure extraction: detect headings, sections, tables | tree | P0 |
| DOCX parser: heading styles → sections | tree | P1 |
| HTML parser: DOM headings → sections | tree | P1 |
| Markdown parser: ATX headings → sections | tree | P1 |
| Tests with sample financial reports (PDF) | tree | P0 |

### Week 5: Tree Index Builder

| Task | Crate | Priority |
|------|-------|----------|
| Tree data structures (Node, Tree, Summary) | tree | P0 |
| Hierarchical tree builder from parsed sections | tree | P0 |
| Summary generation via external LLM (through proxy) | tree | P0 |
| Pseudonymize summaries before LLM sees them | tree | P0 |
| Local JSON tree persistence | tree | P0 |
| `cloakpipe tree build <document>` CLI command | cli | P0 |
| Tests with golden tree indices | tree | P0 |

### Week 6: LLM-Driven Tree Search

| Task | Crate | Priority |
|------|-------|----------|
| Tree search protocol: present tree to LLM, get node selection | tree | P0 |
| Multi-round navigation: drill into selected branches | tree | P0 |
| Full text extraction from selected nodes | tree | P0 |
| Pseudonymize extracted text before generation call | tree | P0 |
| Rehydrate generation response | tree | P0 |
| `cloakpipe tree search <query> --index <path>` CLI | cli | P0 |
| End-to-end test: build tree → search → generate → rehydrate | tree | P0 |

### Week 7: Integration + Polish

| Task | Crate | Priority |
|------|-------|----------|
| `/v1/tree/build` HTTP endpoint | proxy | P0 |
| `/v1/tree/search` HTTP endpoint | proxy | P0 |
| `/v1/tree/list` HTTP endpoint | proxy | P1 |
| Mode routing: `mode = "cloaktree"` dispatches to tree pipeline | proxy | P0 |
| Option: no-summary mode (titles + page ranges only, no LLM for indexing) | tree | P1 |
| Integration tests: full CloakTree flow via HTTP | proxy | P0 |
| Benchmark: tree search latency on real financial reports | tree | P0 |

### v0.2 Release Criteria

- [ ] `cloakpipe tree build report.pdf` produces valid tree index
- [ ] `cloakpipe tree search "What was EBITDA?"` returns correct sections
- [ ] Tree summaries are pseudonymized before LLM sees them
- [ ] Full generation flow: tree search → extract → pseudonymize → generate → rehydrate
- [ ] Only 1 external API call (generation) with pseudonymized text
- [ ] Published to crates.io with `tree` feature flag

---

## Phase 3: CloakVector + Streaming (v0.3) — Weeks 8-10

**Goal**: Full vector RAG pipeline support with SSE streaming rehydration.

### Week 8: Streaming Rehydration

| Task | Crate | Priority |
|------|-------|----------|
| SSE parser for upstream responses | proxy | P0 |
| Token buffer state machine for streaming rehydration | core | P0 |
| Handle `stream: true` in chat completions | proxy | P0 |
| Edge case: pseudonym split across SSE chunks | core | P0 |
| Edge case: `[DONE]` triggers buffer flush | proxy | P0 |
| Buffer timeout (50ms) for non-matching patterns | core | P1 |
| Integration tests: streaming with wiremock SSE | proxy | P0 |

### Week 9: Multi-Turn + Batch + Audit

| Task | Crate | Priority |
|------|-------|----------|
| Multi-turn: anonymize all messages in conversation | proxy | P0 |
| Batch embedding support (array of strings in `input`) | proxy | P0 |
| JSONL audit logger (entity counts, latencies, no values) | audit | P0 |
| `cloakpipe audit summary --last 7d` | cli | P1 |
| `cloakpipe vault inspect` (stats only) | cli | P1 |

### Week 10: Hardening

| Task | Crate | Priority |
|------|-------|----------|
| `preserve` and `force` override lists in detection | core | P0 |
| Fail-open vs fail-closed configuration | proxy | P0 |
| Connection pooling for upstream requests | proxy | P0 |
| Graceful shutdown (drain connections, flush vault) | proxy | P0 |
| CI: GitHub Actions (test, clippy, fmt, build, release) | root | P0 |
| Cross-compilation: Linux/macOS amd64/arm64 | root | P1 |

### v0.3 Release Criteria

- [ ] SSE streaming works with LangChain and LlamaIndex
- [ ] Multi-turn conversations use consistent pseudonyms
- [ ] Batch embeddings anonymized correctly
- [ ] Audit logs in JSONL, no sensitive values
- [ ] GitHub repo public, CI green
- [ ] 100+ stars target

---

## Phase 4: NER + ADCPE (v0.4) — Weeks 11-14

**Goal**: ML-based entity detection and vector-level encryption.

### Weeks 11-12: NER

| Task | Crate | Priority |
|------|-------|----------|
| `ner` feature flag | core | P0 |
| ONNX model loading via `ort` | core | P0 |
| BERT tokenization via `tokenizers` | core | P0 |
| NER inference pipeline (tokenize → infer → decode BIO tags) | core | P0 |
| Confidence threshold filtering | core | P0 |
| Text chunking for >512 tokens | core | P1 |
| `spawn_blocking` integration in proxy | proxy | P0 |
| Graceful degradation: model missing → regex-only | core | P0 |
| `cloakpipe model download` | cli | P1 |

### Weeks 13-14: ADCPE Vector Encryption

| Task | Crate | Priority |
|------|-------|----------|
| ADCPE key generation (symmetric, 256-bit) | vector | P0 |
| `encrypt_vector(vec, key)` implementation | vector | P0 |
| `encrypt_query(vec, key)` implementation | vector | P0 |
| Property tests: `cosine_sim(enc(a), enc(b)) ≈ cosine_sim(a, b)` | vector | P0 |
| Security tests: encrypted vectors resist naive inversion | vector | P0 |
| Hook into `/v1/embeddings` handler: encrypt before returning | proxy | P0 |
| Tunable accuracy/privacy parameter in config | vector | P0 |
| Docker image (multi-stage, scratch base) | root | P1 |
| Homebrew formula | root | P1 |
| Multi-vault / multi-tenant support | core | P0 |
| Vault key rotation | core | P0 |

### v0.4 Release Criteria

- [ ] NER detects persons, organizations, locations via ONNX
- [ ] ADCPE encrypts embeddings, similarity search still works
- [ ] Docker image available
- [ ] Multi-vault support for tenant isolation
- [ ] First enterprise pilot inquiry

---

## Phase 5: Local-First + TEE (v0.5) — Weeks 15-20

**Goal**: Complete air-gap mode and hardware-isolated deployment.

### Weeks 15-17: Local-First Mode

| Task | Crate | Priority |
|------|-------|----------|
| candle-rs local embedding models (BGE, nomic-embed) | local | P0 |
| LanceDB integration for local vector storage | local | P0 |
| Local tree generation (candle model for summaries) | local/tree | P1 |
| Optional local LLM inference (candle or llama.cpp) | local | P2 |
| `cloakpipe start --mode local` | cli | P0 |

### Weeks 18-20: TEE + Ecosystem

| Task | Crate | Priority |
|------|-------|----------|
| AWS Nitro Enclave: VSOCK server | tee | P1 |
| Cryptographic attestation with KMS | tee | P1 |
| Enclave build pipeline (Docker → EIF image) | tee | P1 |
| MCP server implementation | proxy | P0 |
| tree-sitter code-aware detection | core | P2 |
| WASM compilation of core crate | core | P2 |
| Policy templates: healthcare, finance, legal | policies | P1 |
| Documentation site (mdbook) | root | P0 |
| LangChain + LlamaIndex integration guides | docs | P0 |

### v0.5 Release Criteria

- [ ] `cloakpipe start --mode local` works with zero external APIs
- [ ] MCP server shipped
- [ ] Documentation site live
- [ ] 500+ GitHub stars target

---

## Deferred (Post v0.5)

These are real capabilities but should not distract from v0.1-v0.5:

| Feature | Reason to Defer |
|---------|----------------|
| Token bijection (AlienLM) | Requires fine-tuning API, niche audience |
| Vision-based CloakTree | Depends on multimodal model capabilities |
| Browser extension (Chrome / Manifest V3) — endpoint DLP | **Companion surface, not core.** Closes the "employee pastes into chatgpt.com" gap the proxy can't reach (DOM/textarea layer). **v1:** detect + mask + warn/block on major LLM sites, log to Audit (detection via cloud API). **v2:** reversible in-page restore via Vault + policy pull + optional local WASM detection for offline. Lead-gen + endpoint-DLP; only valuable if it feeds the same Policy/Audit. See cloud `docs/ROADMAP.md → Browser Extension`. |
| Compliance reports (SOC 2, HIPAA, GDPR) | Enterprise sales feature, not dev adoption |
| Intel TDX / NVIDIA Confidential GPU | Nitro first, others later |
| Covariant obfuscation (AloePri) | Requires model weight access |
| Activation steering (PrivacyRestore) | Research-stage, requires model internals |

---

## Risk Register (v2)

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Streaming rehydration edge cases | High | High | Fuzz testing, configurable buffer, timeout flush |
| CloakTree: poor tree quality on unstructured docs | High | Medium | Clear documentation: CloakTree for structured docs only |
| CloakTree: search quality with weak local models | High | Medium | Default to external LLM; local is opt-in |
| ADCPE: incorrect crypto implementation | Medium | Critical | Use published reference implementation, get crypto review |
| Scope creep: 8 crates too ambitious | High | High | Feature-gate everything, ship core first |
| Vault corruption on crash | Medium | Critical | Atomic writes, write-ahead intent log |
| PageIndex license/IP issues | Low | High | Verify MIT/Apache license, CloakTree is inspired-by not fork |
| Dataiku ships production code before us | Medium | Medium | CloakTree is unique — Dataiku won't have vectorless mode |

---

## Build Order (v2)

```
PHASE 1 (v0.1):
 1. cloakpipe-core/src/detector/patterns.rs     ← START HERE
 2. cloakpipe-core/src/detector/financial.rs
 3. cloakpipe-core/src/detector/custom.rs
 4. cloakpipe-core/src/detector/mod.rs
 5. cloakpipe-core/src/vault.rs                  ← CRITICAL PATH
 6. cloakpipe-core/src/replacer.rs
 7. cloakpipe-core/src/rehydrator.rs
 8. cloakpipe-core/src/lib.rs
 9. cloakpipe-proxy/src/server.rs
10. cloakpipe-proxy/src/middleware.rs
11. cloakpipe-proxy/src/routing.rs
12. cloakpipe-cli/src/config.rs
13. cloakpipe-cli/src/commands.rs
14. cloakpipe-cli/src/main.rs

PHASE 2 (v0.2 — CloakTree):
15. cloakpipe-tree/src/parser.rs                 ← PDF FIRST
16. cloakpipe-tree/src/tree.rs
17. cloakpipe-tree/src/indexer.rs
18. cloakpipe-tree/src/search.rs
19. cloakpipe-tree/src/extractor.rs
20. cloakpipe-tree/src/storage.rs

PHASE 3 (v0.3):
21. cloakpipe-proxy/src/streaming.rs
22. cloakpipe-audit/src/logger.rs

PHASE 4 (v0.4):
23. cloakpipe-core/src/detector/ner.rs
24. cloakpipe-vector/src/adcpe.rs
25. cloakpipe-vector/src/encrypt.rs
26. cloakpipe-vector/src/search.rs

PHASE 5 (v0.5):
27. cloakpipe-local/src/embeddings.rs
28. cloakpipe-local/src/lancedb.rs
29. cloakpipe-tee/src/nitro.rs
30. cloakpipe-tee/src/attestation.rs
```

---

## Success Metrics (v2)

| Milestone | When | Target |
|-----------|------|--------|
| v0.1 ships | Week 3 | Works with OpenAI SDK, <5ms overhead |
| v0.2 ships | Week 7 | CloakTree works on financial PDFs — **no competitor has this** |
| v0.3 ships | Week 10 | Streaming works, GitHub public, 100+ stars |
| v0.4 ships | Week 14 | NER + ADCPE, Docker image, first enterprise interest |
| v0.5 ships | Week 20 | Local mode, MCP server, 500+ stars |
