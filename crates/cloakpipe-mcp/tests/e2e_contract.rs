//! The interceptor enforces tool contracts on the raw (pre-masking)
//! arguments: a call that breaks its contract never reaches the tool, the
//! agent gets a JSON-RPC error naming the reason and contract path, and the
//! refusal is no-PII evidence (`gate_denial`, `gate_path`).

use cloakpipe_cert::statement::{sign, statement, Certification, TrustedKey, VerifyContext};
use cloakpipe_core::{config::DetectionConfig, detector::Detector, vault::Vault};
use cloakpipe_ledger::{record::LedgerRecord, ActionKind, LedgerStore, MetadataValue};
use cloakpipe_mcp::{run_proxy_io, stable_ids, GateMode, ProxyContext, ToolGate};
use cloakpipe_release::contract::ToolContract;
use cloakpipe_release::{parse_path, AgentRelease, ArtifactRef, Format};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn messages(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }
}

/// A fake tool that records every line and answers each with an empty result.
fn fake_upstream(dir: &Path) -> (Vec<String>, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  id=$(printf '%s' "$line" | sed 's/^{{"id":\([0-9]*\),.*$/\1/')
  printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[]}}}}\n' "$id"
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (vec!["sh".into(), script.to_string_lossy().into_owned()], received)
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
}

/// The example contract with approval and operation tracking (items 2 and 3)
/// switched off, plus `edits`.
fn contract(edits: &[(&str, &str)]) -> ToolContract {
    let mut src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
        .unwrap()
        .replace("sideEffect: true", "sideEffect: false")
        .replace("requiresApproval: true", "requiresApproval: false");
    for (from, to) in edits {
        src = src.replace(from, to);
    }
    ToolContract::parse_str(&src, Format::Yaml).unwrap()
}

fn release_binding(c: &ToolContract) -> AgentRelease {
    let mut m = parse_path(&example("release.yaml")).unwrap();
    m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
    m.spec.policies.push(ArtifactRef { reference: c.policy_ref() });
    m
}

fn task() -> Value {
    serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap()
}

fn certified(m: &AgentRelease) -> ToolGate {
    let release = m.manifest_hash().to_string();
    let now = chrono::Utc::now();
    let c: Certification = serde_json::from_value(json!({
        "id": "cert-contract",
        "release": release,
        "environment": "production",
        "decision": {
            "outcome": "certified", "release": release,
            "policy": {"name": "p", "version": "1", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": [], "runs": [{"runId": "r", "suite": "s", "hash": format!("sha256:{}", "11".repeat(32))}],
            "baselineRuns": [], "summaries": [], "reasons": []
        },
        "issuedAt": (now - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "validUntil": (now + chrono::Duration::days(30)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "issuer": "test"
    }))
    .unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let trust = VerifyContext {
        trusted: vec![TrustedKey { keyid: "k1".into(), public_key: key.verifying_key().to_bytes() }],
        ..Default::default()
    };
    ToolGate::new(GateMode::Enforce, m, "production", Some(sign(&statement(&c), &key, "k1")), trust)
}

fn gate(c: ToolContract, task: Option<Value>) -> ToolGate {
    certified(&release_binding(&c)).with_contracts(vec![c], task).unwrap()
}

fn call(id: u64, tool: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
}

fn args() -> Value {
    json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified", "note": "called back"}})
}

struct Run {
    messages: Vec<Value>,
    seen: String,
    records: Vec<LedgerRecord>,
}

fn run(gate: ToolGate, lines: &[String]) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = fake_upstream(dir.path());
    let ledger_db = dir.path().join("ledger.db");
    let ctx = ProxyContext {
        detector: Detector::from_config(&serde_json::from_str::<DetectionConfig>("{}").unwrap()).unwrap(),
        vault: Vault::ephemeral(),
        ledger_db: Some(ledger_db.to_string_lossy().into_owned()),
        release: Some(gate.release_bytes()),
        gate: Some(gate),
    };
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(upstream, ctx, input, out.clone()).unwrap();
    let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
    Run {
        messages: out.messages(),
        seen: std::fs::read_to_string(&received).unwrap_or_default(),
        records: store.records_for_tenant(&stable_ids().0).unwrap().into_iter().map(|r| r.record).collect(),
    }
}

fn blocks(r: &Run) -> Vec<&LedgerRecord> {
    r.records.iter().filter(|r| r.actions.iter().any(|a| a.kind == ActionKind::Block)).collect()
}

/// The refusal for request `id`, asserting the call never reached the tool
/// and the refusal was recorded as `(gate_denial, gate_path)`.
fn refused(r: &Run, id: u64, code: &str, path: Option<&str>) {
    assert!(!r.seen.contains("crm.patch"), "{code}: the refused call reached the tool: {}", r.seen);
    let refusal = r.messages.iter().find(|m| m["id"] == id).expect("the agent gets an answer");
    assert_eq!(refusal["error"]["code"], -32001, "{refusal}");
    assert_eq!(refusal["error"]["data"]["reason"], code, "{refusal}");
    assert_eq!(refusal["error"]["data"].get("path").and_then(Value::as_str), path, "{refusal}");
    let b = blocks(r);
    assert_eq!(b.len(), 1, "{:?}", r.records);
    assert_eq!(b[0].metadata.get("gate_denial"), Some(&MetadataValue::OpaqueId(code.into())));
    assert_eq!(b[0].metadata.get("gate_path"), path.map(|p| MetadataValue::OpaqueId(p.into())).as_ref());
}

/// No raw argument value appears in the ledger.
fn no_values_in_ledger(r: &Run, values: &[&str]) {
    let dump = format!("{:?}", r.records);
    for v in values {
        assert!(!dump.contains(v), "{v} leaked into the ledger: {dump}");
    }
}

#[test]
fn a_conforming_call_reaches_the_tool() {
    let r = run(gate(contract(&[]), Some(task())), &[call(1, "crm.patch", args())]);
    assert!(r.seen.contains("crm.patch") && r.seen.contains("qualified"), "{}", r.seen);
    assert!(r.messages.iter().any(|m| m["id"] == 1 && m.get("result").is_some()), "{:?}", r.messages);
    assert!(blocks(&r).is_empty(), "{:?}", r.records);
}

#[test]
fn the_contract_sees_raw_arguments_before_masking() {
    // The task binds the tenant to an email; masking replaces it with a
    // token before the tool sees it, but the gate compares the raw value.
    let mut t = task();
    t["tenant"] = json!("ops@demo-co.example");
    let mut a = args();
    a["tenant"] = json!("ops@demo-co.example");
    let r = run(gate(contract(&[]), Some(t)), &[call(1, "crm.patch", a)]);
    assert!(r.seen.contains("crm.patch"), "allowed: {}", r.seen);
    assert!(!r.seen.contains("ops@demo-co.example"), "masked before the tool: {}", r.seen);
}

#[test]
fn a_cross_tenant_call_is_a_scope_mismatch() {
    let mut a = args();
    a["tenant"] = json!("rival-co");
    // `_meta` is agent-controlled: it cannot change the trusted task context.
    let line = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "crm.patch", "arguments": a,
        "_meta": {"cloakpipe": {"task": {"tenant": "rival-co"}}, "tenant": "rival-co"}
    }})
    .to_string();
    let r = run(gate(contract(&[]), Some(task())), &[line]);
    refused(&r, 2, "scope_mismatch", Some("/tenant"));
    no_values_in_ledger(&r, &["rival-co", "demo-co", "lead-42"]);
}

#[test]
fn an_unknown_argument_is_refused_without_naming_it() {
    let mut a = args();
    a["owner_override"] = json!("mallory");
    let r = run(gate(contract(&[]), Some(task())), &[call(3, "crm.patch", a)]);
    refused(&r, 3, "argument_not_allowed", None);
    let refusal = r.messages.iter().find(|m| m["id"] == 3).unwrap().to_string();
    assert!(!refusal.contains("owner_override") && !refusal.contains("mallory"), "{refusal}");
    no_values_in_ledger(&r, &["owner_override", "mallory"]);
}

#[test]
fn an_invalid_enum_value_is_refused_with_its_contract_path() {
    let mut a = args();
    a["patch"]["stage"] = json!("closed-won");
    let r = run(gate(contract(&[]), Some(task())), &[call(4, "crm.patch", a)]);
    refused(&r, 4, "argument_invalid", Some("/patch/stage"));
    no_values_in_ledger(&r, &["closed-won"]);
}

#[test]
fn a_missing_task_context_is_refused() {
    let r = run(gate(contract(&[]), None), &[call(5, "crm.patch", args())]);
    refused(&r, 5, "task_context_missing", Some("/record"));
}

#[test]
fn a_contract_path_the_ledger_would_reject_still_records_the_denial() {
    // `/company` contains `pan`, a PII marker for the ledger's opaque-id
    // check; the hop is still recorded, without the path.
    let c = contract(&[("note:  { type: string, maxLength: 280 }", "company: { type: string, maxLength: 3 }")]);
    let mut a = args();
    a["patch"] = json!({"company": "acme"});
    let r = run(gate(c, Some(task())), &[call(6, "crm.patch", a)]);
    assert!(!r.seen.contains("crm.patch"));
    let b = blocks(&r);
    assert_eq!(b.len(), 1, "the denial is evidence: {:?}", r.records);
    assert_eq!(b[0].metadata.get("gate_denial"), Some(&MetadataValue::OpaqueId("argument_invalid".into())));
    assert!(!b[0].metadata.contains_key("gate_path"));
}

#[test]
fn warn_mode_forwards_and_records_the_contract_violation() {
    let c = contract(&[]);
    let m = release_binding(&c);
    let mut g = certified(&m).with_contracts(vec![c], Some(task())).unwrap();
    g.mode = GateMode::Warn;
    let mut a = args();
    a["patch"]["stage"] = json!("closed-won");
    let r = run(g, &[call(7, "crm.patch", a)]);
    assert!(r.seen.contains("crm.patch"), "warn mode forwards: {}", r.seen);
    let flagged: Vec<_> = r.records.iter().filter(|x| x.metadata.contains_key("gate_violation")).collect();
    assert_eq!(flagged.len(), 1, "{:?}", r.records);
    assert_eq!(flagged[0].metadata.get("gate_violation"), Some(&MetadataValue::OpaqueId("argument_invalid".into())));
    assert_eq!(flagged[0].metadata.get("gate_path"), Some(&MetadataValue::OpaqueId("/patch/stage".into())));
}

#[test]
fn a_contract_digest_not_in_the_release_refuses_to_start() {
    // The release binds the example contract; the operator supplies an edited
    // copy. The gate is never built, so the interceptor never starts.
    let bound = contract(&[]);
    let edited = contract(&[("maxLength: 280", "maxLength: 100000")]);
    let m = release_binding(&bound);
    let err = certified(&m).with_contracts(vec![edited.clone()], Some(task())).err().expect("refused");
    assert!(err.to_string().contains(&edited.policy_ref()), "{err}");
}
