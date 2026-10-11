//! Operation identity and outcome states in the interceptor: a contract tool
//! with `sideEffect: true` runs through the operations store, so a call whose
//! outcome is unknown is never silently re-executed (docs/ACTION_BOUNDARY.md).

use cloakpipe_cert::statement::{sign, statement, Certification, TrustedKey, VerifyContext};
use cloakpipe_core::{config::DetectionConfig, detector::Detector, vault::Vault};
use cloakpipe_ledger::{record::LedgerRecord, Hop, LedgerStore, MetadataValue};
use cloakpipe_mcp::operations::{OperationState, OperationStore};
use cloakpipe_mcp::{reconcile_operation, run_proxy_io, stable_ids, GateMode, ProxyContext, ToolGate};
use cloakpipe_release::action::{derive_operation_id, fingerprint};
use cloakpipe_release::contract::ToolContract;
use cloakpipe_release::{parse_path, AgentRelease, ArtifactRef, Format};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{Cursor, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

/// How the fake tool behaves. Every call it receives is "committed" by
/// appending one line to `effects.jsonl` before it answers (or not).
#[derive(Clone, Copy)]
enum Tool {
    /// Answers each call with a result echoing the (masked) tenant.
    Ok,
    /// Commits the first call, then exits without replying (lost ack).
    LoseAck,
    /// Answers the first call with `isError: true`, later ones with a result.
    FailOnce,
}

fn fake_tool(dir: &Path, tool: Tool) -> Vec<String> {
    let effects = dir.join("effects.jsonl");
    let script = dir.join(format!("tool-{}.sh", uuid::Uuid::new_v4()));
    let reply = match tool {
        Tool::Ok => r#"printf '{"id":%s,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"patched %s"}]}}\n' "$id" "$tenant""#.to_string(),
        Tool::LoseAck => "exit 0".to_string(),
        Tool::FailOnce => format!(
            r#"if [ "$(wc -l < '{effects}')" -le 1 ]; then
    printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"conflict"}}],"isError":true}}}}\n' "$id"
  else
    printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"patched"}}]}}}}\n' "$id"
  fi"#,
            effects = effects.display()
        ),
    };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{effects}'
  id=$(printf '%s' "$line" | sed 's/^{{"id":\([0-9]*\),.*$/\1/')
  tenant=$(printf '%s' "$line" | sed 's/.*"tenant":"\([^"]*\)".*/\1/')
  {reply}
done
"#,
            effects = effects.display()
        ),
    )
    .unwrap();
    vec!["sh".into(), script.to_string_lossy().into_owned()]
}

fn effects(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("effects.jsonl")).map(|s| s.lines().count()).unwrap_or(0)
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
}

/// The example contract with operation tracking on and approval as given.
fn contract(approval: bool) -> ToolContract {
    let src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
        .unwrap()
        .replace("requiresApproval: true", &format!("requiresApproval: {approval}"));
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
        "id": "cert-ops",
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

/// A gate for the side-effect contract (no approval) over the operations
/// database in `dir`.
fn gate(dir: &Path, t: Value) -> ToolGate {
    let c = contract(false);
    certified(&release_binding(&c))
        .with_contracts(vec![c], Some(t))
        .unwrap()
        .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
        .unwrap()
}

fn call(id: u64, arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "crm.patch", "arguments": arguments}}).to_string()
}

fn args() -> Value {
    json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified", "note": "called back"}})
}

fn op_id(arguments: &Value) -> String {
    let m = release_binding(&contract(false));
    derive_operation_id("t-981", &fingerprint(&m.manifest_hash(), "crm.patch", arguments))
}

fn ctx(gate: ToolGate, ledger_db: &Path) -> ProxyContext {
    ProxyContext {
        detector: Detector::from_config(&serde_json::from_str::<DetectionConfig>("{}").unwrap()).unwrap(),
        vault: Vault::ephemeral(),
        ledger_db: Some(ledger_db.to_string_lossy().into_owned()),
        release: Some(gate.release_bytes()),
        gate: Some(gate),
    }
}

fn ledger(ledger_db: &Path) -> Vec<LedgerRecord> {
    let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
    store.records_for_tenant(&stable_ids().0).unwrap().into_iter().map(|r| r.record).collect()
}

/// Run the interceptor over `lines` (all sent at once).
fn run(dir: &Path, tool: Tool, gate: ToolGate, lines: &[String]) -> Vec<Value> {
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(fake_tool(dir, tool), ctx(gate, &dir.join("ledger.db")), input, out.clone()).unwrap();
    out.messages()
}

/// Run the interceptor, sending each line only after the previous request
/// has been answered (so a retry follows its first attempt's reply).
fn run_in_turn(dir: &Path, tool: Tool, gate: ToolGate, lines: &[String]) -> Vec<Value> {
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let upstream = fake_tool(dir, tool);
    let context = ctx(gate, &dir.join("ledger.db"));
    let writer = out.clone();
    let reader = proxy_side.try_clone().unwrap();
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    for (i, line) in lines.iter().enumerate() {
        agent.write_all(format!("{line}\n").as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while out.messages().len() <= i {
            assert!(Instant::now() < deadline, "no answer to {line}: {:?}", out.messages());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    handle.join().unwrap();
    let mut rest = Vec::new();
    let _ = agent.read_to_end(&mut rest);
    out.messages()
}

fn answer(msgs: &[Value], id: u64) -> &Value {
    msgs.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("no answer for {id}: {msgs:?}"))
}

fn state(dir: &Path, op: &str) -> OperationState {
    OperationStore::open(dir.join("ops.db")).unwrap().get(op).unwrap().expect("row").state
}

fn meta<'a>(r: &'a LedgerRecord, key: &str) -> Option<&'a str> {
    match r.metadata.get(key) {
        Some(MetadataValue::OpaqueId(s)) => Some(s),
        _ => None,
    }
}

#[test]
fn a_lost_acknowledgment_is_unknown_until_reconciled_and_never_re_executed() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(&args());

    // 1. The tool commits the effect, then dies without replying.
    let msgs = run(dir.path(), Tool::LoseAck, gate(dir.path(), task()), &[call(1, &args())]);
    assert_eq!(effects(dir.path()), 1);
    assert_eq!(state(dir.path(), &op), OperationState::Unknown);
    let a = answer(&msgs, 1);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "operation_unknown", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");

    // 2. A retry is refused until an operator reconciles the operation.
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(2, &args())]);
    let a = answer(&msgs, 2);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "reconcile_before_retry", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");
    assert_eq!(effects(dir.path()), 1, "the retry never reached the tool");

    // 3. The operator checks the CRM: the patch did land.
    let ledger_db = dir.path().join("ledger.db");
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    let release = gate(dir.path(), task()).release_bytes();
    reconcile_operation(&mut store, &op, OperationState::Done, ledger_db.to_str(), Some(release)).unwrap();
    drop(store);
    assert_eq!(state(dir.path(), &op), OperationState::Done);

    // 4. The retry replays instead of running the effect again.
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(3, &args())]);
    let a = answer(&msgs, 3);
    assert!(a.get("error").is_none(), "{a}");
    assert_eq!(a["result"]["_meta"]["cloakpipe"]["replayed"], true, "{a}");
    assert_eq!(effects(dir.path()), 1, "no second effect");

    // The ledger tells the story with ids and states only.
    let records = ledger(&ledger_db);
    let ops: Vec<(Hop, Option<&str>)> = records
        .iter()
        .filter(|r| meta(r, "operation_id") == Some(op.as_str()))
        .map(|r| (r.hop, meta(r, "operation_state").or(meta(r, "gate_denial"))))
        .collect();
    assert_eq!(
        ops,
        [
            (Hop::McpToolCall, None),
            (Hop::McpToolResult, Some("unknown")),
            (Hop::McpToolCall, Some("reconcile_before_retry")),
            (Hop::OperationReconciled, Some("done")),
            (Hop::McpToolResult, Some("done")),
        ],
        "{records:?}"
    );
    let replay = records.iter().rfind(|r| r.hop == Hop::McpToolResult).unwrap();
    assert_eq!(replay.metadata.get("operation_replayed"), Some(&MetadataValue::Bool(true)));
    assert!(records.iter().all(|r| r.release_hash() == Some(release)), "every hop is bound to the release");
    let dump = format!("{records:?}");
    for raw in ["demo-co", "lead-42", "qualified", "called back"] {
        assert!(!dump.contains(raw), "{raw} leaked: {dump}");
    }
}

#[test]
fn a_reconciled_not_applied_operation_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(&args());
    run(dir.path(), Tool::LoseAck, gate(dir.path(), task()), &[call(1, &args())]);
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    reconcile_operation(&mut store, &op, OperationState::NotApplied, None, None).unwrap();
    drop(store);
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(2, &args())]);
    assert!(answer(&msgs, 2).get("result").is_some(), "{msgs:?}");
    assert_eq!(effects(dir.path()), 2);
    assert_eq!(state(dir.path(), &op), OperationState::Done);
}

#[test]
fn a_done_operation_replays_its_stored_result_rehydrated() {
    let dir = tempfile::tempdir().unwrap();
    // The tenant is an email: masked before the tool, echoed back masked.
    let mut t = task();
    t["tenant"] = json!("ops@demo-co.example");
    let mut a = args();
    a["tenant"] = json!("ops@demo-co.example");
    let msgs = run_in_turn(dir.path(), Tool::Ok, gate(dir.path(), t), &[call(1, &a), call(2, &a)]);
    assert_eq!(effects(dir.path()), 1, "the retry was not forwarded");
    let first = answer(&msgs, 1);
    let replay = answer(&msgs, 2);
    assert_eq!(first["result"]["content"][0]["text"], "patched ops@demo-co.example", "{first}");
    assert_eq!(replay["result"]["content"], first["result"]["content"], "{replay}");
    assert_eq!(replay["result"]["_meta"]["cloakpipe"]["replayed"], true, "{replay}");
    assert!(first["result"].get("_meta").is_none(), "{first}");

    // The store holds the masked result only.
    let m = release_binding(&contract(false));
    let op = derive_operation_id("t-981", &fingerprint(&m.manifest_hash(), "crm.patch", &a));
    let row = OperationStore::open(dir.path().join("ops.db")).unwrap().get(&op).unwrap().unwrap();
    assert_eq!(row.state, OperationState::Done);
    let stored = row.result.unwrap();
    assert!(stored.contains("patched") && !stored.contains("ops@demo-co.example"), "{stored}");
}

#[test]
fn a_failed_operation_may_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(&args());
    let msgs = run_in_turn(dir.path(), Tool::FailOnce, gate(dir.path(), task()), &[call(1, &args()), call(2, &args())]);
    assert_eq!(answer(&msgs, 1)["result"]["isError"], true, "{msgs:?}");
    assert_eq!(answer(&msgs, 2)["result"]["content"][0]["text"], "patched", "{msgs:?}");
    assert_eq!(effects(dir.path()), 2, "the retry ran");
    assert_eq!(state(dir.path(), &op), OperationState::Done);
    let states: Vec<_> = ledger(&dir.path().join("ledger.db"))
        .iter()
        .filter(|r| r.hop == Hop::McpToolResult)
        .filter_map(|r| meta(r, "operation_state").map(str::to_string))
        .collect();
    assert_eq!(states, ["failed", "done"]);
}

#[test]
fn a_side_effect_notification_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let note = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "crm.patch", "arguments": args()}}).to_string();
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[note]);
    assert!(msgs.is_empty(), "a notification gets no answer: {msgs:?}");
    assert_eq!(effects(dir.path()), 0);
    let records = ledger(&dir.path().join("ledger.db"));
    assert!(records.iter().any(|r| meta(r, "gate_denial") == Some("request_id_missing")), "{records:?}");
}

#[test]
fn start_up_marks_operations_left_in_flight_unknown_with_evidence() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = OperationStore::open(dir.path().join("ops.db")).unwrap();
        s.begin("op-crashed", "crm.patch", &[9; 32]).unwrap();
    }
    run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[]);
    assert_eq!(state(dir.path(), "op-crashed"), OperationState::Unknown);
    let records = ledger(&dir.path().join("ledger.db"));
    let swept: Vec<_> = records.iter().filter(|r| meta(r, "operation_id") == Some("op-crashed")).collect();
    assert_eq!(swept.len(), 1, "{records:?}");
    assert_eq!(swept[0].hop, Hop::McpToolResult);
    assert_eq!(meta(swept[0], "operation_state"), Some("unknown"));
}

#[test]
fn a_side_effect_gate_without_an_operations_store_does_not_start() {
    let dir = tempfile::tempdir().unwrap();
    let c = contract(false);
    let g = certified(&release_binding(&c)).with_contracts(vec![c], Some(task())).unwrap();
    let err = run_proxy_io(fake_tool(dir.path(), Tool::Ok), ctx(g, &dir.path().join("ledger.db")), Cursor::new(Vec::new()), Capture::default())
        .expect_err("refused");
    assert!(err.to_string().contains("--operations-db"), "{err}");
}

mod approvals {
    use super::*;
    use cloakpipe_cert::approval::{sign_approval, Approval};

    fn approver() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn approval_gate(dir: &Path) -> ToolGate {
        let c = contract(true);
        let trusted = vec![TrustedKey { keyid: "approver-1".into(), public_key: approver().verifying_key().to_bytes() }];
        certified(&release_binding(&c))
            .with_contracts(vec![c], Some(task()))
            .unwrap()
            .with_approvals(dir, trusted)
            .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
            .unwrap()
    }

    /// File a receipt approving `arguments` as operation `operation_id`.
    fn approve(dir: &Path, arguments: &Value, operation_id: &str) {
        let release = release_binding(&contract(true)).manifest_hash();
        let fp = fingerprint(&release, "crm.patch", arguments);
        let now = chrono::Utc::now();
        let ts = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let a = Approval {
            release: release.to_string(),
            tool: "crm.patch".into(),
            task_id: "t-981".into(),
            operation_id: operation_id.into(),
            approver: "approver-1".into(),
            approved_at: ts(now - chrono::Duration::minutes(1)),
            not_after: ts(now + chrono::Duration::minutes(15)),
        };
        let bytes = serde_json::to_vec(&sign_approval(&fp, &a, &approver(), "approver-1")).unwrap();
        std::fs::write(dir.join(format!("{}.approval.json", fp.hex())), bytes).unwrap();
    }

    #[test]
    fn conflicting_arguments_under_one_operation_id_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut other = args();
        other["patch"]["stage"] = json!("review");
        approve(dir.path(), &args(), "op-crm-7");
        approve(dir.path(), &other, "op-crm-7");
        let msgs = run(dir.path(), Tool::Ok, approval_gate(dir.path()), &[call(1, &args()), call(2, &other)]);
        assert!(answer(&msgs, 1).get("result").is_some(), "{msgs:?}");
        let a = answer(&msgs, 2);
        assert_eq!(a["error"]["code"], -32001, "{a}");
        assert_eq!(a["error"]["data"]["reason"], "operation_conflict", "{a}");
        assert_eq!(a["error"]["data"]["operationId"], "op-crm-7", "{a}");
        assert_eq!(effects(dir.path()), 1, "the conflicting call never reached the tool");
        let records = ledger(&dir.path().join("ledger.db"));
        let denied: Vec<_> = records.iter().filter(|r| meta(r, "gate_denial") == Some("operation_conflict")).collect();
        assert_eq!(denied.len(), 1, "{records:?}");
        assert_eq!(meta(denied[0], "operation_id"), Some("op-crm-7"));
    }

    #[test]
    fn an_approved_operation_is_tracked_under_the_receipts_operation_id() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &args(), "op-crm-8");
        let msgs = run(dir.path(), Tool::Ok, approval_gate(dir.path()), &[call(1, &args())]);
        assert!(answer(&msgs, 1).get("result").is_some(), "{msgs:?}");
        assert_eq!(state(dir.path(), "op-crm-8"), OperationState::Done);
        let records = ledger(&dir.path().join("ledger.db"));
        let call_hop = records.iter().find(|r| r.hop == Hop::McpToolCall).unwrap();
        assert!(call_hop.metadata.contains_key("approval"));
        assert_eq!(meta(call_hop, "operation_id"), Some("op-crm-8"));
    }
}
