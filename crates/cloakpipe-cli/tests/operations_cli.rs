//! `cloakpipe mcp-proxy --operations-db` and `cloakpipe operations
//! list|reconcile`: a side-effecting tool call whose outcome is lost is never
//! silently re-executed (docs/ACTION_BOUNDARY.md).

use cloakpipe_ledger::{record::LedgerRecord, Hop, LedgerStore, MetadataValue};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VAULT_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn root(rel: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel).to_string_lossy().into_owned()
}

fn example(name: &str) -> String {
    root(&format!("../../examples/action-boundary/{name}"))
}

fn p(dir: &Path, name: &str) -> String {
    dir.join(name).to_string_lossy().into_owned()
}

fn cli(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = bin()
        .current_dir(dir)
        .args(args)
        .env_remove("CLOAKPIPE_OPERATIONS_DB")
        .env_remove("CLOAKPIPE_LEDGER_DB")
        .output()
        .unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn run_ok(dir: &Path, args: &[&str]) -> String {
    let (code, out, err) = cli(dir, args);
    assert_eq!(code, 0, "{args:?}: {out}{err}");
    out
}

/// The example contract (approval as given, sideEffect on) with the example
/// release rebound to it. Returns (contract, release) paths.
fn setup(dir: &Path, approval: bool) -> (String, String) {
    let src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
        .unwrap()
        .replace("requiresApproval: true", &format!("requiresApproval: {approval}"));
    std::fs::write(dir.join("contract.yaml"), &src).unwrap();
    let contract = cloakpipe_release::contract::ToolContract::parse_path(&dir.join("contract.yaml")).unwrap();
    let release: String = std::fs::read_to_string(example("release.yaml"))
        .unwrap()
        .lines()
        .map(|l| if l.contains("policy:tool-contract/") { format!("    - ref: {}", contract.policy_ref()) } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(dir.join("release.yaml"), release).unwrap();
    (p(dir, "contract.yaml"), p(dir, "release.yaml"))
}

/// The gate's certification flags. Only the legacy `certification` build has
/// them (and refuses calls without a certification); the default gate runs on
/// the release manifest alone.
fn cert_flags(cert: &str, trust: &str) -> Vec<String> {
    if cfg!(feature = "certification") {
        vec!["--certification".into(), cert.into(), "--trust".into(), trust.into()]
    } else {
        Vec::new()
    }
}

/// keygen + JUnit import + certify the release → (envelope, key file).
fn certify(dir: &Path, release: &str) -> (String, String) {
    run_ok(dir, &["release", "keygen", "--out", &p(dir, "key.json")]);
    run_ok(dir, &[
        "eval", "import", "--junit", &root("tests/fixtures/certification/passing.junit.xml"), "--release", release,
        "--suite", "support-critical@23", "--covers", "privacy,functional", "--out", &p(dir, "run.json"),
    ]);
    run_ok(dir, &[
        "release", "certify", release, "--policy", &root("tests/fixtures/certification/policy.yaml"),
        "--run", &p(dir, "run.json"), "--require", "privacy,functional", "--environment", "production",
        "--issuer", "ci:test", "--key", &p(dir, "key.json"), "--out", &p(dir, "cert.dsse.json"),
    ]);
    (p(dir, "cert.dsse.json"), p(dir, "key.json"))
}

fn args() -> Value {
    json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "review", "note": "asked for a demo"}})
}

fn call(id: u64) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "crm.patch", "arguments": args()}}).to_string()
}

/// A fake tool that commits every call to `effects.jsonl`; with `lose_ack`
/// it then exits without answering, else it answers with a result.
fn upstream(dir: &Path, lose_ack: bool) -> String {
    let effects = dir.join("effects.jsonl");
    let script = dir.join(if lose_ack { "lose.sh" } else { "ok.sh" });
    let reply = if lose_ack {
        "exit 0".to_string()
    } else {
        r#"printf '{"id":%s,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"patched"}]}}\n' "$id""#.to_string()
    };
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  id=$(printf '%s' \"$line\" | sed 's/^{{\"id\":\\([0-9]*\\),.*$/\\1/')\n  {reply}\ndone\n",
            effects.display()
        ),
    )
    .unwrap();
    format!("sh {}", script.display())
}

fn effects(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("effects.jsonl")).map(|s| s.lines().count()).unwrap_or(0)
}

struct Proxy {
    code: i32,
    msgs: Vec<Value>,
    err: String,
}

struct World {
    dir: tempfile::TempDir,
    contract: String,
    release: String,
    cert: String,
    trust: String,
}

fn world(approval: bool) -> World {
    let dir = tempfile::tempdir().unwrap();
    let (contract, release) = setup(dir.path(), approval);
    let (cert, trust) = certify(dir.path(), &release);
    World { dir, contract, release, cert, trust }
}

impl World {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn ops_db(&self) -> String {
        p(self.path(), "ops.db")
    }

    fn ledger_db(&self) -> String {
        p(self.path(), "ledger.db")
    }

    fn gate(&self) -> Vec<String> {
        let rest = ["--tool-contract", &self.contract, "--task-context", &example("task-context.json")].map(String::from).to_vec();
        [vec!["--manifest".to_string(), self.release.clone()], cert_flags(&self.cert, &self.trust), rest].concat()
    }

    /// `mcp-proxy` with the gate, `extra` flags and `env`, fed `lines`.
    fn proxy(&self, lose_ack: bool, extra: &[&str], env: &[(&str, &str)], lines: &[String]) -> Proxy {
        let up = upstream(self.path(), lose_ack);
        let mut a: Vec<String> = vec!["mcp-proxy".into(), "--upstream".into(), up];
        a.extend(self.gate());
        a.extend(extra.iter().map(|s| s.to_string()));
        let mut cmd = bin();
        cmd.current_dir(self.path())
            .args(&a)
            .env("CLOAKPIPE_VAULT_KEY", VAULT_KEY)
            .env("CLOAKPIPE_LEDGER_DB", self.ledger_db())
            .env_remove("CLOAKPIPE_RELEASE")
            .env_remove("CLOAKPIPE_TASK_CONTEXT")
            .env_remove("CLOAKPIPE_OPERATIONS_DB");
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
        let out = child.wait_with_output().unwrap();
        Proxy {
            code: out.status.code().unwrap_or(-1),
            msgs: String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
            err: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn run(&self, lose_ack: bool, lines: &[String]) -> Proxy {
        let db = self.ops_db();
        self.proxy(lose_ack, &["--operations-db", &db], &[], lines)
    }

    fn list(&self, extra: &[&str]) -> Vec<Value> {
        let db = self.ops_db();
        let mut a = vec!["operations", "list", "--operations-db", &db];
        a.extend_from_slice(extra);
        serde_json::from_str(&run_ok(self.path(), &a)).unwrap()
    }

    fn ledger(&self) -> Vec<LedgerRecord> {
        let store = LedgerStore::open(&self.ledger_db()).unwrap();
        store.records_for_tenant(&cloakpipe_mcp::stable_ids().0).unwrap().into_iter().map(|r| r.record).collect()
    }
}

fn answer(msgs: &[Value], id: u64) -> &Value {
    msgs.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("no answer for {id}: {msgs:?}"))
}

fn meta<'a>(r: &'a LedgerRecord, key: &str) -> Option<&'a str> {
    match r.metadata.get(key) {
        Some(MetadataValue::OpaqueId(s)) => Some(s),
        _ => None,
    }
}

#[test]
fn a_lost_acknowledgment_is_reconciled_by_the_operator_and_never_re_executed() {
    let w = world(false);

    // The tool commits the patch, then dies without answering.
    let r = w.run(true, &[call(1)]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(effects(w.path()), 1);
    let a = answer(&r.msgs, 1);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "operation_unknown", "{a}");
    let op = a["error"]["data"]["operationId"].as_str().unwrap().to_string();
    assert!(op.starts_with("op-") && op.len() == 35, "{op}");

    // The operator sees it.
    let unknown = w.list(&["--state", "unknown"]);
    assert_eq!(unknown.len(), 1, "{unknown:?}");
    assert_eq!(unknown[0]["operationId"], op.as_str());
    assert_eq!(unknown[0]["tool"], "crm.patch");
    assert_eq!(unknown[0]["state"], "unknown");
    assert!(unknown[0].get("result").is_none() && unknown[0].get("callDigest").is_none(), "{unknown:?}");
    assert!(w.list(&["--state", "done"]).is_empty());

    // A retry is refused until it is reconciled.
    let r = w.run(false, &[call(2)]);
    let a = answer(&r.msgs, 2);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "reconcile_before_retry", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");
    assert_eq!(effects(w.path()), 1);

    // The operator checks the CRM: the patch landed.
    let (db, ledger) = (w.ops_db(), w.ledger_db());
    let out = run_ok(w.path(), &[
        "operations", "reconcile", &op, "--outcome", "done", "--operations-db", &db, "--ledger-db", &ledger,
        "--manifest", &w.release,
    ]);
    let report: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["operationId"], op.as_str());
    assert_eq!(report["state"], "done");
    assert_eq!(report["previousState"], "unknown");
    assert_eq!(w.list(&["--state", "done"]).len(), 1);

    // The retry replays; the tool is not called again.
    let r = w.run(false, &[call(3)]);
    let a = answer(&r.msgs, 3);
    assert_eq!(a["result"]["_meta"]["cloakpipe"]["replayed"], true, "{a}");
    assert_eq!(effects(w.path()), 1, "no second effect");

    // A reconciled operation cannot be reconciled again.
    let (code, _, err) = cli(w.path(), &["operations", "reconcile", &op, "--outcome", "not-applied", "--operations-db", &db]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("done"), "{err}");

    let records = w.ledger();
    let reconciled: Vec<_> = records.iter().filter(|r| r.hop == Hop::OperationReconciled).collect();
    assert_eq!(reconciled.len(), 1, "{records:?}");
    assert_eq!(meta(reconciled[0], "operation_id"), Some(op.as_str()));
    assert_eq!(meta(reconciled[0], "operation_state"), Some("done"));
    let release = cloakpipe_release::parse_path(Path::new(&w.release)).unwrap().manifest_hash().0;
    assert_eq!(reconciled[0].release_hash(), Some(release), "bound to the release");
    let dump = format!("{records:?}");
    for raw in ["demo-co", "lead-42", "asked for a demo"] {
        assert!(!dump.contains(raw), "{raw} leaked");
    }
}

#[test]
fn a_not_applied_operation_runs_again() {
    let w = world(false);
    let r = w.run(true, &[call(1)]);
    let op = answer(&r.msgs, 1)["error"]["data"]["operationId"].as_str().unwrap().to_string();
    let db = w.ops_db();
    run_ok(w.path(), &["operations", "reconcile", &op, "--outcome", "not-applied", "--operations-db", &db]);
    let r = w.run(false, &[call(2)]);
    assert_eq!(answer(&r.msgs, 2)["result"]["content"][0]["text"], "patched", "{:?}", r.msgs);
    assert_eq!(effects(w.path()), 2);
    assert_eq!(w.list(&[])[0]["state"], "done");
}

#[test]
fn the_operations_db_comes_from_the_environment_too() {
    let w = world(false);
    let db = w.ops_db();
    let r = w.proxy(false, &[], &[("CLOAKPIPE_OPERATIONS_DB", &db)], &[call(1)]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert!(answer(&r.msgs, 1).get("result").is_some(), "{:?}", r.msgs);
    let all = w.list(&[]);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["state"], "done");
}

#[test]
fn a_side_effect_tool_without_an_operations_db_refuses_to_start() {
    let w = world(false);
    let r = w.proxy(false, &[], &[], &[call(1)]);
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(r.err.contains("--operations-db"), "{}", r.err);
    assert_eq!(effects(w.path()), 0, "the upstream never ran");
    assert!(r.msgs.is_empty());
}

#[test]
fn the_shipped_example_contract_runs_with_approval_and_operations() {
    let w = world(true);
    run_ok(w.path(), &["release", "keygen", "--out", &p(w.path(), "approver.json")]);
    std::fs::write(w.path().join("args.json"), args().to_string()).unwrap();
    let report: Value = serde_json::from_str(&run_ok(w.path(), &[
        "approve", "--manifest", &w.release, "--tool", "crm.patch", "--args", &p(w.path(), "args.json"),
        "--task-context", &example("task-context.json"), "--key", &p(w.path(), "approver.json"),
        "--operation-id", "crm-op-9", "--out", &p(w.path(), "approvals"),
    ]))
    .unwrap();
    assert_eq!(report["operationId"], "crm-op-9");
    let (db, approvals, approver) = (w.ops_db(), p(w.path(), "approvals"), p(w.path(), "approver.json"));
    let flags = ["--operations-db", db.as_str(), "--approvals", approvals.as_str(), "--approver-key", approver.as_str()];
    let r = w.proxy(false, &flags, &[], &[call(1)]);
    assert!(answer(&r.msgs, 1).get("result").is_some(), "{:?} {}", r.msgs, r.err);
    // The same approved call again: replayed, not re-run.
    let r = w.proxy(false, &flags, &[], &[call(2)]);
    assert_eq!(answer(&r.msgs, 2)["result"]["_meta"]["cloakpipe"]["replayed"], true, "{:?}", r.msgs);
    assert_eq!(effects(w.path()), 1);
    let all = w.list(&[]);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0]["operationId"], "crm-op-9");
}

#[test]
fn operations_commands_refuse_bad_input() {
    let w = world(false);
    let db = w.ops_db();
    drop(cloakpipe_mcp::operations::OperationStore::open(&db).unwrap());
    // Unknown operation.
    let (code, _, err) = cli(w.path(), &["operations", "reconcile", "op-nope", "--outcome", "done", "--operations-db", &db]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("no such operation"), "{err}");
    // Bad outcome or state names are usage errors.
    let (code, _, _) = cli(w.path(), &["operations", "reconcile", "op-nope", "--outcome", "maybe", "--operations-db", &db]);
    assert_eq!(code, 2);
    let (code, _, _) = cli(w.path(), &["operations", "list", "--state", "sideways", "--operations-db", &db]);
    assert_eq!(code, 2);
    // No database named at all.
    let (code, _, err) = cli(w.path(), &["operations", "list"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("--operations-db"), "{err}");
    // A missing database is not silently created by list.
    let (code, _, err) = cli(w.path(), &["operations", "list", "--operations-db", &p(w.path(), "missing.db")]);
    assert_eq!(code, 2, "{err}");
    assert!(!w.path().join("missing.db").exists());
}

/// A second proxy on an operations database a running gate holds refuses to
/// start (exit 2); `operations list` and `reconcile` still work.
#[test]
fn a_second_gate_on_a_live_operations_db_refuses_to_start() {
    let w = world(false);
    let db = w.ops_db();
    let mut live = cloakpipe_mcp::operations::OperationStore::open(&db).unwrap();
    live.recover().unwrap();
    live.begin("op-live", "crm.patch", &[3; 32]).unwrap();
    live.begin("op-lost", "crm.patch", &[4; 32]).unwrap();
    live.settle("op-lost", cloakpipe_mcp::operations::OperationState::Unknown, None).unwrap();

    let r = w.run(false, &[call(1)]);
    assert_eq!(r.code, 2, "{}", r.err);
    assert!(r.err.contains("another gate"), "{}", r.err);
    assert_eq!(effects(w.path()), 0, "the upstream never ran");
    assert_eq!(live.get("op-live").unwrap().unwrap().state, cloakpipe_mcp::operations::OperationState::InFlight);

    assert_eq!(w.list(&[]).len(), 2);
    run_ok(w.path(), &["operations", "reconcile", "op-lost", "--outcome", "not-applied", "--operations-db", &db]);
    assert_eq!(w.list(&["--state", "not_applied"]).len(), 1);
}

/// Reconciling an `in_flight` operation (a running gate may still get its
/// reply) needs --force; without it the command refuses (exit 1) and warns.
#[test]
fn reconciling_an_in_flight_operation_needs_force() {
    let w = world(false);
    let db = w.ops_db();
    let mut s = cloakpipe_mcp::operations::OperationStore::open(&db).unwrap();
    s.begin("op-pending", "crm.patch", &[5; 32]).unwrap();
    drop(s);
    let (code, _, err) = cli(w.path(), &["operations", "reconcile", "op-pending", "--outcome", "not-applied", "--operations-db", &db]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("in_flight") && err.contains("--force"), "{err}");
    assert_eq!(w.list(&["--state", "in_flight"]).len(), 1, "unchanged");
    let out = run_ok(w.path(), &["operations", "reconcile", "op-pending", "--outcome", "not-applied", "--force", "--operations-db", &db]);
    let report: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["previousState"], "in_flight");
    assert_eq!(report["state"], "not_applied");
}

#[test]
fn a_v011_operations_db_with_masked_results_needs_transform_pii() {
    let w = world(false);
    let r = w.run(false, &[call(1)]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(effects(w.path()), 1);
    // Make the stored result look as v0.11 left it: every v0.11 result was
    // masked, and an upgraded v0.11 row carries no masking flag.
    rusqlite::Connection::open(w.ops_db()).unwrap().execute("UPDATE operations SET result_masked = NULL", []).unwrap();

    // Without --transform pii a replay would hand the agent pseudonym tokens:
    // the proxy refuses to start and says what to do.
    let r = w.run(false, &[call(2)]);
    assert_ne!(r.code, 0, "refused: {}", r.err);
    assert!(r.err.contains("--transform pii"), "{}", r.err);
    assert!(r.msgs.is_empty(), "{:?}", r.msgs);
    assert_eq!(effects(w.path()), 1, "the tool was not called");

    // With it, the retry replays the stored result through the vault.
    let db = w.ops_db();
    let r = w.proxy(false, &["--operations-db", &db, "--transform", "pii"], &[], &[call(3)]);
    assert_eq!(r.code, 0, "{}", r.err);
    let a = answer(&r.msgs, 3);
    assert_eq!(a["result"]["_meta"]["cloakpipe"]["replayed"], true, "{a}");
    assert_eq!(a["result"]["content"][0]["text"], "patched", "{a}");
    assert_eq!(effects(w.path()), 1, "no second effect");
}
