//! `cloakpipe action fingerprint`, `cloakpipe approve` and
//! `cloakpipe mcp-proxy --approvals … --approver-key …`: a tool whose
//! contract requires approval runs only with a signed receipt for that exact
//! call, and the ledger records the receipt's digest, never the arguments.

use cloakpipe_ledger::{LedgerStore, MetadataValue};
use cloakpipe_release::action::fingerprint;
use cloakpipe_release::parse_path;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
    let out = bin().current_dir(dir).args(args).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

fn run_ok(dir: &Path, args: &[&str]) -> String {
    let (code, out, err) = cli(dir, args);
    assert_eq!(code, 0, "{args:?}: {out}{err}");
    out
}

/// The example contract with operation tracking (item 3) off, approval on,
/// and the example release rebound to it. Returns (contract, release) paths.
fn setup(dir: &Path) -> (String, String) {
    let src = std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap().replace("sideEffect: true", "sideEffect: false");
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

fn write_json(dir: &Path, name: &str, v: &Value) -> String {
    std::fs::write(dir.join(name), v.to_string()).unwrap();
    p(dir, name)
}

/// `cloakpipe approve` for `args` with `extra` flags; returns its JSON report.
fn approve(dir: &Path, release: &str, key: &str, arguments: &Value, extra: &[&str]) -> Value {
    let args_file = write_json(dir, "approve-args.json", arguments);
    let out_dir = p(dir, "approvals");
    let task = example("task-context.json");
    let mut a = vec![
        "approve", "--manifest", release, "--tool", "crm.patch", "--args", &args_file,
        "--task-context", &task, "--key", key, "--out", &out_dir,
    ];
    a.extend_from_slice(extra);
    serde_json::from_str(&run_ok(dir, &a)).unwrap()
}

/// A fake tool: records each line, answers with an empty result for its id.
fn upstream(dir: &Path) -> (String, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{}'\n  id=$(printf '%s' \"$line\" | sed 's/^{{\"id\":\\([0-9]*\\),.*$/\\1/')\n  printf '{{\"id\":%s,\"jsonrpc\":\"2.0\",\"result\":{{\"content\":[]}}}}\\n' \"$id\"\ndone\n",
            received.display()
        ),
    )
    .unwrap();
    (format!("sh {}", script.display()), received)
}

fn call(id: u64, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "crm.patch", "arguments": arguments}}).to_string()
}

struct Proxy {
    code: i32,
    msgs: Vec<Value>,
    seen: Option<String>,
    err: String,
    ledger: Vec<cloakpipe_ledger::record::LedgerRecord>,
}

fn proxy(dir: &Path, extra: &[&str], lines: &[String]) -> Proxy {
    let (up, received) = upstream(dir);
    let _ = std::fs::remove_file(&received);
    let ledger_db = dir.join(format!("ledger-{}.db", uuid::Uuid::new_v4()));
    let mut args = vec!["mcp-proxy", "--upstream", up.as_str()];
    args.extend_from_slice(extra);
    let mut child = bin()
        .current_dir(dir)
        .args(&args)
        .env("CLOAKPIPE_VAULT_KEY", VAULT_KEY)
        .env("CLOAKPIPE_LEDGER_DB", &ledger_db)
        .env_remove("CLOAKPIPE_RELEASE")
        .env_remove("CLOAKPIPE_TASK_CONTEXT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let ledger = if ledger_db.exists() {
        let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
        store.records_for_tenant(&cloakpipe_mcp::stable_ids().0).unwrap().into_iter().map(|r| r.record).collect()
    } else {
        Vec::new()
    };
    Proxy {
        code: out.status.code().unwrap_or(-1),
        msgs: String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
        seen: std::fs::read_to_string(&received).ok(),
        err: String::from_utf8_lossy(&out.stderr).into_owned(),
        ledger,
    }
}

fn refusal(msgs: &[Value], id: u64) -> Option<String> {
    msgs.iter().find(|m| m["id"] == id).and_then(|m| m["error"]["data"]["reason"].as_str().map(str::to_string))
}

struct World {
    dir: tempfile::TempDir,
    contract: String,
    release: String,
    cert: String,
    trust: String,
    approver: String,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (contract, release) = setup(dir.path());
    let (cert, trust) = certify(dir.path(), &release);
    run_ok(dir.path(), &["release", "keygen", "--out", &p(dir.path(), "approver.json")]);
    let approver = p(dir.path(), "approver.json");
    World { dir, contract, release, cert, trust, approver }
}

impl World {
    fn gate(&self, approver_key: &str) -> Vec<String> {
        [
            "--manifest", &self.release, "--certification", &self.cert, "--trust", &self.trust,
            "--tool-contract", &self.contract, "--task-context", &example("task-context.json"),
            "--approvals", &p(self.dir.path(), "approvals"), "--approver-key", approver_key,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn run(&self, approver_key: &str, lines: &[String]) -> Proxy {
        let g = self.gate(approver_key);
        proxy(self.dir.path(), &g.iter().map(String::as_str).collect::<Vec<_>>(), lines)
    }
}

#[test]
fn action_fingerprint_prints_the_call_fingerprint() {
    let dir = tempfile::tempdir().unwrap();
    let (_, release) = setup(dir.path());
    let args_file = write_json(dir.path(), "args.json", &args());
    let out = run_ok(dir.path(), &["action", "fingerprint", "--manifest", &release, "--tool", "crm.patch", "--args", &args_file]);
    let m = parse_path(Path::new(&release)).unwrap();
    assert_eq!(out.trim(), fingerprint(&m.manifest_hash(), "crm.patch", &args()).to_string());
}

#[test]
fn an_approved_call_runs_and_the_ledger_records_the_receipt_digest() {
    let w = world();
    let report = approve(w.dir.path(), &w.release, &w.approver, &args(), &[]);
    let m = parse_path(Path::new(&w.release)).unwrap();
    let fp = fingerprint(&m.manifest_hash(), "crm.patch", &args());
    let receipt_path = w.dir.path().join("approvals").join(format!("{}.approval.json", fp.hex()));
    assert_eq!(report["receipt"], receipt_path.to_string_lossy().as_ref(), "{report}");
    assert_eq!(report["fingerprint"], fp.to_string());
    let bytes = std::fs::read(&receipt_path).unwrap();
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(report["digest"], format!("sha256:{}", hex::encode(digest)));
    let op = report["operationId"].as_str().unwrap().to_string();
    assert!(uuid::Uuid::parse_str(&op).is_ok_and(|u| u.get_version_num() == 4), "a fresh UUID v4: {op}");

    let r = w.run(&w.approver, &[call(1, args())]);
    assert_eq!(r.code, 0, "{}", r.err);
    assert_eq!(refusal(&r.msgs, 1), None, "{:?} {}", r.msgs, r.err);
    assert!(r.seen.unwrap_or_default().contains("crm.patch"));

    let approved: Vec<_> = r.ledger.iter().filter(|x| x.metadata.contains_key("approval")).collect();
    assert_eq!(approved.len(), 1, "{:?}", r.ledger);
    assert_eq!(approved[0].metadata.get("approval"), Some(&MetadataValue::Hash(digest)));
    assert_eq!(approved[0].metadata.get("operation_id"), Some(&MetadataValue::OpaqueId(op)));
    let dump = format!("{:?}", r.ledger);
    for raw in ["demo-co", "lead-42", "review", "asked for a demo", fp.hex().as_str()] {
        assert!(!dump.contains(raw), "{raw} in the ledger: {dump}");
    }
    assert!(!dump.contains(&format!("{:?}", fp.0)), "the fingerprint bytes are not recorded");
}

#[test]
fn a_changed_argument_needs_a_new_approval() {
    let w = world();
    approve(w.dir.path(), &w.release, &w.approver, &args(), &[]);
    let mut changed = args();
    changed["patch"]["stage"] = json!("qualified");
    let r = w.run(&w.approver, &[call(1, changed)]);
    assert_eq!(refusal(&r.msgs, 1).as_deref(), Some("approval_required"), "{:?} {}", r.msgs, r.err);
    assert!(r.seen.unwrap_or_default().is_empty(), "never reaches the tool");
}

#[test]
fn an_expired_approval_is_refused() {
    let w = world();
    let issued = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    approve(w.dir.path(), &w.release, &w.approver, &args(), &["--now", &issued, "--expires", "15m"]);
    let r = w.run(&w.approver, &[call(1, args())]);
    assert_eq!(refusal(&r.msgs, 1).as_deref(), Some("approval_expired"), "{:?} {}", r.msgs, r.err);
}

#[test]
fn an_approval_by_an_untrusted_signer_is_refused() {
    let w = world();
    run_ok(w.dir.path(), &["release", "keygen", "--out", &p(w.dir.path(), "mallory.json")]);
    approve(w.dir.path(), &w.release, &p(w.dir.path(), "mallory.json"), &args(), &[]);
    let r = w.run(&w.approver, &[call(1, args())]);
    assert_eq!(refusal(&r.msgs, 1).as_deref(), Some("approval_invalid"), "{:?} {}", r.msgs, r.err);
}

#[test]
fn an_approval_for_another_task_is_refused() {
    let w = world();
    let task = write_json(w.dir.path(), "other-task.json", &json!({"taskId": "t-982", "tenant": "demo-co", "record": "lead-42"}));
    let args_file = write_json(w.dir.path(), "a.json", &args());
    run_ok(w.dir.path(), &[
        "approve", "--manifest", &w.release, "--tool", "crm.patch", "--args", &args_file, "--task-context", &task,
        "--key", &w.approver, "--out", &p(w.dir.path(), "approvals"),
    ]);
    let r = w.run(&w.approver, &[call(1, args())]);
    assert_eq!(refusal(&r.msgs, 1).as_deref(), Some("approval_invalid"), "{:?} {}", r.msgs, r.err);
}

#[test]
fn an_approval_for_another_release_does_not_approve_this_one() {
    let w = world();
    // Same call, another release (a different runtime image).
    let other = std::fs::read_to_string(&w.release).unwrap().replace("region: in-south", "region: eu-west");
    std::fs::write(w.dir.path().join("other-release.yaml"), other).unwrap();
    approve(w.dir.path(), &p(w.dir.path(), "other-release.yaml"), &w.approver, &args(), &[]);
    let r = w.run(&w.approver, &[call(1, args())]);
    assert_eq!(refusal(&r.msgs, 1).as_deref(), Some("approval_required"), "{:?} {}", r.msgs, r.err);
}

#[test]
fn approve_takes_an_explicit_operation_id_and_refuses_bad_input() {
    let w = world();
    let report = approve(w.dir.path(), &w.release, &w.approver, &args(), &["--operation-id", "crm-op-42", "--expires", "2h"]);
    assert_eq!(report["operationId"], "crm-op-42");
    let args_file = write_json(w.dir.path(), "a.json", &args());
    let no_task_id = write_json(w.dir.path(), "t.json", &json!({"tenant": "demo-co"}));
    let out = p(w.dir.path(), "approvals");
    let ctx = example("task-context.json");
    let base = |tool: &'static str, task: String| -> Vec<String> {
        ["approve", "--manifest", &w.release, "--tool", tool, "--args", &args_file, "--task-context", &task, "--key", &w.approver, "--out", &out]
            .iter()
            .map(|s| s.to_string())
            .collect()
    };
    let cases: Vec<(Vec<String>, i32)> = vec![
        (base("crm.delete", ctx.clone()), 1),                                                  // undeclared tool
        (base("crm.patch", no_task_id.clone()), 1),                                            // no taskId
        ([base("crm.patch", ctx.clone()), vec!["--expires".into(), "soon".into()]].concat(), 2),
        ([base("crm.patch", ctx.clone()), vec!["--expires".into(), "0m".into()]].concat(), 2),
        ([base("crm.patch", ctx.clone()), vec!["--operation-id".into(), "op 1".into()]].concat(), 2),
        ([base("crm.patch", ctx.clone()), vec!["--key".into(), w.trust.replace("key.json", "missing.json")]].concat(), 2),
    ];
    for (a, expected) in cases {
        let (code, _, err) = cli(w.dir.path(), &a.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(code, expected, "{a:?}: {err}");
    }
    // Duplicate keys in the arguments are ambiguous: refused.
    std::fs::write(w.dir.path().join("dup.json"), r#"{"tenant":"demo-co","tenant":"rival-co"}"#).unwrap();
    let dup = p(w.dir.path(), "dup.json");
    let (code, _, err) = cli(w.dir.path(), &["action", "fingerprint", "--manifest", &w.release, "--tool", "crm.patch", "--args", &dup]);
    assert_eq!(code, 1, "{err}");
}

#[test]
fn approval_flags_must_come_together_and_need_a_manifest() {
    let w = world();
    let dir = p(w.dir.path(), "approvals");
    std::fs::create_dir_all(&dir).unwrap();
    let base = ["--manifest", w.release.as_str(), "--certification", &w.cert, "--trust", &w.trust, "--tool-contract", &w.contract];
    for flags in [
        [&base[..], &["--approvals", dir.as_str()]].concat(),
        [&base[..], &["--approver-key", w.approver.as_str()]].concat(),
        [&base[..], &["--approvals", "/nonexistent-dir", "--approver-key", w.approver.as_str()]].concat(),
        vec!["--approvals", dir.as_str(), "--approver-key", w.approver.as_str()],
    ] {
        let r = proxy(w.dir.path(), &flags, &[]);
        assert_eq!(r.code, 2, "{flags:?}: {}", r.err);
        assert!(r.seen.is_none(), "{flags:?}: the upstream must not start");
    }
}
