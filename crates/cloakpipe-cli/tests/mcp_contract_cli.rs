//! `cloakpipe mcp-proxy --tool-contract … --task-context …`: argument-level
//! rules for the tools a certified release calls, and the start-up checks
//! that bind the contracts to the release.

use cloakpipe_release::contract::ToolContract;
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

fn run_ok(dir: &Path, args: &[&str]) {
    let out = bin().current_dir(dir).args(args).output().unwrap();
    assert!(out.status.success(), "{args:?}: {}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// Write `contract.yaml` (the example with approval and operation tracking
/// switched off, plus `edits`) and `release.yaml` binding `bind` (default:
/// that contract). Returns (contract path, release path, the contract).
fn setup(dir: &Path, edits: &[(&str, &str)], bind: Option<&ToolContract>) -> (String, String, ToolContract) {
    let mut src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
        .unwrap()
        .replace("sideEffect: true", "sideEffect: false")
        .replace("requiresApproval: true", "requiresApproval: false");
    for (from, to) in edits {
        src = src.replace(from, to);
    }
    std::fs::write(dir.join("contract.yaml"), &src).unwrap();
    let contract = ToolContract::parse_path(&dir.join("contract.yaml")).unwrap();
    let bound = bind.unwrap_or(&contract).policy_ref();
    let release: String = std::fs::read_to_string(example("release.yaml"))
        .unwrap()
        .lines()
        .map(|l| if l.contains("policy:tool-contract/") { format!("    - ref: {bound}") } else { l.to_string() })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(dir.join("release.yaml"), release).unwrap();
    (p(dir, "contract.yaml"), p(dir, "release.yaml"), contract)
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

fn args(tenant: &str) -> Value {
    json!({"tenant": tenant, "record": "lead-42", "patch": {"stage": "review"}})
}

/// Run the interceptor over `lines`; returns (exit code, agent messages, what the tool saw, stderr).
fn proxy(dir: &Path, extra: &[&str], envs: &[(&str, &str)], lines: &[String]) -> (i32, Vec<Value>, Option<String>, String) {
    let (up, received) = upstream(dir);
    let _ = std::fs::remove_file(&received);
    let mut args = vec!["mcp-proxy", "--upstream", up.as_str()];
    args.extend_from_slice(extra);
    let mut cmd = bin();
    cmd.current_dir(dir)
        .args(&args)
        .env("CLOAKPIPE_VAULT_KEY", VAULT_KEY)
        .env_remove("CLOAKPIPE_RELEASE")
        .env_remove("CLOAKPIPE_TASK_CONTEXT");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(lines.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let msgs = String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let seen = std::fs::read_to_string(&received).ok();
    (out.status.code().unwrap_or(-1), msgs, seen, String::from_utf8_lossy(&out.stderr).into_owned())
}

fn refusal(msgs: &[Value], id: u64) -> Option<String> {
    msgs.iter().find(|m| m["id"] == id).and_then(|m| m["error"]["data"]["reason"].as_str().map(str::to_string))
}

#[test]
fn contract_calls_are_checked_against_the_task_context() {
    let dir = tempfile::tempdir().unwrap();
    let (contract, release, _) = setup(dir.path(), &[], None);
    let (cert, key) = certify(dir.path(), &release);
    let task = example("task-context.json");
    let gate = [vec!["--manifest".to_string(), release.clone()], cert_flags(&cert, &key), vec!["--tool-contract".into(), contract.clone(), "--task-context".into(), task]].concat();
    let (code, msgs, seen, err) = proxy(
        dir.path(),
        &gate.iter().map(String::as_str).collect::<Vec<_>>(),
        &[],
        &[call(1, args("demo-co")), call(2, args("rival-co"))],
    );
    assert_eq!(code, 0, "{err}");
    let seen = seen.unwrap_or_default();
    assert!(seen.contains("demo-co") && !seen.contains("rival-co"), "{seen}");
    assert_eq!(refusal(&msgs, 1), None, "{msgs:?}");
    assert_eq!(refusal(&msgs, 2).as_deref(), Some("scope_mismatch"), "{msgs:?}");
}

#[test]
fn the_task_context_can_come_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let (contract, release, _) = setup(dir.path(), &[], None);
    let (cert, key) = certify(dir.path(), &release);
    let gate = [vec!["--manifest".to_string(), release.clone()], cert_flags(&cert, &key), vec!["--tool-contract".into(), contract.clone()]].concat();
    let gate: Vec<&str> = gate.iter().map(String::as_str).collect();
    let (_, msgs, _, err) = proxy(dir.path(), &gate, &[("CLOAKPIPE_TASK_CONTEXT", &example("task-context.json"))], &[call(1, args("demo-co"))]);
    assert_eq!(refusal(&msgs, 1), None, "{msgs:?} {err}");
    // Without one, bound arguments cannot be checked: refused.
    let (_, msgs, _, _) = proxy(dir.path(), &gate, &[], &[call(1, args("demo-co"))]);
    assert_eq!(refusal(&msgs, 1).as_deref(), Some("task_context_missing"), "{msgs:?}");
}

#[test]
fn a_contract_the_release_does_not_bind_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    // The release binds the example contract; the operator passes an edited one.
    let (_, _, original) = setup(dir.path(), &[], None);
    let (edited, release, edited_contract) = setup(dir.path(), &[("maxLength: 280", "maxLength: 100000")], Some(&original));
    let (code, _, seen, err) = proxy(
        dir.path(),
        &["--manifest", &release, "--tool-contract", &edited, "--task-context", &example("task-context.json")],
        &[],
        &[call(1, args("demo-co"))],
    );
    assert_eq!(code, 2, "{err}");
    assert!(seen.is_none(), "the upstream must not start");
    assert!(err.contains(&edited_contract.policy_ref()), "names the digest to bind: {err}");
}

#[test]
fn a_bound_contract_that_was_not_supplied_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let (_, release, contract) = setup(dir.path(), &[], None);
    let (code, _, seen, err) = proxy(dir.path(), &["--manifest", &release], &[], &[call(1, args("demo-co"))]);
    assert_eq!(code, 2, "{err}");
    assert!(seen.is_none());
    assert!(err.contains(&contract.policy_ref()) && err.contains("--tool-contract"), "{err}");
}

#[test]
fn contract_flags_need_a_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (contract, _, _) = setup(dir.path(), &[], None);
    let task = example("task-context.json");
    for flags in [vec!["--tool-contract", contract.as_str()], vec!["--task-context", task.as_str()]] {
        let (code, _, seen, err) = proxy(dir.path(), &flags, &[], &[]);
        assert_eq!(code, 2, "{flags:?} must not run ungated: {err}");
        assert!(seen.is_none());
        assert!(err.contains("--manifest"), "{flags:?}: {err}");
    }
}

#[test]
fn unreadable_contracts_or_task_contexts_refuse_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let (contract, release, _) = setup(dir.path(), &[], None);
    std::fs::write(dir.path().join("bad.yaml"), "apiVersion: cloakpipe.co/v1alpha1\nkind: ToolContract\n").unwrap();
    std::fs::write(dir.path().join("list.json"), "[\"demo-co\"]").unwrap();
    let bad = p(dir.path(), "bad.yaml");
    let list = p(dir.path(), "list.json");
    let task = example("task-context.json");
    for flags in [
        vec!["--manifest", release.as_str(), "--tool-contract", bad.as_str(), "--task-context", task.as_str()],
        vec!["--manifest", release.as_str(), "--tool-contract", "/nonexistent.yaml", "--task-context", task.as_str()],
        vec!["--manifest", release.as_str(), "--tool-contract", contract.as_str(), "--task-context", list.as_str()],
        vec!["--manifest", release.as_str(), "--tool-contract", contract.as_str(), "--task-context", "/nonexistent.json"],
    ] {
        let (code, _, seen, err) = proxy(dir.path(), &flags, &[], &[]);
        assert_ne!(code, 0, "{flags:?}: {err}");
        assert!(seen.is_none(), "{flags:?}");
    }
}
