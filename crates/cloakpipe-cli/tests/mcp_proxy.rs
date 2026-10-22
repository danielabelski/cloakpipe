//! End-to-end test for the transparent MCP interceptor (`cloakpipe mcp-proxy`).
//!
//! Spawns the built binary as an interceptor in front of a tiny mock upstream
//! MCP server (a Python script that echoes back the arguments it receives).
//!
//! By default the proxy forwards arguments as the agent sent them and needs
//! no vault. With `--transform pii`:
//!   1. Egress — the upstream tool only ever sees MASKED arguments (no raw PII).
//!   2. Ingress — the agent sees the result with pseudonym tokens REHYDRATED
//!      back to the originals.
//!
//! Skips gracefully when `python3` is unavailable so it never breaks CI.

use std::io::Write;
use std::process::{Command, Stdio};

/// Mock upstream MCP server: echoes a tools/call's arguments back as the result
/// content, and logs what it actually received to stderr (prefixed) so the test
/// can assert the tool never saw raw PII.
const MOCK_UPSTREAM: &str = r#"import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if msg.get("method") == "tools/call":
        args = msg.get("params", {}).get("arguments", {})
        sys.stderr.write("UPSTREAM_RECEIVED: " + json.dumps(args) + "\n")
        sys.stderr.flush()
        resp = {"jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"content": [{"type": "text", "text": json.dumps(args)}]}}
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
"#;

fn python() -> Option<&'static str> {
    for candidate in ["python3", "python"] {
        let ok = Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn mcp_proxy_starts_without_vault() {
    let Some(py) = python() else {
        eprintln!("skipping mcp_proxy e2e: no python3 available");
        return;
    };

    let dir = std::env::temp_dir().join(format!("cloakpipe-mcp-raw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mock = dir.join("mock_upstream.py");
    std::fs::write(&mock, MOCK_UPSTREAM).unwrap();

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"alice@acme.com","cc":["bob@globex.com"]}}}"#;

    // No vault key, no config: the default proxy needs neither.
    let mut child = Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
        .args([
            "mcp-proxy",
            "--upstream",
            &format!("{py} {}", mock.display()),
        ])
        .current_dir(&dir)
        .env_remove("CLOAKPIPE_VAULT_KEY")
        .env_remove("CLOAKPIPE_LEDGER_DB")
        .env_remove("CLOAKPIPE_OPERATIONS_DB")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cloakpipe mcp-proxy");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{request}\n").as_bytes())
        .unwrap();

    let out = child.wait_with_output().expect("interceptor exits");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let vault_files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("vault"))
        .collect();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(out.status.success(), "stdout={stdout}\nstderr={stderr}");
    // The tool gets the arguments exactly as the agent sent them.
    let received = stderr
        .lines()
        .find(|l| l.contains("UPSTREAM_RECEIVED"))
        .unwrap_or_else(|| panic!("upstream never received a call; stderr={stderr}"));
    assert!(
        received.contains("alice@acme.com") && received.contains("bob@globex.com"),
        "tool gets raw arguments by default; received={received}"
    );
    assert!(
        !received.contains("EMAIL_"),
        "no pseudonym tokens by default; received={received}"
    );
    assert!(
        stdout.contains("alice@acme.com"),
        "agent gets the tool's answer; stdout={stdout}"
    );
    // No vault was opened, created or keyed.
    assert!(vault_files.is_empty(), "no vault file: {vault_files:?}");
    assert!(
        !stderr.to_lowercase().contains("vault"),
        "no vault warnings; stderr={stderr}"
    );
}

#[test]
fn mcp_proxy_transform_pii_masks_egress_and_rehydrates_ingress() {
    let Some(py) = python() else {
        eprintln!("skipping mcp_proxy e2e: no python3 available");
        return;
    };

    // Isolated working dir so the vault DB doesn't touch the repo.
    let dir = std::env::temp_dir().join(format!("cloakpipe-mcp-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mock = dir.join("mock_upstream.py");
    std::fs::write(&mock, MOCK_UPSTREAM).unwrap();

    let request = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"alice@acme.com","cc":["bob@globex.com"]}}}"#;

    let mut child = Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
        .args([
            "mcp-proxy",
            "--upstream",
            &format!("{py} {}", mock.display()),
            "--transform",
            "pii",
        ])
        .current_dir(&dir)
        .env(
            "CLOAKPIPE_VAULT_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn cloakpipe mcp-proxy");

    // Send one tools/call, then close stdin (EOF) — the interceptor shuts down
    // cleanly once the upstream has responded.
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{request}\n").as_bytes())
        .unwrap();

    let out = child.wait_with_output().expect("interceptor exits");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    // Ingress: the agent gets the originals back.
    assert!(
        stdout.contains("alice@acme.com") && stdout.contains("bob@globex.com"),
        "agent must receive rehydrated originals; stdout={stdout}\nstderr={stderr}"
    );

    // Egress: the tool only ever saw masked tokens, never raw PII.
    let received = stderr
        .lines()
        .find(|l| l.contains("UPSTREAM_RECEIVED"))
        .unwrap_or_else(|| panic!("upstream never received a call; stderr={stderr}"));
    assert!(
        !received.contains("alice@acme.com") && !received.contains("bob@globex.com"),
        "tool must NOT see raw PII; received={received}"
    );
    assert!(
        received.contains("EMAIL_"),
        "tool should see pseudonym tokens; received={received}"
    );
}
