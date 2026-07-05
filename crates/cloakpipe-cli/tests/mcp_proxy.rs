//! End-to-end test for the transparent MCP interceptor (`cloakpipe mcp-proxy`).
//!
//! Spawns the built binary as an interceptor in front of a tiny mock upstream
//! MCP server (a Python script that echoes back the arguments it receives) and
//! asserts the two security properties:
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
fn mcp_proxy_masks_egress_and_rehydrates_ingress() {
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
