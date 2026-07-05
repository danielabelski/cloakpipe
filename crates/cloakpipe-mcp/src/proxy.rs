//! Transparent MCP interceptor (M8).
//!
//! Sits between an MCP client (the agent) and an upstream MCP server, speaking
//! MCP's newline-delimited JSON-RPC in both directions:
//!
//!   agent ──stdin──▶ [ mask tools/call args ] ──▶ upstream stdin
//!   agent ◀─stdout── [ rehydrate result tokens ] ◀── upstream stdout
//!
//! So PII never reaches the (possibly external) tool, and pseudonym tokens the
//! tool echoes back are restored before the agent sees them. Every masked call
//! and every result appends a no-PII evidence-ledger hop (`McpToolCall` /
//! `McpToolResult`) — categories + counts only, never the text.
//!
//! The pump is deliberately synchronous std I/O on two OS threads: all the work
//! (detect / mask / rehydrate / ledger append) is blocking anyway, and async
//! stdio (`tokio::io::stdin`) both buffers stdout unhelpfully and blocks runtime
//! shutdown on its background read thread.

use anyhow::{Context, Result};
use cloakpipe_core::{detector::Detector, rehydrator::Rehydrator, replacer::Replacer, vault::Vault};
use cloakpipe_ledger::{
    record::Identity, store::LedgerStore, Action, ActionKind, Detection, Hop, RecordBuilder,
};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

/// Everything the interceptor needs beyond the upstream command.
pub struct ProxyContext {
    pub detector: Detector,
    pub vault: Vault,
    /// Evidence ledger DB path (`CLOAKPIPE_LEDGER_DB`); `None` disables recording.
    pub ledger_db: Option<String>,
}

type SharedLedger = Option<Arc<Mutex<LedgerStore>>>;

/// Run the interceptor: spawn `upstream` and pump JSON-RPC both ways. Returns
/// when the upstream exits (which happens when the agent closes stdin, or when
/// the upstream itself dies).
pub fn run_proxy(upstream: Vec<String>, ctx: ProxyContext) -> Result<()> {
    anyhow::ensure!(!upstream.is_empty(), "upstream MCP command is empty");

    let mut child = Command::new(&upstream[0])
        .args(&upstream[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // upstream logs pass through to our stderr
        .spawn()
        .with_context(|| format!("failed to spawn upstream MCP server: {upstream:?}"))?;

    let to_upstream = child.stdin.take().context("upstream has no stdin")?;
    let from_upstream = child.stdout.take().context("upstream has no stdout")?;

    let detector = Arc::new(ctx.detector);
    let vault = Arc::new(Mutex::new(ctx.vault));
    let ledger: SharedLedger = ctx.ledger_db.as_deref().and_then(open_ledger);
    let (tenant, agent) = stable_ids();

    // Egress: agent stdin → mask tools/call → upstream stdin.
    {
        let detector = detector.clone();
        let vault = vault.clone();
        let ledger = ledger.clone();
        std::thread::spawn(move || {
            let mut to_upstream = to_upstream; // owned: dropped (→ upstream stdin EOF) when this thread ends
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                let Ok(line) = line else { break };
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(mut msg) => {
                        if msg.get("method").and_then(Value::as_str) == Some("tools/call") {
                            let masked = {
                                let mut v = vault.lock().expect("vault poisoned");
                                mask_value(msg.pointer_mut("/params/arguments"), &detector, &mut v)
                            };
                            if masked > 0 {
                                record_hop(&ledger, tenant, agent, Hop::McpToolCall, masked);
                            }
                        }
                        serde_json::to_string(&msg).unwrap_or(line)
                    }
                    Err(_) => line, // not JSON — forward verbatim
                };
                if to_upstream.write_all(out.as_bytes()).is_err()
                    || to_upstream.write_all(b"\n").is_err()
                    || to_upstream.flush().is_err()
                {
                    break;
                }
            }
        });
    }

    // Ingress: upstream stdout → rehydrate result content → agent stdout.
    let ingress = {
        let vault = vault.clone();
        let ledger = ledger.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(from_upstream);
            let stdout = std::io::stdout();
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(mut msg) => {
                        if msg.pointer("/result/content").is_some() {
                            {
                                let v = vault.lock().expect("vault poisoned");
                                rehydrate_value(msg.pointer_mut("/result/content"), &v);
                            }
                            record_hop(&ledger, tenant, agent, Hop::McpToolResult, 0);
                        }
                        serde_json::to_string(&msg).unwrap_or(line)
                    }
                    Err(_) => line,
                };
                let mut w = stdout.lock();
                if w.write_all(out.as_bytes()).is_err()
                    || w.write_all(b"\n").is_err()
                    || w.flush().is_err()
                {
                    break;
                }
            }
        })
    };

    // Wait for the upstream to exit — either because the agent closed stdin (the
    // egress thread ended and dropped the upstream's stdin) or because it died.
    let _ = child.wait();
    // Drain the last of the upstream's output so the final response reaches the
    // agent before we return. Egress may still be parked on stdin; the process
    // exiting cleans it up.
    let _ = ingress.join();
    Ok(())
}

/// Pseudonymize every string leaf under `v`, returning the number of entities
/// masked. Uses the shared vault so the same original → same token (and so the
/// tokens rehydrate on the way back).
fn mask_value(v: Option<&mut Value>, detector: &Detector, vault: &mut Vault) -> usize {
    let Some(v) = v else { return 0 };
    match v {
        Value::String(s) => {
            let entities = detector.detect(s).unwrap_or_default();
            if entities.is_empty() {
                return 0;
            }
            match Replacer::pseudonymize(s, &entities, vault) {
                Ok(r) => {
                    *s = r.text;
                    entities.len()
                }
                Err(_) => 0,
            }
        }
        Value::Array(a) => a.iter_mut().map(|x| mask_value(Some(x), detector, vault)).sum(),
        Value::Object(o) => o
            .values_mut()
            .map(|x| mask_value(Some(x), detector, vault))
            .sum(),
        _ => 0,
    }
}

/// Restore pseudonym tokens back to their originals in every string leaf under
/// `v`. Non-token text is left untouched.
fn rehydrate_value(v: Option<&mut Value>, vault: &Vault) {
    let Some(v) = v else { return };
    match v {
        Value::String(s) => {
            if let Ok(r) = Rehydrator::rehydrate(s, vault) {
                *s = r.text;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| rehydrate_value(Some(x), vault)),
        Value::Object(o) => o.values_mut().for_each(|x| rehydrate_value(Some(x), vault)),
        _ => {}
    }
}

fn open_ledger(path: &str) -> SharedLedger {
    match LedgerStore::open(path) {
        Ok(s) => Some(Arc::new(Mutex::new(s))),
        Err(e) => {
            eprintln!("cloakpipe: MCP ledger open failed ({e}); evidence disabled");
            None
        }
    }
}

fn stable_ids() -> (uuid::Uuid, uuid::Uuid) {
    let ns = uuid::Uuid::NAMESPACE_URL;
    (
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-tenant"),
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-agent"),
    )
}

/// Append a no-PII hop record (categories/count only, never text). Best-effort.
fn record_hop(ledger: &SharedLedger, tenant: uuid::Uuid, agent: uuid::Uuid, hop: Hop, count: usize) {
    let Some(ledger) = ledger else { return };
    let Ok(mut store) = ledger.lock() else { return };
    let next_seq = match store.head(&tenant) {
        Ok((head, _)) => head.map(|s| s + 1).unwrap_or(0),
        Err(_) => return,
    };
    let builder = RecordBuilder::new()
        .seq(next_seq)
        .tenant(tenant)
        .hop(hop)
        .detection(Detection {
            entity_type: "mcp".to_string(),
            count: count as u32,
            detector: cloakpipe_ledger::Detector::Regex,
        })
        .action(Action {
            entity_type: "mcp".to_string(),
            kind: ActionKind::Pseudonymize,
            token_ref: Some(uuid::Uuid::new_v4().to_string()),
        })
        .identities(Identity {
            agent_id: agent,
            human_principal: None,
            upstream: "mcp".to_string(),
            region: std::env::var("CLOAKPIPE_REGION").unwrap_or_else(|_| "local".to_string()),
        });
    if let Ok(mut record) = builder.build() {
        let _ = store.append(&tenant, &mut record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloakpipe_core::config::DetectionConfig;

    #[test]
    fn masks_tool_args_and_rehydrates_round_trip() {
        // Every DetectionConfig field has a serde default (emails on), so an
        // empty object deserializes to the default config.
        let config: DetectionConfig = serde_json::from_str("{}").unwrap();
        let detector = Detector::from_config(&config).unwrap();
        let mut vault = Vault::ephemeral();

        // A tools/call arguments object with PII in nested strings.
        let mut args = serde_json::json!({
            "to": "email alice@acme.com about invoice",
            "cc": ["bob@globex.com"],
            "count": 3
        });
        let masked = mask_value(Some(&mut args), &detector, &mut vault);
        assert!(masked >= 2, "masked the emails, got {masked}");

        let s = serde_json::to_string(&args).unwrap();
        assert!(!s.contains("alice@acme.com"), "raw PII must be gone: {s}");
        assert!(!s.contains("bob@globex.com"), "raw PII must be gone: {s}");

        // The tool echoes the (masked) args back in a result; rehydrate restores
        // the originals for the agent.
        let mut result = args.clone();
        rehydrate_value(Some(&mut result), &vault);
        let r = serde_json::to_string(&result).unwrap();
        assert!(r.contains("alice@acme.com"), "rehydrated original: {r}");
        assert!(r.contains("bob@globex.com"), "rehydrated original: {r}");
    }
}
