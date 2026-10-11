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
    record::Identity, store::LedgerStore, Action, ActionKind, Detection, Hop, MetadataValue, RecordBuilder,
};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::gate::{GateMode, ToolGate};

/// Everything the interceptor needs beyond the upstream command.
pub struct ProxyContext {
    pub detector: Detector,
    pub vault: Vault,
    /// Evidence ledger DB path (`CLOAKPIPE_LEDGER_DB`); `None` disables recording.
    pub ledger_db: Option<String>,
    /// Agent Release manifest hash (`CLOAKPIPE_RELEASE`) every ledger hop is
    /// bound to; `None` records unbound hops.
    pub release: Option<[u8; 32]>,
    /// Phase C tool gate: when set, each `tools/call` must pass
    /// [`ToolGate::check`]. Refused calls (enforce mode) never reach the
    /// upstream; the agent gets a JSON-RPC error instead.
    pub gate: Option<ToolGate>,
}

/// JSON-RPC error code for a tool call the gate refused (server-defined range).
pub const TOOL_REFUSED: i64 = -32001;

type SharedLedger = Option<Arc<Mutex<LedgerStore>>>;

/// Run the interceptor: spawn `upstream` and pump JSON-RPC both ways. Returns
/// when the upstream exits (which happens when the agent closes stdin, or when
/// the upstream itself dies).
pub fn run_proxy(upstream: Vec<String>, ctx: ProxyContext) -> Result<()> {
    run_proxy_io(upstream, ctx, std::io::stdin(), std::io::stdout())
}

/// [`run_proxy`] with the agent side supplied by the caller instead of the
/// process's stdin/stdout, so the interceptor can be driven in-process.
pub fn run_proxy_io<R, W>(upstream: Vec<String>, ctx: ProxyContext, agent_in: R, agent_out: W) -> Result<()>
where
    R: std::io::Read + Send + 'static,
    W: Write + Send + 'static,
{
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
    let release = ctx.release;
    let gate = ctx.gate;
    // Both directions answer the agent: ingress relays upstream replies and
    // egress answers refused calls.
    let agent_out = Arc::new(Mutex::new(agent_out));

    // Egress: agent stdin → mask tools/call → upstream stdin.
    {
        let detector = detector.clone();
        let vault = vault.clone();
        let ledger = ledger.clone();
        let agent_out = agent_out.clone();
        std::thread::spawn(move || {
            let mut to_upstream = to_upstream; // owned: dropped (→ upstream stdin EOF) when this thread ends
            for line in BufReader::new(agent_in).lines() {
                let Ok(line) = line else { break };
                // With a gate, only a message the gate can read in full is
                // forwarded — as re-serialized here, never the raw line.
                if let Some(gate) = &gate {
                    if let Err((reason, code)) = screen(&line) {
                        record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, 0, ActionKind::Block, &[opaque("gate_denial", reason)]);
                        let refusal = serde_json::json!({
                            "jsonrpc": "2.0",
                            "id": Value::Null,
                            "error": {
                                "code": code,
                                "message": format!("message refused by CloakPipe: {reason}"),
                                "data": { "reason": reason, "release": gate.release() },
                            },
                        });
                        if write_line(&agent_out, &refusal.to_string()).is_err() {
                            break;
                        }
                        continue;
                    }
                }
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(mut msg) => {
                        if msg.get("method").and_then(Value::as_str) == Some("tools/call") {
                            // Ledger metadata for the forwarded call: a warn-mode
                            // violation, or the approval it was allowed on.
                            let mut evidence = Vec::new();
                            if let Some(gate) = &gate {
                                let tool = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
                                let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                // The raw arguments, as the agent sent them: masking
                                // happens only after the gate has passed the call.
                                let arguments = msg.pointer("/params/arguments");
                                match gate.authorize(tool, arguments, &now) {
                                    Ok(auth) => {
                                        if let Some(approved) = auth.approval {
                                            // The receipt's digest, never the call fingerprint
                                            // (a plain hash of the arguments).
                                            evidence.push(("approval", MetadataValue::Hash(approved.receipt_digest)));
                                            evidence.push(opaque("operation_id", &approved.operation_id));
                                        }
                                    }
                                    Err(denial) => {
                                        let code = denial.code();
                                        // A contract path comes from the contract, never
                                        // from the call, so it is safe to record.
                                        let path = denial.path().map(str::to_string);
                                        if gate.mode == GateMode::Enforce {
                                            let mut meta = vec![opaque("gate_denial", &code)];
                                            meta.extend(path.as_deref().map(|p| opaque("gate_path", p)));
                                            record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, 0, ActionKind::Block, &meta);
                                            // A notification (no id member) takes no response;
                                            // `"id": null` is a request and is answered.
                                            if let Some(id) = msg.get("id") {
                                                let mut data = serde_json::json!({ "reason": code, "tool": tool, "release": gate.release() });
                                                if let Some(path) = &path {
                                                    data["path"] = Value::String(path.clone());
                                                }
                                                let refusal = serde_json::json!({
                                                    "jsonrpc": "2.0",
                                                    "id": id,
                                                    "error": {
                                                        "code": TOOL_REFUSED,
                                                        "message": format!("tool call refused by CloakPipe: {code}"),
                                                        "data": data,
                                                    },
                                                });
                                                if write_line(&agent_out, &refusal.to_string()).is_err() {
                                                    break;
                                                }
                                            }
                                            continue;
                                        }
                                        tracing::warn!(reason = %code, "MCP tool call fails the release gate (warn mode: forwarded)");
                                        evidence.push(opaque("gate_violation", &code));
                                        evidence.extend(path.as_deref().map(|p| opaque("gate_path", p)));
                                    }
                                }
                            }
                            let masked = {
                                let mut v = vault.lock().expect("vault poisoned");
                                mask_value(msg.pointer_mut("/params/arguments"), &detector, &mut v)
                            };
                            if masked > 0 || !evidence.is_empty() {
                                record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, masked, ActionKind::Pseudonymize, &evidence);
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
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(mut msg) => {
                        if msg.pointer("/result/content").is_some() {
                            {
                                let v = vault.lock().expect("vault poisoned");
                                rehydrate_value(msg.pointer_mut("/result/content"), &v);
                            }
                            record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, ActionKind::Pseudonymize, &[]);
                        }
                        serde_json::to_string(&msg).unwrap_or(line)
                    }
                    Err(_) => line,
                };
                if write_line(&agent_out, &out).is_err() {
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

/// JSON-RPC members whose spelling must be exact. Some JSON decoders (Go's
/// `encoding/json`) match keys case-insensitively, so `"Method"` could reach
/// the upstream as a method the gate never saw.
const CANONICAL_KEYS: [&str; 6] = ["jsonrpc", "id", "method", "params", "result", "error"];
const CANONICAL_PARAMS: [&str; 2] = ["name", "arguments"];

/// Can the gate read this agent message in full? Refuses (reason, JSON-RPC
/// code) anything else: text serde_json rejects but a laxer upstream might
/// accept (out-of-range numbers, lone surrogates, deep nesting), batches,
/// non-objects, and case variants of JSON-RPC member names.
fn screen(line: &str) -> Result<(), (&'static str, i64)> {
    const PARSE_ERROR: i64 = -32700;
    const INVALID_REQUEST: i64 = -32600;
    let msg: Value = serde_json::from_str(line).map_err(|_| ("unreadable", PARSE_ERROR))?;
    let obj = match &msg {
        Value::Object(o) => o,
        Value::Array(_) => return Err(("batch", INVALID_REQUEST)),
        _ => return Err(("not_an_object", INVALID_REQUEST)),
    };
    fn noncanonical(map: &serde_json::Map<String, Value>, canonical: &[&str]) -> bool {
        map.keys().any(|k| {
            let folded = fold(k);
            canonical.iter().any(|c| folded == *c && k.as_str() != *c)
        })
    }
    if noncanonical(obj, &CANONICAL_KEYS) {
        return Err(("noncanonical", INVALID_REQUEST));
    }
    if let Some(Value::Object(params)) = obj.get("params") {
        if noncanonical(params, &CANONICAL_PARAMS) {
            return Err(("noncanonical", INVALID_REQUEST));
        }
    }
    Ok(())
}

/// Case-fold as lax decoders do (ASCII plus the two non-ASCII letters that
/// fold to ASCII: U+017F long s and U+212A Kelvin sign).
fn fold(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c,
        })
        .collect::<String>()
        .to_lowercase()
}

/// Write one JSON-RPC line to the agent.
fn write_line<W: Write>(out: &Mutex<W>, line: &str) -> std::io::Result<()> {
    let mut w = out.lock().map_err(|_| std::io::Error::other("agent writer poisoned"))?;
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
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

/// The fixed `(tenant, agent)` ids the interceptor records ledger hops under.
pub fn stable_ids() -> (uuid::Uuid, uuid::Uuid) {
    let ns = uuid::Uuid::NAMESPACE_URL;
    (
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-tenant"),
        uuid::Uuid::new_v5(&ns, b"cloakpipe-mcp-agent"),
    )
}

/// A string metadata entry (reason codes, contract paths, operation ids).
fn opaque(key: &'static str, value: &str) -> (&'static str, MetadataValue) {
    (key, MetadataValue::OpaqueId(value.to_string()))
}

/// Append a no-PII hop record (categories/count only, never text). Best-effort.
/// `gate` adds metadata entries: the primary one first (a gate reason code,
/// or the approval receipt digest), then optional detail (`gate_path`,
/// `operation_id`). Should the ledger's PII check refuse the detail (a
/// contract property named `phone`, say), the hop is recorded with the
/// primary entry alone rather than lost.
#[allow(clippy::too_many_arguments)]
fn record_hop(
    ledger: &SharedLedger,
    tenant: uuid::Uuid,
    agent: uuid::Uuid,
    release: Option<[u8; 32]>,
    hop: Hop,
    count: usize,
    kind: ActionKind,
    gate: &[(&str, MetadataValue)],
) {
    let Some(ledger) = ledger else { return };
    let Ok(mut store) = ledger.lock() else {
        tracing::warn!(hop = ?hop, "evidence ledger: lock poisoned; MCP hop not recorded");
        return;
    };
    let next_seq = match store.head(&tenant) {
        Ok((head, _)) => head.map(|s| s + 1).unwrap_or(0),
        Err(e) => {
            tracing::warn!(hop = ?hop, "evidence ledger: cannot read chain head; MCP hop not recorded: {e}");
            return;
        }
    };
    let build = |entries: &[(&str, MetadataValue)]| {
        let mut builder = RecordBuilder::new()
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
                kind,
                token_ref: Some(uuid::Uuid::new_v4().to_string()),
            })
            .identities(Identity {
                agent_id: agent,
                human_principal: None,
                upstream: "mcp".to_string(),
                region: std::env::var("CLOAKPIPE_REGION").unwrap_or_else(|_| "local".to_string()),
            });
        if let Some(release) = release {
            builder = builder.release(release);
        }
        for (key, value) in entries {
            builder = builder.metadata(*key, value.clone());
        }
        builder.build()
    };
    let record = match build(gate) {
        Err(e) if gate.len() > 1 => {
            tracing::warn!(hop = ?hop, "evidence ledger: gate detail refused ({e}); recording the reason code only");
            build(&gate[..1])
        }
        other => other,
    };
    let appended = record
        .map_err(|e| e.to_string())
        .and_then(|mut record| store.append(&tenant, &mut record).map(|_| ()).map_err(|e| e.to_string()));
    if let Err(e) = appended {
        // Payload-free: the hop kind and error only, never message content.
        tracing::warn!(hop = ?hop, "evidence ledger: failed to record MCP hop: {e}");
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
