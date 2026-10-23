//! Transparent MCP interceptor.
//!
//! Sits between an MCP client (the agent) and an upstream MCP server, speaking
//! MCP's newline-delimited JSON-RPC in both directions. By default it forwards
//! what the agent sent: the gate allows or refuses a call, and never rewrites
//! an allowed one.
//!
//! With the opt-in PII transform ([`ProxyContext::pii`], `mcp-proxy
//! --transform pii`):
//!
//!   agent ──stdin──▶ [ mask tools/call args ] ──▶ upstream stdin
//!   agent ◀─stdout── [ rehydrate result tokens ] ◀── upstream stdout
//!
//! so PII never reaches the (possibly external) tool, and pseudonym tokens the
//! tool echoes back are restored before the agent sees them. Every masked or
//! gated call and every result appends a no-PII evidence-ledger hop
//! (`McpToolCall` / `McpToolResult`) — categories + counts only, never the text.
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
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use crate::gate::{Denial, GateMode, OperationKey, ToolGate};
use crate::operations::{Begin, OperationState, OperationStore, ReconcileError};

/// The opt-in PII transform (`mcp-proxy --transform pii`): tool-call
/// arguments are pseudonymized through `vault` before the tool sees them,
/// and tokens in results are rehydrated before the agent does.
pub struct PiiTransform {
    pub detector: Detector,
    pub vault: Vault,
}

/// Everything the interceptor needs beyond the upstream command.
pub struct ProxyContext {
    /// The PII transform; `None` (the default) forwards arguments and
    /// results unchanged and needs no vault.
    pub pii: Option<PiiTransform>,
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

/// JSON-RPC error code for a side-effecting call whose earlier attempt has
/// no settled outcome (`reconcile_before_retry`, `operation_unknown`): an
/// operator must reconcile the operation before it may run again.
pub const RECONCILE_REQUIRED: i64 = -32002;

type SharedLedger = Option<Arc<Mutex<LedgerStore>>>;
/// The PII transform as both pump threads share it.
type SharedPii = Option<Arc<(Detector, Mutex<Vault>)>>;
type SharedOperations = Option<Arc<Mutex<OperationStore>>>;
/// Side-effecting calls forwarded and not yet answered.
#[derive(Default)]
struct PendingOps {
    /// JSON-RPC request id (serialized) -> operation id.
    by_request: HashMap<String, String>,
    /// Other agent requests forwarded and not yet answered: request id
    /// (serialized) -> how many. A side-effecting call may not reuse one of
    /// these ids, nor any request reuse the id of a call in `by_request`, so
    /// a reply always maps to the request it answers.
    outstanding: HashMap<String, usize>,
    /// Set by the exit sweep: no call may start after it.
    closed: bool,
}
type Pending = Arc<Mutex<PendingOps>>;

/// What the coordinator decided for a side-effecting call.
enum Coordinated {
    /// Forward it; the operation is in flight under this request id.
    Forward,
    /// Answer with this (stored, rehydrated) result instead of forwarding.
    Replay(Value),
    /// Refuse it.
    Deny(Denial),
}

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
    if let Some(gate) = &ctx.gate {
        // A side-effect tool without an operations store must not run.
        gate.ready()?;
        if ctx.pii.is_none() {
            refuse_masked_results(gate)?;
        }
    }

    let mut child = Command::new(&upstream[0])
        .args(&upstream[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // upstream logs pass through to our stderr
        .spawn()
        .with_context(|| format!("failed to spawn upstream MCP server: {upstream:?}"))?;

    let to_upstream = child.stdin.take().context("upstream has no stdin")?;
    let from_upstream = child.stdout.take().context("upstream has no stdout")?;

    let pii: SharedPii = ctx.pii.map(|p| Arc::new((p.detector, Mutex::new(p.vault))));
    let ledger: SharedLedger = ctx.ledger_db.as_deref().and_then(open_ledger);
    let (tenant, agent) = stable_ids();
    let release = ctx.release;
    let gate = ctx.gate;
    let operations: SharedOperations = gate.as_ref().and_then(ToolGate::operations);
    let pending: Pending = Arc::new(Mutex::new(PendingOps::default()));
    // Evidence for the start-up sweep: operations a previous process left in
    // flight are now unknown.
    for op in gate.as_ref().map(|g| g.recovered_operations().to_vec()).unwrap_or_default() {
        record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, ActionKind::Passthrough, &operation_meta(OperationState::Unknown, &op));
    }
    // Both directions answer the agent: ingress relays upstream replies and
    // egress answers refused calls.
    let agent_out = Arc::new(Mutex::new(agent_out));

    // Egress: agent stdin → (mask tools/call) → upstream stdin.
    {
        let pii = pii.clone();
        let ledger = ledger.clone();
        let agent_out = agent_out.clone();
        let operations = operations.clone();
        let pending = pending.clone();
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
                        // An agent request (any method) reusing the id of a
                        // side-effecting call in flight: its reply would be
                        // taken for the call's and settle the operation.
                        let request_id = msg.get("method").and(msg.get("id")).filter(|id| !id.is_null()).map(Value::to_string);
                        if let (Some(gate), Some(_), Some(request)) = (&gate, &operations, &request_id) {
                            let in_use = pending.lock().map(|p| p.by_request.contains_key(request)).unwrap_or(true);
                            if in_use {
                                let code = Denial::RequestIdInUse.code();
                                record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, 0, ActionKind::Block, &[opaque("gate_denial", &code)]);
                                let refusal = serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": msg.get("id"),
                                    "error": {
                                        "code": TOOL_REFUSED,
                                        "message": format!("message refused by CloakPipe: {code}"),
                                        "data": { "reason": code, "release": gate.release() },
                                    },
                                });
                                if write_line(&agent_out, &refusal.to_string()).is_err() {
                                    break;
                                }
                                continue;
                            }
                        }
                        if msg.get("method").and_then(Value::as_str) == Some("tools/call") {
                            // Ledger metadata for the forwarded call: a warn-mode
                            // violation, the approval it was allowed on, the operation.
                            let mut evidence = Vec::new();
                            if let Some(gate) = &gate {
                                let tool = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("").to_string();
                                let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                // The raw arguments, as the agent sent them: the PII
                                // transform runs only after the gate has passed the call.
                                let arguments = msg.pointer("/params/arguments");
                                // A refusal, and whether it holds in warn mode too.
                                let mut refusal: Option<(Denial, bool)> = None;
                                let mut replay: Option<(Value, String)> = None;
                                // The operation this call is, if it is side-effecting.
                                let mut operation = None;
                                let mut approved = false;
                                match gate.authorize(&tool, arguments, &now) {
                                    Ok(auth) => {
                                        if let Some(a) = &auth.approval {
                                            // The receipt's digest, never the call fingerprint
                                            // (a plain hash of the arguments).
                                            evidence.push(("approval", MetadataValue::Hash(a.receipt_digest)));
                                            evidence.push(opaque("operation_id", &a.operation_id));
                                            approved = true;
                                        }
                                        operation = auth.operation;
                                    }
                                    Err(denial) => {
                                        // Warn mode forwards it: a side-effecting call is
                                        // still an operation (tracking is not a release rule).
                                        if gate.mode == GateMode::Warn {
                                            match gate.operation(&tool, arguments, &now) {
                                                Ok(op) => operation = op,
                                                Err(d) => refusal = Some((d, true)),
                                            }
                                        }
                                        refusal = refusal.or(Some((denial, false)));
                                    }
                                }
                                let forwarding = match &refusal {
                                    None => true,
                                    Some((_, always)) => !always && gate.mode == GateMode::Warn,
                                };
                                if let Some(op) = operation.as_ref().filter(|_| forwarding) {
                                    if !approved {
                                        evidence.push(opaque("operation_id", &op.operation_id));
                                    }
                                    // Exactly-once bookkeeping is not a release rule:
                                    // it holds in warn mode too.
                                    match coordinate(&operations, &pending, &pii, msg.get("id"), &tool, op) {
                                        Coordinated::Forward => {}
                                        Coordinated::Replay(result) => replay = Some((result, op.operation_id.clone())),
                                        Coordinated::Deny(d) => refusal = Some((d, true)),
                                    }
                                }
                                if let Some((result, operation_id)) = replay {
                                    // Already done: answer with the stored result and
                                    // never run the effect again.
                                    let mut meta = operation_meta(OperationState::Done, &operation_id);
                                    meta.push(("operation_replayed", MetadataValue::Bool(true)));
                                    record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, ActionKind::Passthrough, &meta);
                                    if let Some(id) = msg.get("id") {
                                        let reply = serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result });
                                        if write_line(&agent_out, &reply.to_string()).is_err() {
                                            break;
                                        }
                                    }
                                    continue;
                                }
                                if let Some((denial, always)) = refusal {
                                    let code = denial.code();
                                    // A contract path comes from the contract, never
                                    // from the call, so it is safe to record.
                                    let path = denial.path().map(str::to_string);
                                    if always || gate.mode == GateMode::Enforce {
                                        let mut meta = vec![opaque("gate_denial", &code)];
                                        meta.extend(denial.operation_id().map(|o| opaque("operation_id", o)));
                                        meta.extend(path.as_deref().map(|p| opaque("gate_path", p)));
                                        record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, 0, ActionKind::Block, &meta);
                                        // A notification (no id member) takes no response;
                                        // `"id": null` is a request and is answered.
                                        if let Some(id) = msg.get("id") {
                                            let mut data = serde_json::json!({ "reason": code, "tool": tool, "release": gate.release() });
                                            if let Some(path) = &path {
                                                data["path"] = Value::String(path.clone());
                                            }
                                            if let Some(op) = denial.operation_id() {
                                                data["operationId"] = Value::String(op.to_string());
                                            }
                                            let rpc_code = match denial {
                                                Denial::ReconcileBeforeRetry { .. } => RECONCILE_REQUIRED,
                                                _ => TOOL_REFUSED,
                                            };
                                            let refusal = serde_json::json!({
                                                "jsonrpc": "2.0",
                                                "id": id,
                                                "error": {
                                                    "code": rpc_code,
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
                            // Only the opt-in PII transform rewrites an allowed call.
                            let (masked, kind) = match &pii {
                                Some(pii) => {
                                    let (detector, vault) = &**pii;
                                    let mut v = vault.lock().expect("vault poisoned");
                                    (mask_value(msg.pointer_mut("/params/arguments"), detector, &mut v), ActionKind::Pseudonymize)
                                }
                                None => (0, ActionKind::Passthrough),
                            };
                            if masked > 0 || !evidence.is_empty() {
                                record_hop(&ledger, tenant, agent, release, Hop::McpToolCall, masked, kind, &evidence);
                            }
                        }
                        // Every other forwarded request is outstanding until
                        // answered (a side-effecting call is in `by_request`).
                        if let (Some(_), Some(request)) = (&operations, request_id) {
                            if let Ok(mut p) = pending.lock() {
                                if !p.by_request.contains_key(&request) {
                                    *p.outstanding.entry(request).or_default() += 1;
                                }
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

    // Ingress: upstream stdout → (rehydrate result content) → agent stdout.
    let ingress = {
        let pii = pii.clone();
        let ledger = ledger.clone();
        let agent_out = agent_out.clone();
        let operations = operations.clone();
        let pending = pending.clone();
        std::thread::spawn(move || {
            let reader = BufReader::new(from_upstream);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let out = match serde_json::from_str::<Value>(&line) {
                    Ok(mut msg) => {
                        // The reply to a side-effecting call settles its operation
                        // before the agent sees it.
                        let settled = settle_reply(&operations, &pending, &msg, pii.is_some());
                        let kind = match &pii {
                            Some(pii) => {
                                if msg.pointer("/result/content").is_some() {
                                    let v = pii.1.lock().expect("vault poisoned");
                                    rehydrate_value(msg.pointer_mut("/result/content"), &v);
                                }
                                ActionKind::Pseudonymize
                            }
                            None => ActionKind::Passthrough,
                        };
                        if let Some((operation_id, state)) = settled {
                            record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, kind, &operation_meta(state, &operation_id));
                        } else if msg.pointer("/result/content").is_some() {
                            record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, kind, &[]);
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

    // Exit sweep: a side-effecting call still in flight never got its reply.
    // The tool may or may not have acted, so its operation is unknown until
    // an operator reconciles it; the agent is told so.
    let abandoned: Vec<(String, String)> = match pending.lock() {
        Ok(mut p) => {
            p.closed = true;
            p.by_request.drain().collect()
        }
        Err(_) => Vec::new(),
    };
    for (request, operation_id) in abandoned {
        // Only a row this sweep changed is evidence of `unknown`. An
        // operation an operator reconciled meanwhile keeps its verdict and
        // gets no `unknown` hop, but its request is still answered (an MCP
        // client must never wait forever), with the reconciled state. A row
        // the store could not write stays in flight (a restart sweeps and
        // records it); its outcome is still unknown to the agent.
        let swept = match operations.as_ref().map(|s| s.lock()) {
            Some(Ok(mut s)) => match s.settle(&operation_id, OperationState::Unknown, None) {
                Ok(true) => Ok(None),
                Ok(false) => s.get(&operation_id).map(|row| row.map(|r| r.state)).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            },
            _ => Err("lock poisoned".to_string()),
        };
        let (reason, message, state) = match swept {
            Ok(Some(state)) => {
                tracing::info!("operations store: {operation_id} was reconciled meanwhile ({state}); left as is");
                ("operation_reconciled", format!("the tool server went away before answering; an operator reconciled this call as {state}"), Some(state))
            }
            Ok(None) => {
                record_hop(&ledger, tenant, agent, release, Hop::McpToolResult, 0, ActionKind::Passthrough, &operation_meta(OperationState::Unknown, &operation_id));
                ("operation_unknown", "the tool server went away before answering: the outcome of this call is unknown".to_string(), None)
            }
            Err(e) => {
                tracing::warn!("operations store: could not mark {operation_id} unknown ({e}); a restart will");
                ("operation_unknown", "the tool server went away before answering: the outcome of this call is unknown".to_string(), None)
            }
        };
        let id: Value = serde_json::from_str(&request).unwrap_or(Value::Null);
        let mut data = serde_json::json!({ "reason": reason, "operationId": operation_id });
        if let Some(state) = state {
            data["state"] = Value::String(state.as_str().to_string());
        }
        let notice = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": RECONCILE_REQUIRED, "message": message, "data": data },
        });
        let _ = write_line(&agent_out, &notice.to_string());
    }
    // The gate has stopped: give the operations database up now, even if the
    // egress thread (still parked on the agent's stdin) holds the store.
    if let Some(Ok(mut s)) = operations.as_ref().map(|s| s.lock()) {
        s.release_gate();
    }
    Ok(())
}

/// Without the PII transform, refuse to run on an operations database that
/// holds masked results (stored under the transform, or by an earlier
/// version, which always masked): a retry would replay pseudonym tokens the
/// agent cannot read, and only the vault they came from can restore them.
fn refuse_masked_results(gate: &ToolGate) -> Result<()> {
    let Some(store) = gate.operations() else { return Ok(()) };
    let masked = store
        .lock()
        .map_err(|_| anyhow::anyhow!("operations store lock poisoned"))?
        .masked_results()?;
    if masked.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "the operations database holds {} completed operation(s) whose stored results are masked \
         (pseudonym tokens from the PII transform, which earlier versions always applied), e.g. {}. \
         A retry would replay them to the agent unreadable. Start with --transform pii and the \
         vault they were masked with (CLOAKPIPE_VAULT_KEY and the configured vault path) so \
         replays are rehydrated, or give this proxy a new --operations-db",
        masked.len(),
        masked[0]
    )
}

/// Run a side-effecting call through the operations store, in one
/// transaction: forward it (now `in_flight` under its request id), replay a
/// `done` operation's stored result, or refuse it.
fn coordinate(
    operations: &SharedOperations,
    pending: &Pending,
    pii: &SharedPii,
    id: Option<&Value>,
    tool: &str,
    op: &OperationKey,
) -> Coordinated {
    let Some(store) = operations else { return Coordinated::Deny(Denial::OperationsUnavailable) };
    // Without a request id the reply could never settle the operation.
    let Some(id) = id.filter(|id| !id.is_null()) else { return Coordinated::Deny(Denial::RequestIdMissing) };
    let request = id.to_string();
    // `pending` is never held across the store: `begin` may wait (up to the
    // busy timeout) for an operator's `operations reconcile`, and the reply
    // thread needs `pending` for every upstream reply. Checking the request
    // id, then deciding, then registering it is still race-free: only this
    // (egress) thread adds request ids, and nothing is forwarded until this
    // returns, so no reply to this request can arrive in between. Only the
    // exit sweep can close `pending` meanwhile; that is checked again below.
    {
        let Ok(pending) = pending.lock() else { return Coordinated::Deny(Denial::OperationsUnavailable) };
        if pending.closed {
            return Coordinated::Deny(Denial::OperationsUnavailable);
        }
        if pending.by_request.contains_key(&request) || pending.outstanding.contains_key(&request) {
            return Coordinated::Deny(Denial::RequestIdInUse);
        }
    }
    let decision = match store.lock() {
        Ok(mut s) => s.begin(&op.operation_id, tool, &op.fingerprint.0),
        Err(_) => return Coordinated::Deny(Denial::OperationsUnavailable),
    };
    match decision {
        Ok(Begin::Forward) => {
            let registered = match pending.lock() {
                Ok(mut p) if !p.closed => {
                    p.by_request.insert(request, op.operation_id.clone());
                    true
                }
                _ => false,
            };
            if registered {
                return Coordinated::Forward;
            }
            // The proxy is shutting down: the call is never forwarded, so it
            // certainly did not run and may be retried.
            if let Ok(mut s) = store.lock() {
                if let Err(e) = s.settle(&op.operation_id, OperationState::Failed, None) {
                    tracing::warn!("operations store: could not release unsent {} ({e}); a restart marks it unknown", op.operation_id);
                }
            }
            Coordinated::Deny(Denial::OperationsUnavailable)
        }
        Ok(Begin::Replay { result, masked }) => {
            // A masked result is replayed only through the vault (start-up
            // refuses a database holding one without the transform).
            let vault = match (masked, pii) {
                (false, _) => None,
                (true, Some(pii)) => Some(&pii.1),
                (true, None) => {
                    tracing::warn!("operations store: {} holds a masked result and no vault is configured; refused", op.operation_id);
                    return Coordinated::Deny(Denial::OperationsUnavailable);
                }
            };
            match replayed(result.as_deref(), &op.operation_id, vault) {
                Some(result) => Coordinated::Replay(result),
                None => Coordinated::Deny(Denial::OperationsUnavailable),
            }
        }
        Ok(Begin::Conflict) => Coordinated::Deny(Denial::OperationConflict { operation_id: op.operation_id.clone() }),
        Ok(Begin::ReconcileBeforeRetry(_)) => {
            Coordinated::Deny(Denial::ReconcileBeforeRetry { operation_id: op.operation_id.clone() })
        }
        Err(e) => {
            tracing::warn!("operations store: {e}; side-effecting call refused");
            Coordinated::Deny(Denial::OperationsUnavailable)
        }
    }
}

/// The answer for a retry of a `done` operation: its stored result (a masked
/// one rehydrated through `vault`, as the ingress path does), marked
/// `_meta.cloakpipe.replayed`.
/// An operation an operator reconciled as done has no stored result: the
/// agent is told it completed. `None`: the stored result is unreadable.
fn replayed(stored: Option<&str>, operation_id: &str, vault: Option<&Mutex<Vault>>) -> Option<Value> {
    let mut result = match stored {
        Some(stored) => serde_json::from_str::<Value>(stored).ok().filter(Value::is_object)?,
        None => serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!("This call already completed (operation {operation_id}, reconciled by an operator); it was not run again."),
            }],
        }),
    };
    if let Some(vault) = vault.filter(|_| result.get("content").is_some()) {
        let v = vault.lock().ok()?;
        rehydrate_value(result.get_mut("content"), &v);
    }
    let meta = result.as_object_mut()?.entry("_meta").or_insert_with(|| serde_json::json!({}));
    let cloakpipe = meta.as_object_mut()?.entry("cloakpipe").or_insert_with(|| serde_json::json!({}));
    let cloakpipe = cloakpipe.as_object_mut()?;
    cloakpipe.insert("replayed".into(), Value::Bool(true));
    cloakpipe.insert("operationId".into(), Value::String(operation_id.to_string()));
    Some(result)
}

/// Settle the operation an upstream reply answers: a `result` without
/// `isError: true` is `done` (its result stored for replay; `masked`: under
/// the PII transform, so it holds pseudonym tokens); an
/// error result or a JSON-RPC `error` is `failed`. Returns the operation and
/// its new state, or `None` when the message answers no side-effecting call
/// or the store did not settle it (no longer `in_flight`, or unwritable).
/// Only a reply settles: a request or notification from the upstream
/// (`method`), or a message with neither `result` nor `error`, never does,
/// whatever its id.
fn settle_reply(operations: &SharedOperations, pending: &Pending, msg: &Value, masked: bool) -> Option<(String, OperationState)> {
    let store = operations.as_ref()?;
    if msg.get("method").is_some() || (msg.get("result").is_none() && msg.get("error").is_none()) {
        return None;
    }
    let request = msg.get("id")?.to_string();
    // `pending` is released before the store write, which may wait on the
    // database.
    let operation_id = {
        let mut pending = pending.lock().ok()?;
        let Some(operation_id) = pending.by_request.remove(&request) else {
            // The reply to another request: it is no longer outstanding.
            if let Some(n) = pending.outstanding.get_mut(&request) {
                *n -= 1;
                if *n == 0 {
                    pending.outstanding.remove(&request);
                }
            }
            return None;
        };
        operation_id
    };
    let result = msg.get("result").filter(|_| msg.get("error").is_none());
    let done = result.is_some_and(|r| r.get("isError") != Some(&Value::Bool(true)));
    let (state, stored) = if done {
        (OperationState::Done, result.map(Value::to_string))
    } else {
        (OperationState::Failed, None)
    };
    // Evidence of a settlement only when the store row did change: an
    // operation an operator reconciled meanwhile (or another process swept)
    // keeps its state, and the ledger must not claim otherwise.
    let settled = match store.lock() {
        Ok(mut s) => match if masked {
            s.settle_masked(&operation_id, state, stored.as_deref())
        } else {
            s.settle(&operation_id, state, stored.as_deref())
        } {
            Ok(changed) => {
                if !changed {
                    tracing::warn!("operations store: {operation_id} is no longer in flight; its reply settles nothing");
                }
                changed
            }
            Err(e) => {
                tracing::warn!("operations store: could not settle {operation_id} ({e}); a restart marks it unknown");
                false
            }
        },
        Err(_) => {
            tracing::warn!("operations store: lock poisoned; {operation_id} not settled");
            false
        }
    };
    settled.then_some((operation_id, state))
}

/// Ledger metadata naming an operation and its state.
fn operation_meta(state: OperationState, operation_id: &str) -> Vec<(&'static str, MetadataValue)> {
    vec![opaque("operation_id", operation_id), opaque("operation_state", state.as_str())]
}

/// An operator's verdict on an operation whose outcome is unknown
/// (`cloakpipe operations reconcile`): `done` (a retry replays) or
/// `not_applied` (a retry runs); an `in_flight` one only with `force` (a
/// running gate may still get its reply). With a ledger, an `operation_reconciled`
/// hop (release-bound when `release` is given) is appended in the same
/// transaction: if it cannot be recorded, nothing changes.
pub fn reconcile_operation(
    store: &mut OperationStore,
    operation_id: &str,
    outcome: OperationState,
    force: bool,
    ledger_db: Option<&str>,
    release: Option<[u8; 32]>,
) -> Result<(), ReconcileError> {
    store.reconcile(operation_id, outcome, force, || {
        let Some(path) = ledger_db else { return Ok(()) };
        let mut ledger = LedgerStore::open(path).map_err(|e| e.to_string())?;
        let (tenant, agent) = stable_ids();
        append_hop(
            &mut ledger,
            tenant,
            agent,
            release,
            Hop::OperationReconciled,
            0,
            ActionKind::Passthrough,
            &operation_meta(outcome, operation_id),
        )
    })
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
    if let Err(e) = append_hop(&mut store, tenant, agent, release, hop, count, kind, gate) {
        // Payload-free: the hop kind and error only, never message content.
        tracing::warn!(hop = ?hop, "evidence ledger: failed to record MCP hop: {e}");
    }
}

/// [`record_hop`] on an open store, reporting failure.
#[allow(clippy::too_many_arguments)]
fn append_hop(
    store: &mut LedgerStore,
    tenant: uuid::Uuid,
    agent: uuid::Uuid,
    release: Option<[u8; 32]>,
    hop: Hop,
    count: usize,
    kind: ActionKind,
    gate: &[(&str, MetadataValue)],
) -> Result<(), String> {
    let next_seq = match store.head(&tenant) {
        Ok((head, _)) => head.map(|s| s + 1).unwrap_or(0),
        Err(e) => return Err(format!("cannot read chain head: {e}")),
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
    let mut record = record.map_err(|e| e.to_string())?;
    store.append(&tenant, &mut record).map(|_| ()).map_err(|e| e.to_string())
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
