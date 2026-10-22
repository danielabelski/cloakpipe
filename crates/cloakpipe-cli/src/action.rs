//! `cloakpipe action fingerprint` and `cloakpipe approve`: signed approval
//! receipts for one exact tool call (docs/ACTION_BOUNDARY.md).
//!
//! Exit codes follow `release`: 0 ok, 1 invalid input (manifest, arguments,
//! task context, undeclared tool), 2 usage or I/O error.

use crate::cert::{invalid, now_arg, read, rfc3339, signing_key, usage, Res};
use crate::release::{load_valid, EXIT_OK};
use clap::{Args, Subcommand};
use cloakpipe_receipt::approval::{is_valid_operation_id, OPERATION_ID_FORBIDDEN, parse_json_strict, sign_approval, Approval};
use cloakpipe_release::action::{fingerprint, ToolCallFingerprint};
use cloakpipe_release::{AgentRelease, Reference};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub enum ActionCommands {
    /// Print the fingerprint of a tool call: what an approval receipt is about
    Fingerprint(FingerprintArgs),
}

#[derive(Args)]
pub struct FingerprintArgs {
    /// Agent Release manifest the call runs under
    #[arg(long)]
    pub manifest: PathBuf,
    /// Tool name, as in tools/call
    #[arg(long)]
    pub tool: String,
    /// JSON file holding the call's arguments exactly as the agent will send them
    #[arg(long = "args", value_name = "FILE")]
    pub arguments: PathBuf,
}

#[derive(Args)]
pub struct ApproveArgs {
    /// Agent Release manifest the call runs under
    #[arg(long)]
    pub manifest: PathBuf,
    /// Tool name, as in tools/call (must be declared by the manifest)
    #[arg(long)]
    pub tool: String,
    /// JSON file holding the call's arguments exactly as the agent will send them
    #[arg(long = "args", value_name = "FILE")]
    pub arguments: PathBuf,
    /// The trusted task context the gate will run with (its taskId is signed)
    #[arg(long = "task-context", value_name = "FILE")]
    pub task_context: PathBuf,
    /// Approver signing key (from `cloakpipe release keygen`)
    #[arg(long)]
    pub key: PathBuf,
    /// How long the approval stays valid: <n>s, <n>m, <n>h or <n>d
    #[arg(long, default_value = "15m")]
    pub expires: String,
    /// Operation id the call performs (default: a fresh UUID v4)
    #[arg(long = "operation-id")]
    pub operation_id: Option<String>,
    /// Approval time, RFC 3339 (default: now)
    #[arg(long)]
    pub now: Option<String>,
    /// Directory to write <fingerprint hex>.approval.json into (created if missing)
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(cmd: ActionCommands) -> i32 {
    match cmd {
        ActionCommands::Fingerprint(a) => crate::cert::finish(fingerprint_cmd(&a)),
    }
}

pub fn approve(a: ApproveArgs) -> i32 {
    crate::cert::finish(approve_inner(&a))
}

/// The manifest and the fingerprint of the call `tool(arguments file)`.
fn call(manifest: &Path, tool: &str, arguments: &Path) -> Res<(AgentRelease, ToolCallFingerprint)> {
    let m = load_valid(manifest)?;
    let src = read(arguments)?;
    let arguments: Value =
        parse_json_strict(&src).map_err(|e| invalid(format_args!("--args {}: not JSON: {e}", arguments.display())))?;
    let fp = fingerprint(&m.manifest_hash(), tool, &arguments);
    Ok((m, fp))
}

fn fingerprint_cmd(a: &FingerprintArgs) -> Res<i32> {
    let (_, fp) = call(&a.manifest, &a.tool, &a.arguments)?;
    println!("{fp}");
    Ok(EXIT_OK)
}

/// `<n>s|m|h|d`, positive.
fn duration(s: &str) -> Option<chrono::Duration> {
    let (n, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: i64 = n.parse().ok().filter(|n| *n > 0)?;
    match unit {
        "s" => chrono::Duration::try_seconds(n),
        "m" => chrono::Duration::try_minutes(n),
        "h" => chrono::Duration::try_hours(n),
        "d" => chrono::Duration::try_days(n),
        _ => None,
    }
}

fn approve_inner(a: &ApproveArgs) -> Res<i32> {
    let expires = duration(&a.expires)
        .ok_or_else(|| usage(format_args!("--expires {:?}: expected a positive <n>s, <n>m, <n>h or <n>d", a.expires)))?;
    let operation_id = match &a.operation_id {
        Some(id) if is_valid_operation_id(id) => id.clone(),
        Some(id) => {
            return Err(usage(format_args!(
                "--operation-id {id:?}: expected 1-128 ASCII letters, digits, '-', '_', '.' or ':', \
                 without the evidence ledger's PII markers ({})",
                OPERATION_ID_FORBIDDEN.join(", ")
            )))
        }
        None => uuid::Uuid::new_v4().to_string(),
    };
    let now = now_arg(a.now.as_deref())?;
    let not_after = now.checked_add_signed(expires).ok_or_else(|| usage("--expires: out of range"))?;
    let (key, keyid) = signing_key(&a.key)?;
    let (m, fp) = call(&a.manifest, &a.tool, &a.arguments)?;
    let declared = m.spec.tools.iter().filter_map(|t| Reference::parse(&t.reference).ok()).any(|r| r.name == a.tool);
    if !declared {
        return Err(invalid(format_args!("tool {:?} is not declared by the release (spec.tools)", a.tool)));
    }
    let task_src = read(&a.task_context)?;
    let task = parse_json_strict(&task_src)
        .map_err(|e| invalid(format_args!("task context {}: not JSON: {e}", a.task_context.display())))?;
    let Some(task_id) = task.get("taskId").and_then(Value::as_str) else {
        return Err(invalid(format_args!("task context {}: needs a string taskId", a.task_context.display())));
    };

    let approval = Approval {
        release: m.manifest_hash().to_string(),
        tool: a.tool.clone(),
        task_id: task_id.to_string(),
        operation_id,
        approver: keyid.clone(),
        approved_at: rfc3339(now),
        not_after: rfc3339(not_after),
    };
    let envelope = sign_approval(&fp, &approval, &key, &keyid);
    let bytes = format!("{}\n", serde_json::to_string_pretty(&envelope).expect("serialisable"));
    std::fs::create_dir_all(&a.out).map_err(|e| usage(format_args!("cannot create {}: {e}", a.out.display())))?;
    let path = a.out.join(format!("{}.approval.json", fp.hex()));
    write_atomic(&path, bytes.as_bytes()).map_err(|e| usage(format_args!("cannot write {}: {e}", path.display())))?;

    let report = json!({
        "receipt": path.to_string_lossy(),
        "fingerprint": fp.to_string(),
        "digest": format!("sha256:{}", hex::encode(Sha256::digest(bytes.as_bytes()))),
        "operationId": approval.operation_id,
        "approver": approval.approver,
        "notAfter": approval.not_after,
    });
    println!("{}", serde_json::to_string_pretty(&report).expect("serialisable"));
    Ok(EXIT_OK)
}

/// Write via a temporary file and rename, so a gate never reads a partial receipt.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })
}
