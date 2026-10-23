//! The MCP tool gate's command line (`cloakpipe mcp-proxy --manifest …`).
//!
//! The gate runs on the Agent Release manifest and the tool contracts it
//! binds: the release is loaded and checked for what the gate reads
//! ([`cloakpipe_release::AgentRelease::gate_issues`]), not for certifiability,
//! so it needs no code, prompt, model or runtime pins.
//!
//! Legacy, `certification` cargo feature only (off by default): the
//! `--certification`, `--trust`, `--trust-key`, `--revoked-statement`,
//! `--revoked-key` and `--environment` flags, and a gate that refuses every
//! call unless the release holds a certification that verifies now.

use crate::cert::{invalid, read, trusted_key, usage, Res};
use crate::release::load;
use clap::Args;
use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_release::AgentRelease;
use std::path::{Path, PathBuf};

/// Transparently proxy an upstream MCP server. With `--manifest`, only the
/// tools the release declares may be called, with arguments its tool
/// contracts allow (the tool gate). Allowed calls are forwarded unchanged;
/// `--transform pii` masks PII in tool-call arguments and rehydrates
/// pseudonym tokens in results (needs a vault).
#[derive(Debug, Args)]
pub struct McpProxyArgs {
    /// Upstream MCP server command + args, e.g.
    /// --upstream "npx -y @modelcontextprotocol/server-filesystem /data"
    #[arg(long, required = true)]
    pub upstream: String,
    /// Agent Release manifest the agent runs as. Enables the tool gate:
    /// tools/call must name a tool the manifest declares.
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// DSSE certification envelope of the release. Without one, every
    /// tools/call is refused (enforce) or reported (warn).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub certification: Option<PathBuf>,
    /// Trusted signer key file (from `release keygen`; public part only).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub trust: Vec<PathBuf>,
    /// Trusted signer as KEYID=PUBHEX.
    #[cfg(feature = "certification")]
    #[arg(long = "trust-key")]
    pub trust_keys: Vec<String>,
    /// sha256 hex of a revoked certification statement.
    #[cfg(feature = "certification")]
    #[arg(long = "revoked-statement")]
    pub revoked_statements: Vec<String>,
    /// Key id of a revoked signer.
    #[cfg(feature = "certification")]
    #[arg(long = "revoked-key")]
    pub revoked_keys: Vec<String>,
    /// Environment the agent runs in; the certification must cover it
    /// (default: production).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub environment: Option<String>,
    /// enforce (default): refuse calls that fail the gate; warn: forward and
    /// report.
    #[arg(long, value_parser = ["enforce", "warn"])]
    pub gate: Option<String>,
    /// Tool contract (repeatable): argument-level rules for the tools it
    /// covers. Each must be bound by the release (`spec.policies` entry
    /// `policy:tool-contract/<name>@sha256:<digest>`), and every contract the
    /// release binds must be supplied, or the proxy refuses to start.
    #[arg(long = "tool-contract")]
    pub tool_contracts: Vec<PathBuf>,
    /// Trusted task context: a JSON object written by the orchestrator, e.g.
    /// {"taskId":"t-981","tenant":"demo-co"}. `bindTo: task.<key>` arguments
    /// must equal its values. Default: $CLOAKPIPE_TASK_CONTEXT.
    #[arg(long = "task-context")]
    pub task_context: Option<PathBuf>,
    /// Directory of approval receipts (`<fingerprint hex>.approval.json`, from
    /// `cloakpipe approve`) for tools whose contract has requiresApproval.
    /// Needs --approver-key.
    #[arg(long)]
    pub approvals: Option<PathBuf>,
    /// Approver key file (repeatable; from `release keygen`, public part
    /// only): receipts must be signed by one of these keys.
    #[arg(long = "approver-key")]
    pub approver_keys: Vec<PathBuf>,
    /// Operations database (SQLite) tracking side-effecting calls (contract
    /// tools with sideEffect: true): required when the contracts have any.
    /// Default: $CLOAKPIPE_OPERATIONS_DB. One proxy per database.
    #[arg(long = "operations-db")]
    pub operations_db: Option<PathBuf>,
    /// Opt-in transform of allowed calls. `pii`: pseudonymize PII in
    /// tool-call arguments before the tool sees them and rehydrate tokens in
    /// results, through the vault (CLOAKPIPE_VAULT_KEY, vault.path in the
    /// config). Default: none; arguments reach the tool as the agent sent
    /// them and no vault is used.
    #[arg(long, value_parser = ["pii"])]
    pub transform: Option<String>,
}

impl McpProxyArgs {
    /// Whether `--transform pii` was given.
    pub fn pii(&self) -> bool {
        self.transform.as_deref() == Some("pii")
    }

    /// Whether any gate flag is set: without `--manifest`, that would
    /// silently run ungated.
    fn any_gate_flag(&self) -> bool {
        #[cfg(feature = "certification")]
        let certification = self.certification.is_some()
            || !self.trust.is_empty()
            || !self.trust_keys.is_empty()
            || !self.revoked_statements.is_empty()
            || !self.revoked_keys.is_empty()
            || self.environment.is_some();
        #[cfg(not(feature = "certification"))]
        let certification = false;
        certification
            || self.gate.is_some()
            || !self.tool_contracts.is_empty()
            || self.task_context.is_some()
            || self.approvals.is_some()
            || !self.approver_keys.is_empty()
            || self.operations_db.is_some()
    }
}

/// Load the release the gate runs on and check what the gate reads from it.
/// Issues go to stderr.
fn load_release(path: &Path) -> Res<AgentRelease> {
    let release = load(path)?;
    let issues = release.gate_issues();
    if issues.is_empty() {
        return Ok(release);
    }
    for i in &issues {
        eprintln!("error: {}: {i}", path.display());
    }
    Err(invalid("the tool gate cannot run on this release"))
}

/// Build the tool gate for `mcp-proxy`; `Ok(None)` without `--manifest`.
/// Problems are reported on stderr.
pub(crate) fn gate_from_args(a: &McpProxyArgs) -> Res<Option<cloakpipe_mcp::ToolGate>> {
    let Some(manifest_path) = &a.manifest else {
        if a.any_gate_flag() {
            return Err(usage("release gate flags need --manifest (the release they are about)"));
        }
        return Ok(None);
    };
    let manifest = load_release(manifest_path)?;
    #[cfg(feature = "certification")]
    let certification = legacy::certification(a)?;
    let mode = match a.gate.as_deref() {
        Some("warn") => cloakpipe_mcp::GateMode::Warn,
        _ => cloakpipe_mcp::GateMode::Enforce,
    };
    let mut contracts = Vec::new();
    for p in &a.tool_contracts {
        let contract = cloakpipe_release::contract::ToolContract::parse_path(p).map_err(|e| match e {
            cloakpipe_release::contract::ContractError::Io(..) => usage(format_args!("--tool-contract: {e}")),
            _ => invalid(format_args!("--tool-contract {}: {e}", p.display())),
        })?;
        contracts.push(contract);
    }
    let task = task_context(a)?;
    let approvals = approvals(a)?;
    let gate = cloakpipe_mcp::ToolGate::new(mode, &manifest);
    #[cfg(feature = "certification")]
    let gate = gate.with_certification(&certification.environment, certification.envelope, certification.verify);
    // Refuse to start unless the contracts are exactly the ones the release binds.
    let mut gate = gate.with_contracts(contracts, task).map_err(usage)?;
    if let Some((dir, approvers)) = approvals {
        gate = gate.with_approvals(dir, approvers);
    }
    let operations_db = a
        .operations_db
        .clone()
        .or_else(|| std::env::var_os("CLOAKPIPE_OPERATIONS_DB").filter(|v| !v.is_empty()).map(PathBuf::from));
    if let Some(path) = operations_db {
        let store = cloakpipe_mcp::operations::OperationStore::open(&path)
            .map_err(|e| usage(format_args!("--operations-db {}: {e}", path.display())))?;
        gate = gate.with_operations(store).map_err(usage)?;
        for op in gate.recovered_operations() {
            eprintln!("warning: operation {op} was left in flight by a previous run: its outcome is unknown until reconciled (cloakpipe operations reconcile)");
        }
    }
    // A side-effect tool with no operations store must not run.
    gate.ready().map_err(usage)?;
    Ok(Some(gate))
}

/// Legacy (`certification` feature): the certification flags.
#[cfg(feature = "certification")]
mod legacy {
    use super::McpProxyArgs;
    use crate::cert::{inline_key, invalid, read, trusted_key, usage, Res};
    use cloakpipe_cert::statement::{Envelope, VerifyContext};
    use std::collections::BTreeSet;

    pub(super) struct Certification {
        pub environment: String,
        pub envelope: Option<Envelope>,
        pub verify: VerifyContext,
    }

    pub(super) fn certification(a: &McpProxyArgs) -> Res<Certification> {
        let mut revoked_statements = BTreeSet::new();
        for d in &a.revoked_statements {
            let hex = d.trim().trim_start_matches("sha256:").to_ascii_lowercase();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(usage(format_args!("--revoked-statement {d:?}: expected a sha256 hex digest")));
            }
            revoked_statements.insert(hex);
        }
        let mut trusted = a.trust_keys.iter().map(|k| inline_key(k)).collect::<Res<Vec<_>>>()?;
        for p in &a.trust {
            trusted.push(trusted_key(p)?);
        }
        let envelope = match &a.certification {
            None => {
                eprintln!("warning: no --certification: every tools/call fails the release gate");
                None
            }
            Some(p) => {
                if trusted.is_empty() {
                    eprintln!("warning: no trusted keys (--trust / --trust-key); the certification cannot verify");
                }
                let src = read(p)?;
                Some(
                    serde_json::from_str::<Envelope>(&src)
                        .map_err(|e| invalid(format_args!("{}: not a DSSE envelope: {e}", p.display())))?,
                )
            }
        };
        let verify = VerifyContext {
            trusted,
            revoked_statements,
            revoked_keys: a.revoked_keys.iter().cloned().collect(),
            ..Default::default()
        };
        let environment = a.environment.as_deref().unwrap_or("production").to_string();
        Ok(Certification { environment, envelope, verify })
    }
}

/// `--approvals` with its `--approver-key`s: both or neither, and the
/// directory must exist.
fn approvals(a: &McpProxyArgs) -> Res<Option<(PathBuf, Vec<TrustedKey>)>> {
    match (&a.approvals, a.approver_keys.is_empty()) {
        (None, true) => Ok(None),
        (None, false) => Err(usage("--approver-key needs --approvals (the receipts it verifies)")),
        (Some(_), true) => Err(usage("--approvals needs at least one --approver-key (who may approve)")),
        (Some(dir), false) => {
            if !dir.is_dir() {
                return Err(usage(format_args!("--approvals {}: not a directory", dir.display())));
            }
            let keys = a.approver_keys.iter().map(|p| trusted_key(p)).collect::<Res<Vec<_>>>()?;
            Ok(Some((dir.clone(), keys)))
        }
    }
}

/// The trusted task context: `--task-context`, else `$CLOAKPIPE_TASK_CONTEXT`.
/// It comes only from the operator, never from MCP messages.
fn task_context(a: &McpProxyArgs) -> Res<Option<serde_json::Value>> {
    let path = a
        .task_context
        .clone()
        .or_else(|| std::env::var_os("CLOAKPIPE_TASK_CONTEXT").filter(|v| !v.is_empty()).map(PathBuf::from));
    let Some(path) = path else { return Ok(None) };
    let src = read(&path)?;
    let task: serde_json::Value = serde_json::from_str(&src)
        .map_err(|e| invalid(format_args!("task context {}: not JSON: {e}", path.display())))?;
    if !task.is_object() {
        return Err(invalid(format_args!("task context {}: must be a JSON object", path.display())));
    }
    Ok(Some(task))
}
