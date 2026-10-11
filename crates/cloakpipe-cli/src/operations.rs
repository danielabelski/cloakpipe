//! `cloakpipe operations list|reconcile`: the operator's view of the
//! side-effecting tool calls `mcp-proxy --operations-db` tracks
//! (docs/ACTION_BOUNDARY.md).
//!
//! MCP has no standard way to ask a tool whether a call it never answered
//! took effect, so an operation whose outcome is `unknown` waits for an
//! operator to check the system of record and reconcile it as `done` (a
//! retry replays) or `not-applied` (a retry runs).
//!
//! Exit codes follow `release`: 0 ok, 1 refused (no such operation, one
//! that is not pending, or an in_flight one without `--force`), 2 usage or
//! I/O error.

use crate::cert::{invalid, usage, Res};
use crate::release::{load_valid, EXIT_OK};
use clap::{Args, Subcommand};
use cloakpipe_mcp::operations::{OperationState, OperationStore, ReconcileError};
use serde_json::json;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum OperationsCommands {
    /// List tracked operations (JSON array), optionally only those in one state
    List(ListArgs),
    /// Settle an operation whose outcome is unknown, after checking the system of record
    Reconcile(ReconcileArgs),
}

#[derive(Args)]
pub struct ListArgs {
    /// Only operations in this state
    #[arg(long, value_parser = ["in_flight", "done", "failed", "unknown", "not_applied"])]
    pub state: Option<String>,
    /// Operations database (default: $CLOAKPIPE_OPERATIONS_DB)
    #[arg(long = "operations-db")]
    pub operations_db: Option<PathBuf>,
}

#[derive(Args)]
pub struct ReconcileArgs {
    /// The operation id (from `operations list` or the agent's error data)
    pub operation_id: String,
    /// What happened: done (it took effect) or not-applied (it did not)
    #[arg(long, value_parser = ["done", "not-applied"])]
    pub outcome: String,
    /// Operations database (default: $CLOAKPIPE_OPERATIONS_DB)
    #[arg(long = "operations-db")]
    pub operations_db: Option<PathBuf>,
    /// Evidence ledger to record the reconciliation in
    /// (default: $CLOAKPIPE_LEDGER_DB; none: not recorded)
    #[arg(long = "ledger-db")]
    pub ledger_db: Option<PathBuf>,
    /// Agent Release manifest the operation ran under: binds the ledger hop
    /// to its release
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Reconcile an in_flight operation (one a running gate may still get the
    /// reply to). Not needed for an unknown one.
    #[arg(long)]
    pub force: bool,
}

pub fn run(cmd: OperationsCommands) -> i32 {
    crate::cert::finish(match cmd {
        OperationsCommands::List(a) => list(&a),
        OperationsCommands::Reconcile(a) => reconcile(&a),
    })
}

fn env_path(arg: &Option<PathBuf>, var: &str) -> Option<PathBuf> {
    arg.clone().or_else(|| std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from))
}

/// Open an existing operations database; never creates one.
fn open(arg: &Option<PathBuf>) -> Res<OperationStore> {
    let path = env_path(arg, "CLOAKPIPE_OPERATIONS_DB")
        .ok_or_else(|| usage("no operations database: pass --operations-db or set CLOAKPIPE_OPERATIONS_DB"))?;
    if !path.is_file() {
        return Err(usage(format_args!("{}: no such operations database", path.display())));
    }
    OperationStore::open(&path).map_err(|e| usage(format_args!("{}: {e}", path.display())))
}

fn list(a: &ListArgs) -> Res<i32> {
    let store = open(&a.operations_db)?;
    let state = a.state.as_deref().map(|s| s.parse::<OperationState>()).transpose().map_err(usage)?;
    // Ids, tools and states only: the call digest and the stored result stay
    // in the database.
    let rows = store.list(state).map_err(usage)?;
    let out: Vec<_> = rows
        .iter()
        .map(|r| json!({ "operationId": r.operation_id, "tool": r.tool, "state": r.state.as_str(), "updatedAt": r.updated_at }))
        .collect();
    println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
    Ok(EXIT_OK)
}

fn reconcile(a: &ReconcileArgs) -> Res<i32> {
    let outcome = match a.outcome.as_str() {
        "done" => OperationState::Done,
        _ => OperationState::NotApplied,
    };
    let release = match &a.manifest {
        Some(m) => Some(load_valid(m)?.manifest_hash().0),
        None => None,
    };
    let mut store = open(&a.operations_db)?;
    let previous = store
        .get(&a.operation_id)
        .map_err(usage)?
        .ok_or_else(|| invalid(format_args!("operation {}: no such operation", a.operation_id)))?
        .state;
    let ledger = env_path(&a.ledger_db, "CLOAKPIPE_LEDGER_DB").map(|p| p.to_string_lossy().into_owned());
    cloakpipe_mcp::reconcile_operation(&mut store, &a.operation_id, outcome, a.force, ledger.as_deref(), release).map_err(|e| match e {
        ReconcileError::NotFound
        | ReconcileError::NotPending(_)
        | ReconcileError::InFlight
        | ReconcileError::BadOutcome => {
            invalid(format_args!("operation {}: {e}", a.operation_id))
        }
        ReconcileError::Evidence(_) | ReconcileError::Store(_) => usage(format_args!("operation {}: {e}", a.operation_id)),
    })?;
    let report = json!({
        "operationId": a.operation_id,
        "previousState": previous.as_str(),
        "state": outcome.as_str(),
        "recorded": ledger.is_some(),
    });
    println!("{}", serde_json::to_string_pretty(&report).expect("JSON"));
    Ok(EXIT_OK)
}
