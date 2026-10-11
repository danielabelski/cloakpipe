//! Operation identity and outcome states for side-effecting tool calls.
//!
//! A contract tool with `sideEffect: true` runs under a durable coordinator:
//! every call is an *operation* (its id comes from the approval receipt, or
//! is derived from the task and the call, see
//! [`cloakpipe_release::action::derive_operation_id`]) whose state lives in a
//! SQLite table the operator owns:
//!
//! ```sql
//! operations(operation_id TEXT PRIMARY KEY, tool TEXT, call_digest BLOB,
//!            state TEXT, result TEXT, updated_at TEXT)
//! ```
//!
//! `call_digest` is the call's fingerprint and `result` the masked result
//! JSON: local operator state, never ledger content. A one-row table
//! `operation_id_key(id, key)` holds the database's random key for derived
//! operation ids ([`OperationStore::operation_id_key`]).
//!
//! States: `in_flight` (forwarded, no reply yet), `done` (replied with a
//! result; replayed on a retry, never re-executed), `failed` (an error
//! reply; may be retried), `unknown` (the upstream went away before
//! replying: the effect may or may not have happened, so a retry is refused
//! until an operator reconciles it) and `not_applied` (reconciled as not
//! having happened; may be retried).
//!
//! One gate per operations database: a gate starting up takes an exclusive
//! OS lock on `<db>.lock` for as long as it runs, then marks every row left
//! `in_flight` as `unknown` ([`OperationStore::recover`]). A second gate on
//! the same database is refused instead of demoting the first one's live
//! operations; `operations list` and `operations reconcile` take no lock.

use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Where an operation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperationState {
    InFlight,
    Done,
    Failed,
    Unknown,
    NotApplied,
}

impl OperationState {
    /// The stable name stored in the table and recorded as `operation_state`.
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationState::InFlight => "in_flight",
            OperationState::Done => "done",
            OperationState::Failed => "failed",
            OperationState::Unknown => "unknown",
            OperationState::NotApplied => "not_applied",
        }
    }
}

impl std::fmt::Display for OperationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for OperationState {
    type Err = OperationsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "in_flight" => OperationState::InFlight,
            "done" => OperationState::Done,
            "failed" => OperationState::Failed,
            "unknown" => OperationState::Unknown,
            "not_applied" => OperationState::NotApplied,
            other => return Err(OperationsError(format!("unrecognised operation state {other:?}"))),
        })
    }
}

/// One row of the operations table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationRow {
    pub operation_id: String,
    pub tool: String,
    pub call_digest: [u8; 32],
    pub state: OperationState,
    /// The masked result JSON of a `done` operation the gate saw complete.
    pub result: Option<String>,
    /// RFC 3339 time of the last change.
    pub updated_at: String,
}

/// What to do with a call, decided in one `BEGIN IMMEDIATE` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// New (or retryable) operation, now `in_flight`: forward the call.
    Forward,
    /// Already `done`: answer with the stored (masked) result instead of
    /// forwarding. `None` when an operator reconciled it as done.
    Replay { result: Option<String> },
    /// The operation id names a different call.
    Conflict,
    /// The operation is `in_flight` or `unknown`: an operator must
    /// reconcile it before the call may run again.
    ReconcileBeforeRetry(OperationState),
}

/// A storage failure (unreadable database, unrecognised state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationsError(pub String);

impl std::fmt::Display for OperationsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operations store: {}", self.0)
    }
}

impl std::error::Error for OperationsError {}

impl From<rusqlite::Error> for OperationsError {
    fn from(e: rusqlite::Error) -> Self {
        OperationsError(e.to_string())
    }
}

/// Why `reconcile` refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// No such operation.
    NotFound,
    /// The operation is not `unknown` or `in_flight`.
    NotPending(OperationState),
    /// The operation is `in_flight` and `force` was not given: a running
    /// gate may still receive its reply.
    InFlight,
    /// The outcome is not `done` or `not_applied`.
    BadOutcome,
    /// The evidence for the reconciliation could not be written; nothing
    /// changed.
    Evidence(String),
    Store(OperationsError),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconcileError::NotFound => write!(f, "no such operation"),
            ReconcileError::NotPending(s) => {
                write!(f, "the operation is {s}; only an unknown or in_flight operation can be reconciled")
            }
            ReconcileError::InFlight => write!(
                f,
                "the operation is in_flight: a running gate may still be waiting for its reply, and a verdict \
                 now can contradict what the tool actually did. Check that no gate is running for this \
                 operation (or that the tool's system of record is final), then pass --force"
            ),
            ReconcileError::BadOutcome => write!(f, "the outcome must be done or not_applied"),
            ReconcileError::Evidence(e) => write!(f, "the reconciliation could not be recorded ({e}); nothing changed"),
            ReconcileError::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ReconcileError {}

impl From<rusqlite::Error> for ReconcileError {
    fn from(e: rusqlite::Error) -> Self {
        ReconcileError::Store(e.into())
    }
}

/// The operations table.
pub struct OperationStore {
    conn: Connection,
    path: PathBuf,
    /// The gate lock (`<db>.lock`, exclusive), held from [`Self::recover`]
    /// until [`Self::release_gate`] or drop.
    gate_lock: Option<File>,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

const COLUMNS: &str = "operation_id, tool, call_digest, state, result, updated_at";

/// A raw table row: operation_id, tool, call_digest, state, result, updated_at.
type RawRow = (String, String, Vec<u8>, String, Option<String>, String);

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
}

fn to_row(raw: RawRow) -> Result<OperationRow, OperationsError> {
    let (operation_id, tool, digest, state, result, updated_at) = raw;
    let call_digest: [u8; 32] = digest
        .try_into()
        .map_err(|_| OperationsError(format!("operation {operation_id}: call_digest is not 32 bytes")))?;
    Ok(OperationRow { state: state.parse()?, operation_id, tool, call_digest, result, updated_at })
}

impl OperationStore {
    /// Open (creating if needed) the operations database at `path`. Opening
    /// changes no row; a gate also calls [`Self::recover`].
    pub fn open(path: impl AsRef<Path>) -> Result<Self, OperationsError> {
        let path = path.as_ref().to_path_buf();
        let conn = Connection::open(&path)?;
        // The gate and `cloakpipe operations` may use the database at once.
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                tool TEXT,
                call_digest BLOB,
                state TEXT,
                result TEXT,
                updated_at TEXT
            );
            CREATE TABLE IF NOT EXISTS operation_id_key (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                key BLOB NOT NULL CHECK (length(key) = 32)
            );",
        )?;
        // A new database's key comes from the OS CSPRNG; a key already
        // stored (including one an earlier version made) is kept.
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        conn.execute("INSERT OR IGNORE INTO operation_id_key (id, key) VALUES (1, ?1)", params![&key[..]])?;
        Ok(Self { conn, path, gate_lock: None })
    }

    /// The lock file a running gate holds: `<db>.lock` beside the database.
    pub fn gate_lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    /// Take the database for this gate: an exclusive advisory lock on
    /// [`Self::gate_lock_path`], held until [`Self::release_gate`] or drop
    /// (or the process exits). Fails if another gate holds it.
    fn claim_for_gate(&mut self) -> Result<(), OperationsError> {
        if self.gate_lock.is_some() {
            return Ok(());
        }
        let lock_path = self.gate_lock_path();
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options
            .open(&lock_path)
            .map_err(|e| OperationsError(format!("cannot open gate lock {}: {e}", lock_path.display())))?;
        match file.try_lock() {
            Ok(()) => {
                self.gate_lock = Some(file);
                Ok(())
            }
            Err(TryLockError::WouldBlock) => Err(OperationsError(format!(
                "{} is in use by another gate (lock {} is held): one gate per operations database; \
                 stop the other mcp-proxy or give this one its own --operations-db",
                self.path.display(),
                lock_path.display()
            ))),
            Err(TryLockError::Error(e)) => {
                Err(OperationsError(format!("cannot lock {}: {e}", lock_path.display())))
            }
        }
    }

    /// Give the database up (the gate has stopped): another gate may start.
    pub fn release_gate(&mut self) {
        self.gate_lock = None;
    }

    /// This database's secret key for derived operation ids
    /// ([`cloakpipe_release::action::derive_operation_id`]): 32 bytes from
    /// the OS CSPRNG, made when the database is created. It never leaves the
    /// database, so a ledger holder cannot test argument guesses against a
    /// derived id.
    pub fn operation_id_key(&self) -> Result<[u8; 32], OperationsError> {
        let key: Vec<u8> = self.conn.query_row("SELECT key FROM operation_id_key WHERE id = 1", [], |r| r.get(0))?;
        key.try_into().map_err(|_| OperationsError("operation id key is not 32 bytes".into()))
    }

    /// Start-up sweep: take the database for this gate (an error if another
    /// gate holds it), then every operation a previous process left
    /// `in_flight` becomes `unknown` (its reply can no longer arrive).
    /// Returns their ids.
    pub fn recover(&mut self) -> Result<Vec<String>, OperationsError> {
        self.claim_for_gate()?;
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let ids: Vec<String> = {
            let mut stmt = tx.prepare("SELECT operation_id FROM operations WHERE state = 'in_flight' ORDER BY operation_id")?;
            let ids = stmt.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
            ids
        };
        tx.execute("UPDATE operations SET state = 'unknown', updated_at = ?1 WHERE state = 'in_flight'", params![now()])?;
        tx.commit()?;
        Ok(ids)
    }

    /// Decide what to do with a call, and record a forwarded one as
    /// `in_flight`, in one `BEGIN IMMEDIATE` transaction.
    pub fn begin(&mut self, operation_id: &str, tool: &str, call_digest: &[u8; 32]) -> Result<Begin, OperationsError> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = tx
            .query_row(&format!("SELECT {COLUMNS} FROM operations WHERE operation_id = ?1"), params![operation_id], row)
            .optional()?
            .map(to_row)
            .transpose()?;
        let decision = match existing {
            None => {
                tx.execute(
                    "INSERT INTO operations (operation_id, tool, call_digest, state, result, updated_at)
                     VALUES (?1, ?2, ?3, 'in_flight', NULL, ?4)",
                    params![operation_id, tool, &call_digest[..], now()],
                )?;
                Begin::Forward
            }
            Some(r) if r.call_digest != *call_digest || r.tool != tool => Begin::Conflict,
            Some(r) => match r.state {
                OperationState::Done => Begin::Replay { result: r.result },
                s @ (OperationState::InFlight | OperationState::Unknown) => Begin::ReconcileBeforeRetry(s),
                OperationState::Failed | OperationState::NotApplied => {
                    tx.execute(
                        "UPDATE operations SET state = 'in_flight', result = NULL, updated_at = ?2 WHERE operation_id = ?1",
                        params![operation_id, now()],
                    )?;
                    Begin::Forward
                }
            },
        };
        tx.commit()?;
        Ok(decision)
    }

    /// Settle an `in_flight` operation as `done` (with its masked result),
    /// `failed` or `unknown`. Returns false when the operation is not
    /// `in_flight` (absent, or already settled or reconciled): nothing changes.
    pub fn settle(&mut self, operation_id: &str, state: OperationState, result: Option<&str>) -> Result<bool, OperationsError> {
        if !matches!(state, OperationState::Done | OperationState::Failed | OperationState::Unknown) {
            return Err(OperationsError(format!("cannot settle an operation as {state}")));
        }
        let changed = self.conn.execute(
            "UPDATE operations SET state = ?2, result = ?3, updated_at = ?4 WHERE operation_id = ?1 AND state = 'in_flight'",
            params![operation_id, state.as_str(), result, now()],
        )?;
        Ok(changed == 1)
    }

    pub fn get(&self, operation_id: &str) -> Result<Option<OperationRow>, OperationsError> {
        self.conn
            .query_row(&format!("SELECT {COLUMNS} FROM operations WHERE operation_id = ?1"), params![operation_id], row)
            .optional()?
            .map(to_row)
            .transpose()
    }

    /// Every operation (or those in `state`), by operation id.
    pub fn list(&self, state: Option<OperationState>) -> Result<Vec<OperationRow>, OperationsError> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLUMNS} FROM operations WHERE ?1 IS NULL OR state = ?1 ORDER BY operation_id"
        ))?;
        let raw = stmt.query_map(params![state.map(|s| s.as_str())], row)?.collect::<rusqlite::Result<Vec<_>>>()?;
        raw.into_iter().map(to_row).collect()
    }

    /// An operator's verdict on an `unknown` (or, with `force`, `in_flight`) operation:
    /// `done` (it happened; a retry replays) or `not_applied` (it did not; a
    /// retry runs it). `evidence` records the reconciliation (the ledger hop)
    /// inside the transaction: if it fails, nothing changes.
    pub fn reconcile(
        &mut self,
        operation_id: &str,
        outcome: OperationState,
        force: bool,
        evidence: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), ReconcileError> {
        if !matches!(outcome, OperationState::Done | OperationState::NotApplied) {
            return Err(ReconcileError::BadOutcome);
        }
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: Option<String> = tx
            .query_row("SELECT state FROM operations WHERE operation_id = ?1", params![operation_id], |r| r.get(0))
            .optional()?;
        let state: OperationState = state.ok_or(ReconcileError::NotFound)?.parse().map_err(ReconcileError::Store)?;
        if !matches!(state, OperationState::Unknown | OperationState::InFlight) {
            return Err(ReconcileError::NotPending(state));
        }
        if state == OperationState::InFlight && !force {
            return Err(ReconcileError::InFlight);
        }
        evidence().map_err(ReconcileError::Evidence)?;
        tx.execute(
            "UPDATE operations SET state = ?2, result = NULL, updated_at = ?3 WHERE operation_id = ?1",
            params![operation_id, outcome.as_str(), now()],
        )?;
        tx.commit()?;
        Ok(())
    }
}
