//! The operations store: the durable state of side-effecting tool calls
//! (docs/ACTION_BOUNDARY.md, "Operation outcomes").

use cloakpipe_mcp::operations::{Begin, OperationState, OperationStore, ReconcileError};
use std::path::Path;

const DIGEST: [u8; 32] = [0xab; 32];
const OTHER: [u8; 32] = [0xcd; 32];

fn open(dir: &Path) -> OperationStore {
    OperationStore::open(dir.join("ops.db")).unwrap()
}

#[test]
fn the_table_has_the_documented_columns() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(dir.path()));
    let conn = rusqlite::Connection::open(dir.path().join("ops.db")).unwrap();
    let mut stmt = conn.prepare("SELECT name, type, pk FROM pragma_table_info('operations') ORDER BY cid").unwrap();
    let cols: Vec<(String, String, i64)> =
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect();
    let expected = [
        ("operation_id", "TEXT", 1),
        ("tool", "TEXT", 0),
        ("call_digest", "BLOB", 0),
        ("state", "TEXT", 0),
        ("result", "TEXT", 0),
        ("updated_at", "TEXT", 0),
    ];
    let expected: Vec<(String, String, i64)> = expected.iter().map(|(n, t, p)| (n.to_string(), t.to_string(), *p)).collect();
    assert_eq!(cols, expected);
}

#[test]
fn a_new_operation_is_forwarded_and_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    assert_eq!(s.begin("op-1", "crm.patch", &DIGEST).unwrap(), Begin::Forward);
    let row = s.get("op-1").unwrap().unwrap();
    assert_eq!(row.state, OperationState::InFlight);
    assert_eq!(row.tool, "crm.patch");
    assert_eq!(row.call_digest, DIGEST);
    assert!(row.result.is_none());
    assert!(chrono::DateTime::parse_from_rfc3339(&row.updated_at).is_ok(), "{}", row.updated_at);
}

#[test]
fn a_different_call_under_the_same_operation_id_is_a_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Done, Some(r#"{"content":[]}"#)).unwrap();
    assert_eq!(s.begin("op-1", "crm.patch", &OTHER).unwrap(), Begin::Conflict);
    assert_eq!(s.begin("op-1", "crm.lookup", &DIGEST).unwrap(), Begin::Conflict);
    // Nothing changed.
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::Done);
}

#[test]
fn a_done_operation_replays_its_stored_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    assert!(s.settle("op-1", OperationState::Done, Some(r#"{"content":[{"type":"text","text":"ok"}]}"#)).unwrap());
    assert_eq!(
        s.begin("op-1", "crm.patch", &DIGEST).unwrap(),
        Begin::Replay { result: Some(r#"{"content":[{"type":"text","text":"ok"}]}"#.into()) }
    );
}

#[test]
fn in_flight_and_unknown_operations_must_be_reconciled_before_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    assert_eq!(s.begin("op-1", "crm.patch", &DIGEST).unwrap(), Begin::ReconcileBeforeRetry(OperationState::InFlight));
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    assert_eq!(s.begin("op-1", "crm.patch", &DIGEST).unwrap(), Begin::ReconcileBeforeRetry(OperationState::Unknown));
}

#[test]
fn failed_and_not_applied_operations_may_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Failed, None).unwrap();
    assert_eq!(s.begin("op-1", "crm.patch", &DIGEST).unwrap(), Begin::Forward);
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::InFlight);

    s.settle("op-1", OperationState::Unknown, None).unwrap();
    s.reconcile("op-1", OperationState::NotApplied, false, || Ok(())).unwrap();
    assert_eq!(s.begin("op-1", "crm.patch", &DIGEST).unwrap(), Begin::Forward);
}

#[test]
fn only_an_in_flight_operation_is_settled() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    assert!(!s.settle("op-missing", OperationState::Done, None).unwrap());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    // A late reply after the operation was swept to unknown does not
    // overwrite it: the operator decides.
    assert!(!s.settle("op-1", OperationState::Done, Some("{}")).unwrap());
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::Unknown);
}

#[test]
fn recovery_marks_operations_left_in_flight_unknown() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = open(dir.path());
        s.begin("op-1", "crm.patch", &DIGEST).unwrap();
        s.begin("op-2", "crm.patch", &OTHER).unwrap();
        s.settle("op-2", OperationState::Done, Some("{}")).unwrap();
    } // the process died with op-1 in flight
    let mut s = open(dir.path());
    // Opening alone changes nothing (`operations list` must not sweep a live gate).
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::InFlight);
    assert_eq!(s.recover().unwrap(), vec!["op-1".to_string()]);
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::Unknown);
    assert_eq!(s.get("op-2").unwrap().unwrap().state, OperationState::Done);
    assert!(s.recover().unwrap().is_empty());
}

#[test]
fn list_filters_by_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-a", "crm.patch", &DIGEST).unwrap();
    s.begin("op-b", "crm.patch", &OTHER).unwrap();
    s.settle("op-b", OperationState::Unknown, None).unwrap();
    let all: Vec<String> = s.list(None).unwrap().into_iter().map(|r| r.operation_id).collect();
    assert_eq!(all, ["op-a", "op-b"]);
    let unknown: Vec<String> = s.list(Some(OperationState::Unknown)).unwrap().into_iter().map(|r| r.operation_id).collect();
    assert_eq!(unknown, ["op-b"]);
}

#[test]
fn reconcile_settles_unknown_or_in_flight_operations_only() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    assert_eq!(s.reconcile("op-x", OperationState::Done, false, || Ok(())), Err(ReconcileError::NotFound));

    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    s.reconcile("op-1", OperationState::Done, false, || Ok(())).unwrap();
    let row = s.get("op-1").unwrap().unwrap();
    assert_eq!(row.state, OperationState::Done);
    assert!(row.result.is_none(), "the operator supplies an outcome, not a result");
    // Already settled: refused, unchanged.
    assert_eq!(
        s.reconcile("op-1", OperationState::NotApplied, false, || Ok(())),
        Err(ReconcileError::NotPending(OperationState::Done))
    );

    s.begin("op-2", "crm.patch", &OTHER).unwrap();
    s.reconcile("op-2", OperationState::NotApplied, true, || Ok(())).unwrap();
    assert_eq!(s.get("op-2").unwrap().unwrap().state, OperationState::NotApplied);

    // Only done / not_applied are outcomes.
    s.begin("op-3", "crm.patch", &[1; 32]).unwrap();
    for bad in [OperationState::Failed, OperationState::Unknown, OperationState::InFlight] {
        assert_eq!(s.reconcile("op-3", bad, false, || Ok(())), Err(ReconcileError::BadOutcome));
    }
}

#[test]
fn reconcile_keeps_the_row_when_its_evidence_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    let err = s.reconcile("op-1", OperationState::Done, false, || Err("ledger unavailable".into())).unwrap_err();
    assert_eq!(err, ReconcileError::Evidence("ledger unavailable".into()));
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::Unknown);
}

#[test]
fn a_row_with_an_unrecognised_state_is_an_error_not_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("ops.db")).unwrap();
    conn.execute("UPDATE operations SET state = 'maybe' WHERE operation_id = 'op-1'", []).unwrap();
    assert!(s.begin("op-1", "crm.patch", &DIGEST).is_err());
}

#[test]
fn state_names_are_stable() {
    for (state, name) in [
        (OperationState::InFlight, "in_flight"),
        (OperationState::Done, "done"),
        (OperationState::Failed, "failed"),
        (OperationState::Unknown, "unknown"),
        (OperationState::NotApplied, "not_applied"),
    ] {
        assert_eq!(state.as_str(), name);
        assert_eq!(name.parse::<OperationState>().unwrap(), state);
    }
    assert!("in-flight".parse::<OperationState>().is_err());
}

/// Every id `cloakpipe approve --operation-id` and the gate accept is one
/// the evidence ledger accepts as an `operation_id`, so its hops are never lost.
#[test]
fn every_valid_operation_id_is_a_ledger_opaque_id() {
    use cloakpipe_receipt::approval::is_valid_operation_id;
    use cloakpipe_ledger::{MetadataValue, RecordBuilder};
    let ledger_ok =
        |id: &str| RecordBuilder::new().metadata("operation_id", MetadataValue::OpaqueId(id.to_string())).build().is_ok();
    let words = ["op", "japan", "lessn", "phone", "EMAIL", "aadhaar", "ifsc", "gstin", "Pan", "SSN", "crm", "x"];
    let seps = ["", "-", "_", ".", ":", "1"];
    for a in words {
        for sep in seps {
            for b in words {
                let id = format!("{a}{sep}{b}");
                if is_valid_operation_id(&id) {
                    assert!(ledger_ok(&id), "{id:?} passes is_valid_operation_id but the ledger refuses it");
                }
            }
        }
    }
    assert!(ledger_ok(&uuid::Uuid::new_v4().to_string()));
}

/// Each operations database holds its own random key for deriving
/// operation ids: stable across opens, different between databases.
#[test]
fn the_store_holds_a_stable_random_operation_id_key() {
    let dir = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let key = open(dir.path()).operation_id_key().unwrap();
    assert_eq!(open(dir.path()).operation_id_key().unwrap(), key);
    assert_ne!(open(other.path()).operation_id_key().unwrap(), key);
    assert_ne!(key, [0u8; 32]);
}

/// One gate per operations database: a second gate's start-up sweep would
/// demote the first gate's live `in_flight` operations, so it is refused
/// while the first one holds the database. Reading and reconciling are not.
#[test]
fn a_second_gate_on_a_live_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut live = open(dir.path());
    assert!(live.recover().unwrap().is_empty());
    live.begin("op-1", "crm.patch", &DIGEST).unwrap();

    let mut second = open(dir.path());
    let err = second.recover().expect_err("the database belongs to a running gate");
    assert!(err.to_string().contains("another gate"), "{err}");
    assert_eq!(second.get("op-1").unwrap().unwrap().state, OperationState::InFlight, "nothing was demoted");
    // `operations list` / `reconcile` style access still works.
    assert_eq!(second.list(None).unwrap().len(), 1);

    // Once the live gate is gone, the next one takes over and sweeps.
    drop(live);
    assert_eq!(second.recover().unwrap(), vec!["op-1".to_string()]);
}

/// The gate gives the database up when it stops.
#[test]
fn a_released_database_can_be_taken_by_the_next_gate() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = open(dir.path());
    first.recover().unwrap();
    first.release_gate();
    let mut second = open(dir.path());
    assert!(second.recover().is_ok());
}

/// An `in_flight` operation may still be answered by a running gate:
/// reconciling it takes an explicit `force`. An `unknown` one does not.
#[test]
fn reconciling_an_in_flight_operation_needs_force() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    let mut recorded = false;
    assert_eq!(
        s.reconcile("op-1", OperationState::NotApplied, false, || {
            recorded = true;
            Ok(())
        }),
        Err(ReconcileError::InFlight)
    );
    assert!(!recorded, "no evidence for a refused reconciliation");
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::InFlight);
    let err = ReconcileError::InFlight.to_string();
    assert!(err.contains("--force") && err.contains("running"), "{err}");
    s.reconcile("op-1", OperationState::NotApplied, true, || Ok(())).unwrap();
    assert_eq!(s.get("op-1").unwrap().unwrap().state, OperationState::NotApplied);
}

/// A key an existing database already holds (whoever made it) is kept: the
/// operation ids derived under it stay the same.
#[test]
fn an_existing_operation_id_key_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let conn = rusqlite::Connection::open(dir.path().join("ops.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE operation_id_key (id INTEGER PRIMARY KEY CHECK (id = 1), key BLOB NOT NULL CHECK (length(key) = 32));
         INSERT INTO operation_id_key (id, key) VALUES (1, randomblob(32));",
    )
    .unwrap();
    let stored: Vec<u8> = conn.query_row("SELECT key FROM operation_id_key", [], |r| r.get(0)).unwrap();
    drop(conn);
    assert_eq!(open(dir.path()).operation_id_key().unwrap().to_vec(), stored);
    assert_eq!(open(dir.path()).operation_id_key().unwrap().to_vec(), stored);
}

/// The database holds masked results and the operation-id key: on unix a new
/// one (and the gate lock file) is readable by its owner only. An existing
/// file's permissions are the operator's and are left alone.
#[cfg(unix)]
#[test]
fn a_new_operations_database_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let mut s = open(dir.path());
    s.recover().unwrap();
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    assert_eq!(mode(&dir.path().join("ops.db")), 0o600);
    assert_eq!(mode(&s.gate_lock_path()), 0o600);
    drop(s);

    let existing = dir.path().join("shared.db");
    std::fs::write(&existing, b"").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o640)).unwrap();
    drop(OperationStore::open(&existing).unwrap());
    assert_eq!(mode(&existing), 0o640);
}
