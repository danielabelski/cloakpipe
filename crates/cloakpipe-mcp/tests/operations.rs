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
    s.reconcile("op-1", OperationState::NotApplied, || Ok(())).unwrap();
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
    assert_eq!(s.reconcile("op-x", OperationState::Done, || Ok(())), Err(ReconcileError::NotFound));

    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    s.reconcile("op-1", OperationState::Done, || Ok(())).unwrap();
    let row = s.get("op-1").unwrap().unwrap();
    assert_eq!(row.state, OperationState::Done);
    assert!(row.result.is_none(), "the operator supplies an outcome, not a result");
    // Already settled: refused, unchanged.
    assert_eq!(
        s.reconcile("op-1", OperationState::NotApplied, || Ok(())),
        Err(ReconcileError::NotPending(OperationState::Done))
    );

    s.begin("op-2", "crm.patch", &OTHER).unwrap();
    s.reconcile("op-2", OperationState::NotApplied, || Ok(())).unwrap();
    assert_eq!(s.get("op-2").unwrap().unwrap().state, OperationState::NotApplied);

    // Only done / not_applied are outcomes.
    s.begin("op-3", "crm.patch", &[1; 32]).unwrap();
    for bad in [OperationState::Failed, OperationState::Unknown, OperationState::InFlight] {
        assert_eq!(s.reconcile("op-3", bad, || Ok(())), Err(ReconcileError::BadOutcome));
    }
}

#[test]
fn reconcile_keeps_the_row_when_its_evidence_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = open(dir.path());
    s.begin("op-1", "crm.patch", &DIGEST).unwrap();
    s.settle("op-1", OperationState::Unknown, None).unwrap();
    let err = s.reconcile("op-1", OperationState::Done, || Err("ledger unavailable".into())).unwrap_err();
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
