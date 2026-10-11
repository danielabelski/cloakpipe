//! Signed approval receipts: a trusted approver's signature over one exact
//! tool call (docs/ACTION_BOUNDARY.md §Approval receipts).
//!
//! **Statement** ([`approval_statement`]): an in-toto v1 Statement
//! ```json
//! { "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{ "name": "tool-call:<tool>",
//!                 "digest": { "sha256": "<tool-call fingerprint hex>" } }],
//!   "predicateType": "https://cloakpipe.co/attestations/approval/v1alpha1",
//!   "predicate": { "release", "tool", "taskId", "operationId", "approver",
//!                  "approvedAt", "notAfter" } }
//! ```
//! The subject is the [tool-call fingerprint](cloakpipe_release::action),
//! so the receipt covers the raw arguments without carrying them.
//!
//! **Envelope** ([`sign_approval`]): the same DSSE envelope as a
//! certification ([`crate::statement::sign`]): Ed25519 over the PAE of the
//! RFC 8785 statement bytes.
//!
//! **Verification** ([`verify_approval`]) is offline and deterministic (the
//! caller supplies `now`). It fails with [`ApprovalError::Invalid`] when the
//! envelope or statement is malformed (including duplicate JSON keys and
//! unknown predicate fields), when no signature verifies under a trusted
//! approver key with a matching keyid, when `approver` is not the keyid of a
//! verifying signature, when the subject is not the expected fingerprint, or
//! `release` / `tool` / `taskId` are not the expected ones, when
//! `operationId` is not a valid operation id ([`is_valid_operation_id`]),
//! when a timestamp is not RFC 3339, when `notAfter` is not after
//! `approvedAt`, or when `approvedAt` is more than [`CLOCK_SKEW_SECS`] ahead
//! of `now`. Otherwise it fails with [`ApprovalError::Expired`] when
//! `now >= notAfter`. Invalid takes precedence over expired. Never panics.

use crate::statement::{self, parse_rfc3339, verified_keyids, Envelope, NoDuplicateKeys, TrustedKey, PAYLOAD_TYPE, STATEMENT_TYPE};
use base64::prelude::*;
use cloakpipe_release::action::ToolCallFingerprint;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// in-toto `predicateType` of an approval receipt.
pub const APPROVAL_PREDICATE_TYPE: &str = cloakpipe_release::namespace::APPROVAL_PREDICATE_TYPE;

/// How far `approvedAt` may be ahead of the verifier's clock, in seconds
/// (the same default allowance as `cloakpipe anchor --clock-skew-secs`).
pub const CLOCK_SKEW_SECS: i64 = 60;

/// The predicate of an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    /// `sha256:<hex>` manifest hash of the release the call runs under.
    pub release: String,
    /// The tool name, as in `tools/call`.
    pub tool: String,
    /// The trusted task context's `taskId`.
    pub task_id: String,
    /// The operation this call performs (item 3 deduplicates on it).
    pub operation_id: String,
    /// The approver: the keyid of the key that signs the receipt.
    pub approver: String,
    /// RFC 3339.
    pub approved_at: String,
    /// RFC 3339: the receipt is not accepted at or after this time.
    pub not_after: String,
}

/// What the receipt must be about: the call the gate is checking.
#[derive(Debug, Clone)]
pub struct ApprovalCheck<'a> {
    pub fingerprint: ToolCallFingerprint,
    /// `sha256:<hex>` manifest hash of the gate's release.
    pub release: &'a str,
    pub tool: &'a str,
    /// The trusted task context's `taskId`.
    pub task_id: &'a str,
    /// Keys trusted to approve calls.
    pub approvers: &'a [TrustedKey],
    /// RFC 3339 "current" time.
    pub now: &'a str,
}

/// Why a receipt does not approve the call. `code()` is stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalError {
    /// Malformed, untrusted, or about another call; carries a description
    /// (diagnostics only: it may name receipt fields, never argument values).
    Invalid(String),
    /// Valid, but `notAfter` has passed.
    Expired,
}

impl ApprovalError {
    pub fn code(&self) -> &'static str {
        match self {
            ApprovalError::Invalid(_) => "approval_invalid",
            ApprovalError::Expired => "approval_expired",
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::Invalid(why) => write!(f, "approval_invalid: {why}"),
            ApprovalError::Expired => f.write_str("approval_expired"),
        }
    }
}

impl std::error::Error for ApprovalError {}

/// Substrings the evidence ledger refuses in an opaque id (ASCII
/// case-insensitive), because they look like PII. Mirrors the ledger's
/// opaque-id check for the characters an operation id may contain.
pub const OPERATION_ID_FORBIDDEN: [&str; 7] = ["aadhaar", "pan", "ifsc", "gstin", "ssn", "phone", "email"];

/// An operation id: 1 to 128 ASCII letters, digits, `-`, `_`, `.` or `:`,
/// containing none of [`OPERATION_ID_FORBIDDEN`] in any case. Short and
/// opaque, so the evidence ledger accepts it as an `operation_id`.
pub fn is_valid_operation_id(id: &str) -> bool {
    let lowered = id.to_ascii_lowercase();
    (1..=128).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        && !OPERATION_ID_FORBIDDEN.iter().any(|m| lowered.contains(m))
}

/// Parse JSON (tool-call arguments, a task context) refusing duplicate
/// object keys: a reader that kept the other duplicate would see another
/// call than the one approved.
pub fn parse_json_strict(src: &str) -> Result<Value, String> {
    serde_json::from_str::<NoDuplicateKeys>(src)
        .and_then(|_| serde_json::from_str::<Value>(src))
        .map_err(|e| e.to_string())
}

/// Build the in-toto Statement of an approval for the call `fingerprint`.
pub fn approval_statement(fingerprint: &ToolCallFingerprint, a: &Approval) -> Value {
    serde_json::json!({
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": format!("tool-call:{}", a.tool),
            "digest": { "sha256": fingerprint.hex() },
        }],
        "predicateType": APPROVAL_PREDICATE_TYPE,
        // Every field is a string: serialising cannot fail.
        "predicate": serde_json::to_value(a).unwrap_or(Value::Null),
    })
}

/// Sign an approval for the call `fingerprint` into a DSSE envelope.
pub fn sign_approval(fingerprint: &ToolCallFingerprint, a: &Approval, key: &SigningKey, keyid: &str) -> Envelope {
    statement::sign(&approval_statement(fingerprint, a), key, keyid)
}

/// Verify a receipt against the call in `check` (see the module contract).
/// Returns the approval it carries.
pub fn verify_approval(envelope: &Envelope, check: &ApprovalCheck) -> Result<Approval, ApprovalError> {
    let invalid = |why: String| Err(ApprovalError::Invalid(why));
    if envelope.payload_type != PAYLOAD_TYPE {
        return invalid(format!("payloadType: expected {PAYLOAD_TYPE:?}"));
    }
    let Ok(payload) = BASE64_STANDARD.decode(&envelope.payload) else {
        return invalid("payload: not standard base64".into());
    };
    let (signers, _) = verified_keyids(envelope, &payload, check.approvers);
    if signers.is_empty() {
        return invalid("signature: no signature verifies under a trusted approver key with a matching keyid".into());
    }
    let statement: Value = match serde_json::from_slice::<NoDuplicateKeys>(&payload).and_then(|_| serde_json::from_slice(&payload)) {
        Ok(v) => v,
        Err(e) => return invalid(format!("payload: not JSON: {e}")),
    };
    if statement.get("_type").and_then(Value::as_str) != Some(STATEMENT_TYPE) {
        return invalid(format!("_type: expected {STATEMENT_TYPE:?}"));
    }
    if statement.get("predicateType").and_then(Value::as_str) != Some(APPROVAL_PREDICATE_TYPE) {
        return invalid(format!("predicateType: expected {APPROVAL_PREDICATE_TYPE:?}"));
    }
    let subject_ok = match statement.get("subject").and_then(Value::as_array).map(Vec::as_slice) {
        Some([entry]) => {
            entry.get("name").and_then(Value::as_str).is_some()
                && entry.pointer("/digest/sha256").and_then(Value::as_str) == Some(check.fingerprint.hex().as_str())
        }
        _ => false,
    };
    if !subject_ok {
        return invalid("subject: expected exactly one entry whose digest is this call's fingerprint".into());
    }
    let a = match statement.get("predicate").map(Approval::deserialize) {
        Some(Ok(a)) => a,
        Some(Err(e)) => return invalid(format!("predicate: malformed approval: {e}")),
        None => return invalid("predicate: missing".into()),
    };
    if !signers.contains(a.approver.as_str()) {
        return invalid("approver: not the keyid of a verifying signature".into());
    }
    if a.release != check.release {
        return invalid("release: approved for another release".into());
    }
    if a.tool != check.tool {
        return invalid("tool: approved for another tool".into());
    }
    if a.task_id != check.task_id {
        return invalid("taskId: approved for another task".into());
    }
    if !is_valid_operation_id(&a.operation_id) {
        return invalid("operationId: not a valid operation id".into());
    }
    let (Some(approved_at), Some(not_after), Some(now)) =
        (parse_rfc3339(&a.approved_at), parse_rfc3339(&a.not_after), parse_rfc3339(check.now))
    else {
        return invalid("approvedAt / notAfter / now: not RFC 3339".into());
    };
    if not_after <= approved_at {
        return invalid("notAfter is not after approvedAt".into());
    }
    if approved_at > now + chrono::Duration::seconds(CLOCK_SKEW_SECS) {
        return invalid("approvedAt is in the future".into());
    }
    if now >= not_after {
        return Err(ApprovalError::Expired);
    }
    Ok(a)
}
