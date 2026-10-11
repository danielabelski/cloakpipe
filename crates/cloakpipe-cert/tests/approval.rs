//! Signed approval receipts (docs/ACTION_BOUNDARY.md §Approval receipts):
//! an in-toto Statement about one tool-call fingerprint, in a DSSE envelope
//! signed by a trusted approver, verified offline against the call the gate
//! is about to forward.

use base64::prelude::*;
use cloakpipe_cert::approval::{
    approval_statement, is_valid_operation_id, sign_approval, verify_approval, Approval, ApprovalCheck, ApprovalError,
    APPROVAL_PREDICATE_TYPE, CLOCK_SKEW_SECS,
};
use cloakpipe_cert::statement::{pae, Envelope, Signature, TrustedKey, PAYLOAD_TYPE};
use cloakpipe_release::action::{fingerprint, ToolCallFingerprint};
use cloakpipe_release::ReleaseHash;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

const NOW: &str = "2026-10-11T12:00:00Z";

fn release() -> String {
    format!("sha256:{}", "ab".repeat(32))
}

fn fp() -> ToolCallFingerprint {
    let r: ReleaseHash = release().parse().unwrap();
    fingerprint(&r, "crm.patch", &json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "review"}}))
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn trusted() -> Vec<TrustedKey> {
    vec![TrustedKey { keyid: "approver-1".into(), public_key: key().verifying_key().to_bytes() }]
}

fn approval() -> Approval {
    Approval {
        release: release(),
        tool: "crm.patch".into(),
        task_id: "t-981".into(),
        operation_id: "2b0f8f9e-5c3a-4d7e-9a61-0c2f1b7d4e10".into(),
        approver: "approver-1".into(),
        approved_at: "2026-10-11T11:55:00Z".into(),
        not_after: "2026-10-11T12:10:00Z".into(),
    }
}

fn receipt(a: &Approval) -> Envelope {
    sign_approval(&fp(), a, &key(), "approver-1")
}

fn check<'a>(approvers: &'a [TrustedKey]) -> ApprovalCheck<'a> {
    ApprovalCheck { fingerprint: fp(), release: "", tool: "crm.patch", task_id: "t-981", approvers, now: NOW }
}

fn verify(env: &Envelope, f: impl Fn(&mut ApprovalCheck)) -> Result<Approval, ApprovalError> {
    let keys = trusted();
    let r = release();
    let mut c = check(&keys);
    c.release = &r;
    f(&mut c);
    verify_approval(env, &c)
}

fn invalid(r: Result<Approval, ApprovalError>) {
    match r {
        Err(ApprovalError::Invalid(_)) => {}
        other => panic!("expected approval_invalid, got {other:?}"),
    }
}

/// Re-sign an edited statement with the trusted key.
fn resign(statement: &Value) -> Envelope {
    let payload = serde_json_canonicalizer::to_vec(statement).unwrap();
    raw(&payload)
}

fn raw(payload: &[u8]) -> Envelope {
    let sig = key().sign(&pae(PAYLOAD_TYPE, payload));
    Envelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: BASE64_STANDARD.encode(payload),
        signatures: vec![Signature { keyid: "approver-1".into(), sig: BASE64_STANDARD.encode(sig.to_bytes()) }],
    }
}

#[test]
fn the_receipt_is_an_in_toto_statement_about_the_fingerprint() {
    assert_eq!(APPROVAL_PREDICATE_TYPE, "https://cloakpipe.co/attestations/approval/v1alpha1");
    let s = approval_statement(&fp(), &approval());
    assert_eq!(s["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(s["predicateType"], APPROVAL_PREDICATE_TYPE);
    assert_eq!(s["subject"], json!([{"name": "tool-call:crm.patch", "digest": {"sha256": fp().hex()}}]));
    assert_eq!(
        s["predicate"],
        json!({
            "release": release(), "tool": "crm.patch", "taskId": "t-981",
            "operationId": "2b0f8f9e-5c3a-4d7e-9a61-0c2f1b7d4e10", "approver": "approver-1",
            "approvedAt": "2026-10-11T11:55:00Z", "notAfter": "2026-10-11T12:10:00Z"
        })
    );
    let env = receipt(&approval());
    assert_eq!(env.payload_type, "application/vnd.in-toto+json");
    let payload = BASE64_STANDARD.decode(&env.payload).unwrap();
    assert_eq!(payload, serde_json_canonicalizer::to_vec(&s).unwrap(), "payload is the JCS statement");
}

#[test]
fn a_receipt_for_this_call_verifies() {
    assert_eq!(verify(&receipt(&approval()), |_| {}).unwrap(), approval());
}

#[test]
fn a_receipt_from_an_untrusted_signer_is_invalid() {
    let other = SigningKey::from_bytes(&[3u8; 32]);
    invalid(verify(&sign_approval(&fp(), &approval(), &other, "approver-1"), |_| {}));
    // Trusted key, but under another keyid.
    invalid(verify(&sign_approval(&fp(), &approval(), &key(), "approver-2"), |_| {}));
    // No approvers trusted at all.
    let env = receipt(&approval());
    invalid(verify_approval(&env, &ApprovalCheck { approvers: &[], release: &release(), ..check(&[]) }));
}

#[test]
fn the_named_approver_must_be_the_signer() {
    let mut a = approval();
    a.approver = "someone-else".into();
    invalid(verify(&receipt(&a), |_| {}));
}

#[test]
fn a_tampered_receipt_is_invalid() {
    let mut env = receipt(&approval());
    let mut s: Value = serde_json::from_slice(&BASE64_STANDARD.decode(&env.payload).unwrap()).unwrap();
    s["predicate"]["notAfter"] = json!("2027-01-01T00:00:00Z");
    env.payload = BASE64_STANDARD.encode(serde_json_canonicalizer::to_vec(&s).unwrap());
    invalid(verify(&env, |_| {}));
    let mut env = receipt(&approval());
    env.payload_type = "application/json".into();
    invalid(verify(&env, |_| {}));
    let mut env = receipt(&approval());
    env.payload = "%%%".into();
    invalid(verify(&env, |_| {}));
}

#[test]
fn a_receipt_for_another_release_tool_task_or_call_is_invalid() {
    let env = receipt(&approval());
    let other_release = format!("sha256:{}", "cd".repeat(32));
    invalid(verify(&env, |c| c.release = Box::leak(other_release.clone().into_boxed_str())));
    invalid(verify(&env, |c| c.tool = "crm.lookup"));
    invalid(verify(&env, |c| c.task_id = "t-982"));
    invalid(verify(&env, |c| c.fingerprint = ToolCallFingerprint([0u8; 32])));
}

#[test]
fn the_signed_fields_must_agree_with_the_subject() {
    // A correctly signed receipt whose predicate names another release or
    // tool than the call it is checked against.
    for (field, value) in [("release", json!(format!("sha256:{}", "cd".repeat(32)))), ("tool", json!("crm.lookup")), ("taskId", json!("t-1"))] {
        let mut s = approval_statement(&fp(), &approval());
        s["predicate"][field] = value;
        invalid(verify(&resign(&s), |_| {}));
    }
}

#[test]
fn an_expired_receipt_is_expired() {
    assert_eq!(verify(&receipt(&approval()), |c| c.now = "2026-10-11T12:10:00Z"), Err(ApprovalError::Expired));
    assert_eq!(verify(&receipt(&approval()), |c| c.now = "2026-12-01T00:00:00Z"), Err(ApprovalError::Expired));
    assert_eq!(ApprovalError::Expired.code(), "approval_expired");
    assert_eq!(ApprovalError::Invalid("x".into()).code(), "approval_invalid");
}

#[test]
fn invalid_wins_over_expired() {
    let env = receipt(&approval());
    invalid(verify(&env, |c| {
        c.now = "2026-12-01T00:00:00Z";
        c.task_id = "t-982";
    }));
}

#[test]
fn approved_at_may_be_ahead_only_by_the_clock_skew_allowance() {
    assert_eq!(CLOCK_SKEW_SECS, 60);
    let mut a = approval();
    a.approved_at = "2026-10-11T12:00:59Z".into();
    assert!(verify(&receipt(&a), |_| {}).is_ok(), "within the allowance");
    a.approved_at = "2026-10-11T12:01:01Z".into();
    invalid(verify(&receipt(&a), |_| {}));
}

#[test]
fn malformed_windows_and_ids_are_invalid() {
    let edits: [fn(&mut Approval); 6] = [
        |a| a.not_after = a.approved_at.clone(),
        |a| a.not_after = "2026-10-11 12:10:00Z".into(),
        |a| a.approved_at = "yesterday".into(),
        |a| a.operation_id = String::new(),
        |a| a.operation_id = "op 1".into(),
        |a| a.operation_id = "op=1;x".into(),
    ];
    for edit in edits {
        let mut a = approval();
        edit(&mut a);
        invalid(verify(&receipt(&a), |_| {}));
    }
    invalid(verify(&receipt(&approval()), |c| c.now = "not-a-time"));
}

#[test]
fn unknown_fields_wrong_types_and_duplicate_keys_are_invalid() {
    let mut s = approval_statement(&fp(), &approval());
    s["predicate"]["scope"] = json!("all");
    invalid(verify(&resign(&s), |_| {}));

    let mut s = approval_statement(&fp(), &approval());
    s["predicateType"] = json!("https://cloakpipe.co/attestations/certification/v1alpha1");
    invalid(verify(&resign(&s), |_| {}));

    let mut s = approval_statement(&fp(), &approval());
    s["_type"] = json!("https://in-toto.io/Statement/v0.1");
    invalid(verify(&resign(&s), |_| {}));

    let mut s = approval_statement(&fp(), &approval());
    s["subject"] = json!([s["subject"][0].clone(), s["subject"][0].clone()]);
    invalid(verify(&resign(&s), |_| {}));

    let canonical = String::from_utf8(serde_json_canonicalizer::to_vec(&approval_statement(&fp(), &approval())).unwrap()).unwrap();
    let dup = canonical.replacen(r#""tool":"crm.patch""#, r#""tool":"crm.lookup","tool":"crm.patch""#, 1);
    assert_ne!(dup, canonical);
    invalid(verify(&raw(dup.as_bytes()), |_| {}));
}

#[test]
fn operation_ids_are_short_opaque_tokens() {
    for ok in ["2b0f8f9e-5c3a-4d7e-9a61-0c2f1b7d4e10", "op-1", "crm:patch.42_A"] {
        assert!(is_valid_operation_id(ok), "{ok}");
    }
    let long = "a".repeat(129);
    for bad in ["", "op 1", "a=b", "a;b", "a/b", "é", long.as_str()] {
        assert!(!is_valid_operation_id(bad), "{bad:?}");
    }
}
