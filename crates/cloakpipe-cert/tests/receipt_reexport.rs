//! The DSSE primitives and approval receipts moved to `cloakpipe-receipt`.
//! `cloakpipe-cert` re-exports them for one release so existing callers keep
//! compiling: the re-exported items are the same types and functions, not
//! copies.

use cloakpipe_cert::{approval as cert_approval, statement as cert_statement};
use cloakpipe_receipt::{approval, dsse};
use std::any::TypeId;

#[test]
fn statement_dsse_items_are_the_receipt_crate_items() {
    assert_eq!(TypeId::of::<cert_statement::Envelope>(), TypeId::of::<dsse::Envelope>());
    assert_eq!(TypeId::of::<cert_statement::Signature>(), TypeId::of::<dsse::Signature>());
    assert_eq!(TypeId::of::<cert_statement::TrustedKey>(), TypeId::of::<dsse::TrustedKey>());
    assert_eq!(cert_statement::PAYLOAD_TYPE, dsse::PAYLOAD_TYPE);
    assert_eq!(cert_statement::STATEMENT_TYPE, dsse::STATEMENT_TYPE);
    assert_eq!(cert_statement::pae("t", b"p"), dsse::pae("t", b"p"));
    let _: fn(&serde_json::Value, &ed25519_dalek::SigningKey, &str) -> dsse::Envelope = cert_statement::sign;
}

#[test]
fn approval_module_is_the_receipt_crate_module() {
    assert_eq!(TypeId::of::<cert_approval::Approval>(), TypeId::of::<approval::Approval>());
    assert_eq!(TypeId::of::<cert_approval::ApprovalError>(), TypeId::of::<approval::ApprovalError>());
    assert_eq!(cert_approval::APPROVAL_PREDICATE_TYPE, approval::APPROVAL_PREDICATE_TYPE);
    assert_eq!(cert_approval::CLOCK_SKEW_SECS, approval::CLOCK_SKEW_SECS);
    assert!(cert_approval::is_valid_operation_id("op-1"));
}
