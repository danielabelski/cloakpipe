//! The generic DSSE primitives every CloakPipe receipt is built on: PAE,
//! Ed25519 signing over RFC 8785 statement bytes, signature checking against
//! trusted keys, strict JSON and RFC 3339 parsing.

use base64::prelude::*;
use cloakpipe_receipt::dsse::{
    canonical_bytes, pae, parse_rfc3339, sign, verified_keyids, Envelope, NoDuplicateKeys, Signature, TrustedKey,
    PAYLOAD_TYPE, STATEMENT_TYPE,
};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn trusted(keyid: &str) -> Vec<TrustedKey> {
    vec![TrustedKey { keyid: keyid.into(), public_key: key().verifying_key().to_bytes() }]
}

#[test]
fn constants_are_the_in_toto_and_dsse_identifiers() {
    assert_eq!(STATEMENT_TYPE, "https://in-toto.io/Statement/v1");
    assert_eq!(PAYLOAD_TYPE, "application/vnd.in-toto+json");
}

#[test]
fn pae_matches_dsse_spec_example() {
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}

#[test]
fn sign_puts_the_jcs_statement_in_the_payload_and_verifies() {
    let statement = json!({"b": 1, "a": {"y": true, "x": "z"}});
    let env = sign(&statement, &key(), "k1");
    assert_eq!(env.payload_type, PAYLOAD_TYPE);
    let payload = BASE64_STANDARD.decode(&env.payload).unwrap();
    assert_eq!(payload, canonical_bytes(&statement));
    assert_eq!(payload, br#"{"a":{"x":"z","y":true},"b":1}"#.to_vec());

    let (ok, problems) = verified_keyids(&env, &payload, &trusted("k1"));
    assert_eq!(ok.into_iter().collect::<Vec<_>>(), vec!["k1"]);
    assert!(problems.is_empty());
}

#[test]
fn verified_keyids_rejects_untrusted_keyid_and_bad_signature() {
    let env = sign(&json!({"a": 1}), &key(), "k1");
    let payload = BASE64_STANDARD.decode(&env.payload).unwrap();

    let (ok, problems) = verified_keyids(&env, &payload, &trusted("other"));
    assert!(ok.is_empty());
    assert_eq!(problems.len(), 1);

    let tampered = Envelope {
        signatures: vec![Signature { keyid: "k1".into(), sig: BASE64_STANDARD.encode([0u8; 64]) }],
        ..env.clone()
    };
    let (ok, _) = verified_keyids(&tampered, &payload, &trusted("k1"));
    assert!(ok.is_empty());

    let (ok, _) = verified_keyids(&env, br#"{"a":2}"#, &trusted("k1"));
    assert!(ok.is_empty(), "a signature over other bytes must not verify");
}

#[test]
fn no_duplicate_keys_refuses_duplicate_members_at_any_depth() {
    assert!(serde_json::from_str::<NoDuplicateKeys>(r#"{"a":1,"b":[{"c":1}]}"#).is_ok());
    assert!(serde_json::from_str::<NoDuplicateKeys>(r#"{"a":1,"a":2}"#).is_err());
    assert!(serde_json::from_str::<NoDuplicateKeys>(r#"{"a":[{"c":1,"c":1}]}"#).is_err());
}

#[test]
fn parse_rfc3339_requires_the_t_separator() {
    assert!(parse_rfc3339("2026-10-11T12:00:00Z").is_some());
    assert!(parse_rfc3339("2026-10-11t12:00:00+05:30").is_some());
    assert!(parse_rfc3339("2026-10-11 12:00:00Z").is_none());
    assert!(parse_rfc3339("not a time").is_none());
    assert!(parse_rfc3339("").is_none());
}
