//! The tool-call fingerprint: what an approval receipt is about.
//!
//! `SHA-256("cloakpipe.co/tool-call/v1" || "\n" || JCS({"release", "tool",
//! "arguments"}))` over the raw arguments, so any change to the call is a
//! different fingerprint.

use cloakpipe_release::action::{fingerprint, ToolCallFingerprint, TOOL_CALL_FINGERPRINT_DOMAIN};
use cloakpipe_release::ReleaseHash;
use serde_json::json;
use sha2::{Digest, Sha256};

fn release() -> ReleaseHash {
    format!("sha256:{}", "ab".repeat(32)).parse().unwrap()
}

#[test]
fn the_fingerprint_is_sha256_over_the_domain_and_the_jcs_call() {
    assert_eq!(TOOL_CALL_FINGERPRINT_DOMAIN, "cloakpipe.co/tool-call/v1");
    let fp = fingerprint(&release(), "crm.patch", &json!({"tenant": "demo-co", "patch": {"stage": "review", "n": 1}}));
    let jcs = format!(
        r#"{{"arguments":{{"patch":{{"n":1,"stage":"review"}},"tenant":"demo-co"}},"release":"sha256:{}","tool":"crm.patch"}}"#,
        "ab".repeat(32)
    );
    let expected: [u8; 32] = Sha256::digest(format!("cloakpipe.co/tool-call/v1\n{jcs}").as_bytes()).into();
    assert_eq!(fp, ToolCallFingerprint(expected));
    assert_eq!(fp.hex(), hex::encode(expected));
    assert_eq!(fp.to_string(), format!("sha256:{}", hex::encode(expected)));
}

#[test]
fn key_order_and_whitespace_do_not_matter() {
    let a: serde_json::Value = serde_json::from_str(r#"{"a": 1, "b": {"y": true, "x": null}}"#).unwrap();
    let b: serde_json::Value = serde_json::from_str(r#"{"b":{"x":null,"y":true},"a":1}"#).unwrap();
    assert_eq!(fingerprint(&release(), "t", &a), fingerprint(&release(), "t", &b));
}

#[test]
fn any_change_to_the_call_changes_the_fingerprint() {
    let base = fingerprint(&release(), "crm.patch", &json!({"stage": "review"}));
    let other_release: ReleaseHash = format!("sha256:{}", "cd".repeat(32)).parse().unwrap();
    for changed in [
        fingerprint(&release(), "crm.patch", &json!({"stage": "qualified"})),
        fingerprint(&release(), "crm.patch", &json!({"stage": "review", "note": ""})),
        fingerprint(&release(), "crm.patch", &json!({"stage": ["review"]})),
        fingerprint(&release(), "crm.patch", &json!(null)),
        fingerprint(&release(), "crm.lookup", &json!({"stage": "review"})),
        fingerprint(&other_release, "crm.patch", &json!({"stage": "review"})),
    ] {
        assert_ne!(changed, base);
    }
}

#[test]
fn the_fingerprint_is_not_unicode_normalised() {
    // "é" precomposed vs combining: different calls, different fingerprints.
    let nfc = fingerprint(&release(), "t", &json!({"n": "\u{e9}"}));
    let nfd = fingerprint(&release(), "t", &json!({"n": "e\u{301}"}));
    assert_ne!(nfc, nfd);
}

#[test]
fn fingerprints_parse_from_their_display_and_bare_hex() {
    let fp = fingerprint(&release(), "t", &json!({}));
    assert_eq!(fp.to_string().parse::<ToolCallFingerprint>().unwrap(), fp);
    assert_eq!(fp.hex().parse::<ToolCallFingerprint>().unwrap(), fp);
    assert!("sha256:XYZ".parse::<ToolCallFingerprint>().is_err());
    assert!(fp.hex().to_uppercase().parse::<ToolCallFingerprint>().is_err());
}

// ── derived operation ids ───────────────────────────────────────────────

/// HMAC-SHA256 written out from its definition (RFC 2104), so the test does
/// not share the implementation's HMAC.
fn hmac_sha256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(key);
    let pad = |b: u8| block.iter().map(|k| k ^ b).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

const KEY: [u8; 32] = [0x5a; 32];

#[test]
fn a_derived_operation_id_is_op_plus_32_hex_of_a_keyed_mac_of_the_domain_task_and_fingerprint() {
    use cloakpipe_release::action::{derive_operation_id, OPERATION_ID_DOMAIN};
    assert_eq!(OPERATION_ID_DOMAIN, "cloakpipe.co/operation/v1");
    let fp = fingerprint(&release(), "crm.patch", &json!({"stage": "review"}));
    let expected = hex::encode(hmac_sha256(&KEY, format!("cloakpipe.co/operation/v1\nt-981\n{}", fp.hex()).as_bytes()));
    let id = derive_operation_id(&KEY, "t-981", &fp);
    assert_eq!(id, format!("op-{}", &expected[..32]));
    assert_eq!(id.len(), 35);
}

/// The id is recorded in the evidence ledger next to the release hash, and
/// task ids are low entropy: without the operator's key, a ledger holder
/// cannot test guesses of the arguments against it.
#[test]
fn a_derived_operation_id_is_not_a_plain_hash_of_the_call() {
    use cloakpipe_release::action::derive_operation_id;
    let fp = fingerprint(&release(), "crm.patch", &json!({"phone": "+91 98765 43210"}));
    let plain = hex::encode(Sha256::digest(format!("cloakpipe.co/operation/v1\nt-981\n{}", fp.hex()).as_bytes()));
    assert_ne!(derive_operation_id(&KEY, "t-981", &fp), format!("op-{}", &plain[..32]));
    assert_ne!(derive_operation_id(&KEY, "t-981", &fp), derive_operation_id(&[0x5b; 32], "t-981", &fp));
}

#[test]
fn the_same_call_in_another_task_is_another_operation() {
    use cloakpipe_release::action::derive_operation_id;
    let fp = fingerprint(&release(), "crm.patch", &json!({"stage": "review"}));
    let other = fingerprint(&release(), "crm.patch", &json!({"stage": "qualified"}));
    let d = |t: &str, fp: &ToolCallFingerprint| derive_operation_id(&KEY, t, fp);
    assert_eq!(d("t-981", &fp), d("t-981", &fp));
    assert_ne!(d("t-981", &fp), d("t-982", &fp));
    assert_ne!(d("t-981", &fp), d("t-981", &other));
    // The fingerprint is fixed-length hex, so the input splits one way only.
    assert_ne!(d("t-9\n", &fp), d("t-9", &fp));
}
