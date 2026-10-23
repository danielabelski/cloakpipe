//! DSSE envelopes over in-toto Statements: the signing layer shared by every
//! CloakPipe receipt.
//!
//! **Envelope** ([`sign`]): payloadType `application/vnd.in-toto+json`,
//! payload = standard base64 of the RFC 8785 canonical bytes of the
//! statement, one Ed25519 signature over the DSSE PAE:
//! `"DSSEv1" SP len(type) SP type SP len(payload) SP payload` (lengths are
//! ASCII decimal byte counts of the *raw* type and payload bytes). `sig` is
//! standard base64; `keyid` as given.
//!
//! **Signature checking** ([`verified_keyids`]) is offline: a signature
//! counts only when it verifies (strict Ed25519) under a trusted key whose
//! `keyid` matches. Never panics on any input.

use base64::prelude::*;
use chrono::{DateTime, FixedOffset};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// in-toto Statement `_type`.
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// DSSE `payloadType` of an in-toto Statement.
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// One DSSE signature: standard base64 `sig` under the key named `keyid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

/// DSSE envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub payload_type: String,
    pub payload: String,
    pub signatures: Vec<Signature>,
}

/// An Ed25519 public key trusted to sign under `keyid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub keyid: String,
    pub public_key: [u8; 32],
}

/// DSSE pre-authentication encoding:
/// `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`, with lengths
/// as ASCII decimal byte counts.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Sign a statement into a DSSE envelope: the payload is the RFC 8785
/// canonical form of `statement`, signed with Ed25519 over its [`pae`].
pub fn sign(statement: &Value, key: &SigningKey, keyid: &str) -> Envelope {
    let payload = canonical_bytes(statement);
    let sig = key.sign(&pae(PAYLOAD_TYPE, &payload));
    Envelope {
        payload_type: PAYLOAD_TYPE.into(),
        payload: BASE64_STANDARD.encode(&payload),
        signatures: vec![Signature { keyid: keyid.into(), sig: BASE64_STANDARD.encode(sig.to_bytes()) }],
    }
}

/// RFC 8785 canonical bytes of `value`.
pub fn canonical_bytes(value: &Value) -> Vec<u8> {
    // A `serde_json::Value` only holds finite numbers, which RFC 8785 always
    // accepts; the fallback is unreachable but keeps `sign` panic-free.
    serde_json_canonicalizer::to_vec(value).unwrap_or_else(|_| value.to_string().into_bytes())
}

/// Accepts any JSON document whose objects have no duplicate member names.
///
/// `serde_json::Value` silently keeps the last duplicate, so a payload with
/// duplicate keys could be read differently by another verifier; it is
/// treated as undecodable JSON.
pub struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> serde::de::Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateKeys)
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {key:?}")));
            }
            map.next_value::<NoDuplicateKeys>()?;
        }
        Ok(NoDuplicateKeys)
    }
}

/// The keyids whose signatures verify over `payload` (DSSE PAE with the
/// envelope's payloadType) under a trusted key with a matching keyid, and a
/// description of each signature that does not.
pub fn verified_keyids<'a>(
    envelope: &'a Envelope,
    payload: &[u8],
    trusted: &[TrustedKey],
) -> (BTreeSet<&'a str>, Vec<String>) {
    let message = pae(&envelope.payload_type, payload);
    let mut verified = BTreeSet::new();
    let mut problems = Vec::new();
    for (i, s) in envelope.signatures.iter().enumerate() {
        match check_signature(s, &message, trusted) {
            Ok(()) => {
                verified.insert(s.keyid.as_str());
            }
            Err(problem) => problems.push(format!("signatures[{i}] (keyid {:?}): {problem}", s.keyid)),
        }
    }
    (verified, problems)
}

fn check_signature(s: &Signature, message: &[u8], trusted: &[TrustedKey]) -> Result<(), &'static str> {
    let mut candidates = trusted.iter().filter(|k| k.keyid == s.keyid).peekable();
    if candidates.peek().is_none() {
        return Err("keyid is not trusted");
    }
    let bytes = BASE64_STANDARD.decode(&s.sig).map_err(|_| "sig is not standard base64")?;
    let sig = ed25519_dalek::Signature::from_slice(&bytes).map_err(|_| "sig is not a 64-byte Ed25519 signature")?;
    let verifies = candidates.any(|k| {
        VerifyingKey::from_bytes(&k.public_key).is_ok_and(|vk| vk.verify_strict(message, &sig).is_ok())
    });
    if verifies { Ok(()) } else { Err("sig does not verify under the trusted key") }
}

/// RFC 3339 `date-time`. chrono also accepts a space between date and time,
/// which the RFC 3339 ABNF does not (it requires `T` or `t`), so the
/// separator is checked first.
pub fn parse_rfc3339(value: &str) -> Option<DateTime<FixedOffset>> {
    if !matches!(value.as_bytes().get(10), Some(b'T' | b't')) {
        return None;
    }
    DateTime::parse_from_rfc3339(value).ok()
}
