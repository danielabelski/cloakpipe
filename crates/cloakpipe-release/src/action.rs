//! The tool-call fingerprint: the exact call an approval receipt is about.
//!
//! `SHA-256(domain || "\n" || jcs_bytes)`, where `domain` is
//! [`TOOL_CALL_FINGERPRINT_DOMAIN`] and `jcs_bytes` is the RFC 8785 encoding
//! of `{"release": "sha256:<hex>", "tool": <name>, "arguments": <raw args>}`.
//! The arguments are taken exactly as the agent sent them (no Unicode
//! normalisation, no masking), so any change to the call, however small, is
//! a different fingerprint.
//!
//! The fingerprint is operator state (receipt file names, the operations
//! store), never ledger content: low-entropy argument values could be
//! brute-forced from it. For the same reason a derived operation id, which
//! is ledger content, is keyed ([`derive_operation_id`]).

use crate::canonical::ReleaseHash;
use crate::namespace;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Domain separator of the tool-call fingerprint.
pub const TOOL_CALL_FINGERPRINT_DOMAIN: &str = namespace::TOOL_CALL_FINGERPRINT_DOMAIN;

/// Domain separator of a derived operation id.
pub const OPERATION_ID_DOMAIN: &str = namespace::OPERATION_ID_DOMAIN;

/// A tool-call fingerprint. Displays as `sha256:<hex>`; parses from that or
/// from bare lowercase hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ToolCallFingerprint(pub [u8; 32]);

impl ToolCallFingerprint {
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for ToolCallFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl std::str::FromStr for ToolCallFingerprint {
    type Err = crate::ReleaseHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefixed = if s.starts_with("sha256:") { s.to_string() } else { format!("sha256:{s}") };
        prefixed
            .parse::<ReleaseHash>()
            .map(|h| ToolCallFingerprint(h.0))
            .map_err(|_| crate::ReleaseHashParseError(s.to_string()))
    }
}

/// The fingerprint of a call to `tool` with raw `arguments` under `release`.
pub fn fingerprint(release: &ReleaseHash, tool: &str, arguments: &Value) -> ToolCallFingerprint {
    let call = json!({ "release": release.to_string(), "tool": tool, "arguments": arguments });
    let mut h = Sha256::new();
    h.update(TOOL_CALL_FINGERPRINT_DOMAIN.as_bytes());
    h.update(b"\n");
    // A `serde_json::Value` holds only finite numbers, which RFC 8785 encodes.
    h.update(serde_json_canonicalizer::to_vec(&call).expect("a JSON value encodes"));
    ToolCallFingerprint(h.finalize().into())
}

/// The operation id of a side-effecting call that has no approval receipt
/// (a receipt's `operationId` is used when there is one): `op-` + the first
/// 32 hex digits of `HMAC-SHA256(key, domain || "\n" || task_id || "\n" ||
/// fingerprint hex)`, where `domain` is [`OPERATION_ID_DOMAIN`] and `key` is
/// the operations store's own random secret. The same call in the same task
/// under the same store is the same operation; the model never supplies it.
///
/// The id is recorded in the evidence ledger, beside the release hash, and
/// task ids are low entropy: the key keeps a ledger holder from testing
/// guesses of the arguments against it (a plain hash would let them).
pub fn derive_operation_id(key: &[u8; 32], task_id: &str, fingerprint: &ToolCallFingerprint) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(OPERATION_ID_DOMAIN.as_bytes());
    mac.update(b"\n");
    mac.update(task_id.as_bytes());
    mac.update(b"\n");
    mac.update(fingerprint.hex().as_bytes());
    let digest = hex::encode(mac.finalize().into_bytes());
    format!("op-{}", &digest[..32])
}
