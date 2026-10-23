//! Signed certification attestations and offline verification.
//!
//! Contract (see docs/CERTIFICATION.md §Attestation):
//!
//! **Statement** (`statement`): an in-toto v1 Statement
//! ```json
//! { "_type": "https://in-toto.io/Statement/v1",
//!   "subject": [{ "name": "agent-release:<agent or 'unknown'>",
//!                 "digest": { "sha256": "<release hex>" } }],
//!   "predicateType": "https://cloakpipe.co/attestations/certification/v1alpha1",
//!   "predicate": { "certification": <Certification as camelCase JSON> } }
//! ```
//! `Certification.decision.release` must equal `Certification.release`.
//!
//! **Envelope** (`sign`): a DSSE envelope, payloadType
//! `application/vnd.in-toto+json`, payload = standard base64 of the
//! RFC 8785 canonical bytes of the statement, one Ed25519 signature over the
//! DSSE PAE: `"DSSEv1" SP len(type) SP type SP len(payload) SP payload`
//! (lengths are ASCII decimal byte counts of the *raw* type and payload
//! bytes). `sig` is standard base64; `keyid` as given.
//!
//! **Verification** (`verify`) is offline and deterministic (the caller
//! supplies `now`). It returns the *most severe* applicable status, in
//! precedence order Invalid > Revoked > Expired > Incomplete >
//! ValidWithLimitations > Valid, plus every reason found:
//! - **Invalid**: wrong payloadType; undecodable base64/JSON; no signature
//!   that verifies under a *trusted* key whose `keyid` matches; wrong
//!   `_type`/`predicateType` (the legacy
//!   `https://cloakpipe.dev/attestations/certification/v1alpha1` is accepted);
//!   malformed predicate; empty `certification.id`;
//!   subject digest ≠
//!   `certification.release` hex or ≠ `decision.release`; `expected_release`
//!   given and ≠ subject; `issuedAt`/`validUntil` not RFC 3339, or
//!   `validUntil` ≤ `issuedAt`; `now` < `issuedAt` (not yet valid).
//! - **Revoked**: the statement digest (sha256 hex of the decoded payload
//!   bytes) is in `revoked_statements`, or the verifying signature's keyid is
//!   in `revoked_keys`.
//! - **Expired**: `now` ≥ `validUntil`.
//! - **Incomplete**: `required_runs` given and some hash in it is not among
//!   `decision.runs[].hash`.
//! - **ValidWithLimitations**: `certification.limitations` is non-empty.
//! - **Valid**: none of the above.
//!
//! A Blocked decision can still be a Valid attestation (of a block);
//! `Report.certified` is true only when status is Valid or
//! ValidWithLimitations *and* the decision outcome is Certified.
//! Never panics on any input.

use crate::model::{Decision, Outcome};
use base64::prelude::*;
use chrono::{DateTime, FixedOffset};
use cloakpipe_release::ReleaseHash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

// The DSSE layer lives in `cloakpipe-receipt`; re-exported here so callers of
// `cloakpipe_cert::statement` keep compiling.
pub use cloakpipe_receipt::dsse::{
    canonical_bytes, pae, parse_rfc3339, sign, verified_keyids, Envelope, NoDuplicateKeys, Signature, TrustedKey,
    PAYLOAD_TYPE, STATEMENT_TYPE,
};

/// in-toto `predicateType` writers emit for a certification attestation.
/// [`verify`] also accepts the legacy `cloakpipe.dev` predicate type.
pub const PREDICATE_TYPE: &str = cloakpipe_release::namespace::CERTIFICATION_PREDICATE_TYPE;

/// The predicate body: a decision scoped to an environment and a validity
/// window, issued by a named issuer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Certification {
    /// Unique per issuance (e.g. a UUID). It is signed, so two otherwise
    /// identical certifications never share a statement digest and revoking
    /// one never revokes another.
    pub id: String,
    /// `sha256:<hex>` manifest hash of the certified release.
    pub release: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Scope, e.g. `production`.
    pub environment: String,
    pub decision: Decision,
    /// RFC 3339.
    pub issued_at: String,
    /// RFC 3339; `issued_at + policy validity`.
    pub valid_until: String,
    /// Issuer identity, e.g. `cloakpipe-cloud` or a CI workload.
    pub issuer: String,
    /// Declared scope exclusions or caveats (e.g. "locale en only").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

/// Everything verification depends on besides the envelope itself.
#[derive(Debug, Clone, Default)]
pub struct VerifyContext {
    pub trusted: Vec<TrustedKey>,
    /// sha256 hex of revoked statement payloads.
    pub revoked_statements: BTreeSet<String>,
    pub revoked_keys: BTreeSet<String>,
    /// RFC 3339 "current" time supplied by the caller.
    pub now: String,
    /// `sha256:<hex>` the attestation must be about, if known.
    pub expected_release: Option<String>,
    /// Run hashes that must be cited by the decision (evidence completeness).
    pub required_runs: Option<Vec<String>>,
}

/// Verification status; the derived order is the severity order (most
/// severe last), so the overall status is the maximum over all reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Valid,
    ValidWithLimitations,
    Incomplete,
    Expired,
    Revoked,
    Invalid,
}

/// The outcome of [`verify`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub status: Status,
    pub reasons: Vec<String>,
    /// sha256 hex of the decoded payload, when decodable.
    pub statement_digest: Option<String>,
    /// `sha256:<hex>` subject, when parseable.
    pub release: Option<String>,
    pub outcome: Option<Outcome>,
    pub certified: bool,
}

// ── Building and signing ────────────────────────────────────────────────

/// Build the in-toto Statement for a certification.
///
/// The subject digest is `c.release` without its `sha256:` prefix. This does
/// not check `c`: [`verify`] rejects a statement whose release is not a
/// manifest hash or whose `decision.release` differs from it. Non-finite
/// floats have no JSON form and become `null`, which [`verify`] rejects as a
/// malformed certification.
pub fn statement(c: &Certification) -> Value {
    // Serialising into a `Value` cannot fail for `Certification`: every map
    // key is a string (non-finite floats become `null`).
    let certification = serde_json::to_value(c).unwrap_or(Value::Null);
    let digest = c.release.strip_prefix("sha256:").unwrap_or(&c.release);
    serde_json::json!({
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": subject_name(c.agent.as_deref()),
            "digest": { "sha256": digest },
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": { "certification": certification },
    })
}

fn subject_name(agent: Option<&str>) -> String {
    format!("agent-release:{}", agent.unwrap_or("unknown"))
}

// ── Verification ────────────────────────────────────────────────────────

/// Verify an envelope offline against `ctx` (see the module contract).
pub fn verify(envelope: &Envelope, ctx: &VerifyContext) -> Report {
    let mut f = Findings::default();
    let mut report = Report {
        status: Status::Valid,
        reasons: Vec::new(),
        statement_digest: None,
        release: None,
        outcome: None,
        certified: false,
    };

    if envelope.payload_type != PAYLOAD_TYPE {
        f.invalid(format!("payloadType: expected {PAYLOAD_TYPE:?}, got {:?}", envelope.payload_type));
    }
    let Ok(payload) = BASE64_STANDARD.decode(&envelope.payload) else {
        f.invalid("payload: not standard base64");
        return f.finish(report);
    };
    let digest = hex::encode(Sha256::digest(&payload));

    check_signatures(envelope, &payload, ctx, &mut f);
    if ctx.revoked_statements.contains(&digest) {
        f.push(Status::Revoked, format!("statement {digest} is revoked"));
    }
    report.statement_digest = Some(digest);

    match serde_json::from_slice::<NoDuplicateKeys>(&payload).and_then(|_| serde_json::from_slice::<Value>(&payload)) {
        Ok(value) => check_statement(&value, ctx, &mut f, &mut report),
        Err(e) => f.invalid(format!("payload: not JSON: {e}")),
    }
    f.finish(report)
}

/// Reasons found so far, each with the status it implies.
#[derive(Default)]
struct Findings(Vec<(Status, String)>);

impl Findings {
    fn push(&mut self, status: Status, reason: impl Into<String>) {
        self.0.push((status, reason.into()));
    }

    fn invalid(&mut self, reason: impl Into<String>) {
        self.push(Status::Invalid, reason);
    }

    /// The most severe status wins; reasons keep the order they were found.
    fn finish(self, mut report: Report) -> Report {
        report.status = self.0.iter().map(|(s, _)| *s).max().unwrap_or(Status::Valid);
        report.reasons = self.0.into_iter().map(|(_, r)| r).collect();
        report.certified = report.status <= Status::ValidWithLimitations
            && report.outcome == Some(Outcome::Certified);
        report
    }
}

/// Invalid unless some signature verifies under a trusted key with a
/// matching keyid; Revoked when any verifying signature's keyid is revoked.
fn check_signatures(envelope: &Envelope, payload: &[u8], ctx: &VerifyContext, f: &mut Findings) {
    let (verified, problems) = verified_keyids(envelope, payload, &ctx.trusted);

    if verified.is_empty() {
        f.invalid("signature: no signature verifies under a trusted key with a matching keyid");
        problems.into_iter().for_each(|p| f.invalid(p));
    } else {
        for keyid in verified.into_iter().filter(|k| ctx.revoked_keys.contains(*k)) {
            f.push(Status::Revoked, format!("signing key {keyid:?} is revoked"));
        }
    }
}

/// The predicate wrapper; anything besides `certification` is malformed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predicate {
    certification: Certification,
}

fn check_statement(value: &Value, ctx: &VerifyContext, f: &mut Findings, report: &mut Report) {
    let Some(obj) = value.as_object() else {
        f.invalid("statement: not a JSON object");
        return;
    };
    if obj.get("_type").and_then(Value::as_str) != Some(STATEMENT_TYPE) {
        f.invalid(format!("_type: expected {STATEMENT_TYPE:?}"));
    }
    if !obj
        .get("predicateType")
        .and_then(Value::as_str)
        .is_some_and(cloakpipe_release::namespace::is_known_certification_predicate_type)
    {
        f.invalid(format!(
            "predicateType: expected {PREDICATE_TYPE:?} (or legacy {:?})",
            cloakpipe_release::namespace::LEGACY_CERTIFICATION_PREDICATE_TYPE
        ));
    }

    let subject = match parse_subject(obj.get("subject")) {
        Ok(subject) => {
            report.release = Some(subject.release.to_string());
            Some(subject)
        }
        Err(problem) => {
            f.invalid(problem);
            None
        }
    };
    if let (Some(expected), Some(subject)) = (&ctx.expected_release, &subject) {
        if *expected != subject.release.to_string() {
            f.invalid(format!("subject: {} is not the expected release {expected:?}", subject.release));
        }
    }

    let certification = match obj.get("predicate").map(Predicate::deserialize) {
        Some(Ok(p)) => p.certification,
        Some(Err(e)) => return f.invalid(format!("predicate: malformed certification: {e}")),
        None => return f.invalid("predicate: missing"),
    };
    report.outcome = Some(certification.decision.outcome);
    check_certification(&certification, subject.as_ref(), ctx, f);
}

/// The subject's name is not checked against the certification: the
/// contract's Invalid list covers the subject digest only.
struct Subject {
    release: ReleaseHash,
}

/// Exactly one subject with a string name and a lowercase-hex sha256 digest.
fn parse_subject(subject: Option<&Value>) -> Result<Subject, String> {
    let entries = subject.and_then(Value::as_array).ok_or("subject: expected an array")?;
    let [entry] = entries.as_slice() else {
        return Err(format!("subject: expected exactly one entry, got {}", entries.len()));
    };
    entry.get("name").and_then(Value::as_str).ok_or("subject.name: expected a string")?;
    let hex = entry
        .get("digest")
        .and_then(|d| d.get("sha256"))
        .and_then(Value::as_str)
        .ok_or("subject.digest.sha256: expected a string")?;
    let release = format!("sha256:{hex}")
        .parse()
        .map_err(|_| format!("subject.digest.sha256: {hex:?} is not 64 lowercase hex"))?;
    Ok(Subject { release })
}

fn check_certification(c: &Certification, subject: Option<&Subject>, ctx: &VerifyContext, f: &mut Findings) {
    if c.id.trim().is_empty() {
        f.invalid("certification.id: must not be empty");
    }
    if c.release.parse::<ReleaseHash>().is_err() {
        f.invalid(format!("certification.release: {:?} is not a sha256:<hex> manifest hash", c.release));
    }
    if let Some(subject) = subject {
        if subject.release.to_string() != c.release {
            f.invalid(format!(
                "subject: digest {} does not match certification.release {:?}",
                subject.release, c.release
            ));
        }
    }
    if c.decision.release != c.release {
        f.invalid(format!(
            "certification.decision.release {:?} does not match certification.release {:?}",
            c.decision.release, c.release
        ));
    }

    check_validity_window(c, ctx, f);

    if let Some(required) = &ctx.required_runs {
        let cited: BTreeSet<&str> = c.decision.runs.iter().map(|r| r.hash.as_str()).collect();
        for hash in required.iter().filter(|h| !cited.contains(h.as_str())) {
            f.push(Status::Incomplete, format!("required run {hash} is not cited by the decision"));
        }
    }

    for limitation in &c.limitations {
        f.push(Status::ValidWithLimitations, format!("limitation: {limitation}"));
    }
}

fn check_validity_window(c: &Certification, ctx: &VerifyContext, f: &mut Findings) {
    let mut parse = |field: &str, value: &str| match parse_rfc3339(value) {
        Some(t) => Some(t),
        None => {
            f.invalid(format!("{field}: {value:?} is not an RFC 3339 timestamp"));
            None
        }
    };
    let issued_at = parse("issuedAt", &c.issued_at);
    let valid_until = parse("validUntil", &c.valid_until);
    let now: Option<DateTime<FixedOffset>> = parse("now", &ctx.now);

    if let (Some(issued_at), Some(valid_until)) = (issued_at, valid_until) {
        if valid_until <= issued_at {
            f.invalid(format!("validUntil {} is not after issuedAt {}", c.valid_until, c.issued_at));
        }
    }
    let Some(now) = now else { return };
    if issued_at.is_some_and(|t| now < t) {
        f.invalid(format!("issuedAt: not yet valid (now {} is before issuedAt {})", ctx.now, c.issued_at));
    }
    if valid_until.is_some_and(|t| now >= t) {
        f.push(Status::Expired, format!("validUntil: expired at {} (now {})", c.valid_until, ctx.now));
    }
}
