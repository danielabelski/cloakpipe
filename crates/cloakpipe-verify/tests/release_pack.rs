//! Release audit packs (docs/AUDIT_PACK.md): build with the real producers,
//! verify offline, and reject tampering of every section.

mod common;

use base64::prelude::*;
use cloakpipe_cert::statement::Status;
use cloakpipe_verify::pack::{
    verify_pack, verify_pack_bytes, BuildError, GovernanceEvent, PackReport, SentinelAction, SentinelOp, VerifyOptions,
    GOVERNANCE_LIMITATION, PACK_API_VERSION, PACK_KIND,
};
use common::*;
use serde_json::{json, Value};

fn check(doc: &Value) -> PackReport {
    verify_pack_bytes(&to_bytes(doc), &options())
}

fn assert_ok(r: &PackReport) {
    assert!(r.ok, "expected PASS, failures: {:#?}", r.failures);
    assert!(r.failures.is_empty());
}

#[track_caller]
fn assert_fails(r: &PackReport, needle: &str) {
    assert!(!r.ok, "expected FAIL mentioning {needle:?}");
    assert!(r.failures.iter().any(|f| f.contains(needle)), "no failure mentions {needle:?}: {:#?}", r.failures);
}

// ── The happy path ──────────────────────────────────────────────────────

#[test]
fn a_built_pack_verifies() {
    let p = pack();
    let r = check(&serde_json::to_value(&p).unwrap());
    assert_ok(&r);
    assert_eq!(r.release.as_deref(), Some(release().as_str()));
    assert_eq!(r.agent.as_deref(), Some("support-agent"));
    assert_eq!(r.version.as_deref(), Some("184"));
    assert_eq!(r.signer.as_deref(), Some(trusted(EXPORTER_SEED).keyid.as_str()));
    assert_eq!(r.digest.as_deref(), Some(p.digest.as_str()));
    assert_eq!(r.runs.len(), 1);
    assert_eq!(r.certifications.len(), 1);
    assert_eq!(r.certifications[0].status, Status::Valid);
    assert!(r.certifications[0].certified);
    assert_eq!(r.ledger.len(), 1);
    assert_eq!(r.ledger[0].records, 6);
    assert_eq!(r.ledger[0].release_hops, 4);
    assert_eq!(r.ledger[0].other_hops, 2);
}

#[test]
fn the_wire_format_uses_the_documented_field_names() {
    let doc = pack_value();
    let keys = |v: &Value| v.as_object().unwrap().keys().cloned().collect::<Vec<_>>();
    assert_eq!(keys(&doc), ["apiVersion", "digest", "kind", "signature", "spec"]);
    assert_eq!(doc["apiVersion"], PACK_API_VERSION);
    assert_eq!(doc["kind"], PACK_KIND);
    assert_eq!(
        keys(&doc["spec"]),
        [
            "certifications",
            "createdAt",
            "evaluationRuns",
            "exporter",
            "governance",
            "ledgerExports",
            "limitations",
            "release"
        ]
    );
    assert_eq!(keys(&doc["spec"]["release"]), ["hash", "manifest"]);
    assert_eq!(keys(&doc["spec"]["governance"]), ["attestedBy", "events"]);
    assert_eq!(doc["spec"]["governance"]["attestedBy"], "exporter");
    assert_eq!(keys(&doc["signature"]), ["keyid", "sig"]);
    assert!(doc["digest"].as_str().unwrap().starts_with("sha256:"));
    let promotion = &doc["spec"]["governance"]["events"][2];
    assert_eq!(promotion["type"], "release_promoted");
    assert_eq!(keys(promotion), ["actor", "at", "breakGlass", "environment", "fromRelease", "type"]);
}

#[test]
fn the_pack_states_the_governance_limitation() {
    let doc = pack_value();
    let limits: Vec<&str> =
        doc["spec"]["limitations"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert!(limits.contains(&GOVERNANCE_LIMITATION), "{limits:?}");
    let r = check(&doc);
    assert!(r.limitations.iter().any(|l| l == GOVERNANCE_LIMITATION), "{:?}", r.limitations);
}

#[test]
fn the_report_has_a_status_timeline() {
    let r = check(&pack_value());
    let events: Vec<&str> = r.timeline.iter().map(|t| t.event.as_str()).collect();
    // In time order.
    let times: Vec<&str> = r.timeline.iter().map(|t| t.at.as_str()).collect();
    let mut sorted = times.clone();
    sorted.sort();
    assert_eq!(times, sorted);
    assert!(events.contains(&"registered"));
    assert!(events.contains(&"certification_issued"));
    assert!(events.contains(&"runtime_first_hop"));
    assert!(events.iter().filter(|e| **e == "promoted").count() == 2);
    let prod = r.environments.iter().find(|e| e.environment == "production").expect("production status");
    assert!(prod.live);
    assert_eq!(prod.since, "2026-10-02T00:00:00Z");
    assert_eq!(prod.basis, "certified");
    let text = r.render_text();
    assert!(text.starts_with("PASS"), "{text}");
    assert!(text.contains("production"), "{text}");
    assert!(text.contains(&release()), "{text}");
    assert!(text.contains("TIMELINE"), "{text}");
    assert!(text.contains(GOVERNANCE_LIMITATION), "{text}");
}

#[test]
fn a_pack_without_ledger_or_promotions_still_verifies() {
    let p = cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .run(run())
        .certification(envelope())
        .event(registered())
        .build(&key(EXPORTER_SEED))
        .unwrap();
    assert_ok(&check(&serde_json::to_value(p).unwrap()));
}

// ── Pack signature and digest ───────────────────────────────────────────

#[test]
fn an_untrusted_exporter_fails() {
    let doc = resign(pack_value(), 99);
    assert_fails(&check(&doc), "not trusted");
}

#[test]
fn a_ledger_or_cert_key_does_not_vouch_for_the_pack_unless_trusted() {
    // The cert key is trusted for certifications only.
    let doc = resign(pack_value(), CERT_SEED);
    assert_fails(&check(&doc), "signature");
}

#[test]
fn a_forged_signature_fails() {
    let mut doc = pack_value();
    let mut sig = BASE64_STANDARD.decode(doc["signature"]["sig"].as_str().unwrap()).unwrap();
    sig[0] ^= 1;
    doc["signature"]["sig"] = json!(BASE64_STANDARD.encode(sig));
    assert_fails(&check(&doc), "signature");
}

#[test]
fn a_wrong_digest_fails() {
    let mut doc = pack_value();
    doc["digest"] = json!(format!("sha256:{}", "00".repeat(32)));
    assert_fails(&check(&doc), "digest");
}

/// Changing any section without the exporter's key breaks the signature.
#[test]
fn tampering_any_section_without_resigning_fails() {
    type Edit = Box<dyn Fn(&mut Value)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("manifest", Box::new(|d| d["spec"]["release"]["manifest"]["metadata"]["version"] = json!("185"))),
        ("run", Box::new(|d| d["spec"]["evaluationRuns"][0]["cases"][0]["status"] = json!("fail"))),
        ("certification", Box::new(|d| d["spec"]["certifications"].as_array_mut().unwrap().clear())),
        ("event", Box::new(|d| d["spec"]["governance"]["events"][2]["actor"] = json!("mallory"))),
        ("ledger", Box::new(|d| d["spec"]["ledgerExports"].as_array_mut().unwrap().clear())),
        ("limitations", Box::new(|d| d["spec"]["limitations"].as_array_mut().unwrap().clear())),
        ("exporter", Box::new(|d| d["spec"]["exporter"] = json!("someone-else"))),
    ];
    for (section, edit) in edits {
        let mut doc = pack_value();
        edit(&mut doc);
        let r = check(&doc);
        assert!(!r.ok, "tampered {section} must fail");
        assert!(r.failures.iter().any(|f| f.contains("digest")), "{section}: {:#?}", r.failures);
    }
}

// ── Each section, tampered and re-signed by the exporter ────────────────

#[test]
fn a_manifest_that_does_not_hash_to_the_release_fails() {
    let mut doc = pack_value();
    doc["spec"]["release"]["manifest"]["spec"]["model"]["ref"] = json!("model:openai/gpt-5@2026-09-01");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "does not recompute");
}

#[test]
fn a_declared_hash_that_is_not_canonical_fails() {
    let mut doc = pack_value();
    doc["spec"]["release"]["hash"] = json!(release().to_uppercase().replace("SHA256:", "sha256:"));
    assert!(!check(&resign(doc, EXPORTER_SEED)).ok);
}

#[test]
fn an_uncertifiable_manifest_fails() {
    let mut doc = pack_value();
    doc["spec"]["release"]["manifest"]["spec"]["model"]["ref"] = json!("model:openai/gpt-5@latest");
    let mut m: cloakpipe_release::AgentRelease =
        serde_json::from_value(doc["spec"]["release"]["manifest"].clone()).unwrap();
    m.spec.model.reference = "model:openai/gpt-5@latest".into();
    doc["spec"]["release"]["hash"] = json!(m.manifest_hash().to_string());
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "manifest");
}

#[test]
fn a_run_for_another_release_fails() {
    let mut doc = pack_value();
    doc["spec"]["evaluationRuns"] = json!([run_for(&other_release())]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "is not this release");
}

#[test]
fn a_structurally_invalid_run_fails() {
    let mut doc = pack_value();
    doc["spec"]["evaluationRuns"][0]["covers"] = json!(["vibes"]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "evaluationRuns[0]");
}

#[test]
fn duplicate_runs_fail() {
    let mut doc = pack_value();
    let r = doc["spec"]["evaluationRuns"][0].clone();
    doc["spec"]["evaluationRuns"].as_array_mut().unwrap().push(r);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "duplicate");
}

#[test]
fn a_certification_citing_a_run_missing_from_the_pack_fails() {
    let mut doc = pack_value();
    doc["spec"]["evaluationRuns"] = json!([]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "not in the pack");
}

#[test]
fn a_tampered_certification_payload_fails() {
    let mut doc = pack_value();
    let payload = doc["spec"]["certifications"][0]["payload"].as_str().unwrap().to_string();
    let mut st: Value = serde_json::from_slice(&BASE64_STANDARD.decode(payload).unwrap()).unwrap();
    st["predicate"]["certification"]["environment"] = json!("anything");
    doc["spec"]["certifications"][0]["payload"] = json!(BASE64_STANDARD.encode(serde_json::to_vec(&st).unwrap()));
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "certifications[0]");
}

#[test]
fn a_certification_by_an_untrusted_key_fails() {
    let mut doc = pack_value();
    doc["spec"]["certifications"] = json!([sign_cert(&certification(), 42)]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "certifications[0]");
}

#[test]
fn without_cert_trust_no_certification_verifies() {
    let r = verify_pack(&pack_value(), &VerifyOptions { cert_trusted: vec![], ..options() });
    assert_fails(&r, "certifications[0]");
    assert_fails(&r, "break_glass");
}

// ── Key roles (exporter, ledger signer, certification issuer) ───────────

#[test]
fn the_exporter_key_cannot_certify_its_own_promotion() {
    let mut doc = pack_value();
    doc["spec"]["certifications"] = json!([sign_cert(&certification(), EXPORTER_SEED)]);
    let r = check(&resign(doc, EXPORTER_SEED));
    assert_fails(&r, "certifications[0]");
    assert_fails(&r, "break_glass");
}

#[test]
fn the_ledger_key_cannot_sign_the_pack() {
    assert_fails(&check(&resign(pack_value(), LEDGER_SEED)), "not trusted");
}

#[test]
fn a_ledger_export_signed_by_the_exporter_key_fails() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"] = json!([ledger_with(2, 0, EXPORTER_SEED)]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "not trusted");
}

#[test]
fn a_key_trusted_for_two_roles_fails() {
    let doc = pack_value();
    let both = VerifyOptions { cert_trusted: vec![trusted(CERT_SEED), trusted(EXPORTER_SEED)], ..options() };
    assert_fails(&verify_pack(&doc, &both), "more than one role");
    let both = VerifyOptions { ledger_trusted: vec![trusted(LEDGER_SEED), trusted(EXPORTER_SEED)], ..options() };
    assert_fails(&verify_pack(&doc, &both), "more than one role");
    let both = VerifyOptions { ledger_trusted: vec![trusted(LEDGER_SEED), trusted(CERT_SEED)], ..options() };
    assert_fails(&verify_pack(&doc, &both), "more than one role");
}

#[test]
fn a_certification_about_another_release_fails() {
    let mut c = certification();
    c.release = other_release();
    c.decision.release = other_release();
    let mut doc = pack_value();
    doc["spec"]["certifications"] = json!([sign_cert(&c, CERT_SEED)]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "certifications[0]");
}

#[test]
fn duplicate_certifications_fail() {
    let mut doc = pack_value();
    let c = doc["spec"]["certifications"][0].clone();
    doc["spec"]["certifications"].as_array_mut().unwrap().push(c);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "duplicate");
}

#[test]
fn an_expired_certification_is_reported_not_failed() {
    let opts = VerifyOptions { now: "2026-11-15T00:00:00Z".parse().unwrap(), ..options() };
    let r = verify_pack(&pack_value(), &opts);
    assert_ok(&r);
    assert_eq!(r.certifications[0].status, Status::Expired);
    assert!(r.timeline.iter().any(|t| t.event == "certification_expired"), "{:#?}", r.timeline);
}

// ── Governance consistency ──────────────────────────────────────────────

#[test]
fn a_production_promotion_without_a_valid_certification_fails() {
    // Promoted before the certification was issued.
    let p = pack_with(vec![registered(), promoted("production", "2026-09-30T18:00:00Z", false, None)]);
    let r = check(&serde_json::to_value(p).unwrap());
    assert_fails(&r, "break_glass");
}

#[test]
fn a_production_promotion_with_only_a_staging_certification_fails() {
    let c = certification_with("cert-staging", "staging", "certified", ISSUED_AT, VALID_UNTIL);
    let p = cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .run(run())
        .certification(sign_cert(&c, CERT_SEED))
        .event(registered())
        .event(promoted("production", "2026-10-02T00:00:00Z", false, None))
        .build(&key(EXPORTER_SEED))
        .unwrap();
    assert_fails(&check(&serde_json::to_value(p).unwrap()), "break_glass");
}

#[test]
fn a_production_promotion_on_a_blocked_decision_fails() {
    let c = certification_with("cert-blocked", "production", "blocked", ISSUED_AT, VALID_UNTIL);
    let p = cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .run(run())
        .certification(sign_cert(&c, CERT_SEED))
        .event(registered())
        .event(promoted("production", "2026-10-02T00:00:00Z", false, None))
        .build(&key(EXPORTER_SEED))
        .unwrap();
    assert_fails(&check(&serde_json::to_value(p).unwrap()), "break_glass");
}

#[test]
fn a_break_glass_promotion_with_a_reason_passes_and_is_shown() {
    let p =
        pack_with(vec![registered(), promoted("production", "2026-09-30T18:00:00Z", true, Some("SEV1 hotfix INC-42"))]);
    let r = check(&serde_json::to_value(p).unwrap());
    assert_ok(&r);
    let prod = r.environments.iter().find(|e| e.environment == "production").unwrap();
    assert_eq!(prod.basis, "break_glass");
    assert!(r.timeline.iter().any(|t| t.detail.contains("BREAK-GLASS") && t.detail.contains("INC-42")));
    assert!(!r.warnings.is_empty(), "a break-glass promotion is worth a warning");
}

#[test]
fn a_break_glass_promotion_without_a_reason_fails() {
    for reason in [None, Some("   ")] {
        let p = pack_with(vec![registered(), promoted("production", "2026-09-30T18:00:00Z", true, reason)]);
        assert_fails(&check(&serde_json::to_value(p).unwrap()), "reason");
    }
}

#[test]
fn a_promotion_after_revocation_needs_break_glass() {
    let digest = statement_digest(&envelope());
    let revoked = GovernanceEvent::CertificationRevoked {
        at: "2026-10-01T12:00:00Z".into(),
        actor: "sentinel:block-rate".into(),
        statement_digest: digest,
        reason: "guardrail_block_rate 0.4 > 0.2".into(),
    };
    let p = pack_with(vec![registered(), revoked, promoted("production", "2026-10-02T00:00:00Z", false, None)]);
    let r = check(&serde_json::to_value(p).unwrap());
    assert_fails(&r, "break_glass");
    assert_eq!(r.certifications[0].status, Status::Revoked);
}

#[test]
fn a_revocation_after_promotion_is_reported_as_revoked() {
    let digest = statement_digest(&envelope());
    let mut evs = events();
    evs.push(GovernanceEvent::SentinelBreach {
        at: "2026-10-04T00:00:00Z".into(),
        actor: "sentinel:block-rate".into(),
        sentinel: "block-rate".into(),
        environment: "production".into(),
        metric: "guardrail_block_rate".into(),
        op: SentinelOp::Gt,
        threshold: 0.2,
        value: 0.4,
        calls: 50,
        action: SentinelAction::Revoke,
    });
    evs.push(GovernanceEvent::CertificationRevoked {
        at: "2026-10-04T00:00:00Z".into(),
        actor: "sentinel:block-rate".into(),
        statement_digest: digest.clone(),
        reason: "sentinel breach".into(),
    });
    let r = check(&serde_json::to_value(pack_with(evs)).unwrap());
    assert_ok(&r);
    assert_eq!(r.certifications[0].status, Status::Revoked);
    assert!(!r.certifications[0].certified);
    assert_eq!(r.certifications[0].revoked_at.as_deref(), Some("2026-10-04T00:00:00Z"));
    assert!(r.timeline.iter().any(|t| t.event == "sentinel_breach"));
    assert!(r.timeline.iter().any(|t| t.event == "certification_revoked"));
}

#[test]
fn revoking_a_certification_not_in_the_pack_fails() {
    let mut evs = events();
    evs.push(GovernanceEvent::CertificationRevoked {
        at: "2026-10-04T00:00:00Z".into(),
        actor: "bob".into(),
        statement_digest: "ff".repeat(32),
        reason: "x".into(),
    });
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "not in the pack");
}

#[test]
fn revoking_twice_fails() {
    let digest = statement_digest(&envelope());
    let rev = |at: &str| GovernanceEvent::CertificationRevoked {
        at: at.into(),
        actor: "bob".into(),
        statement_digest: digest.clone(),
        reason: "x".into(),
    };
    let mut evs = events();
    evs.push(rev("2026-10-04T00:00:00Z"));
    evs.push(rev("2026-10-05T00:00:00Z"));
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "more than once");
}

#[test]
fn an_inconsistent_sentinel_breach_fails() {
    let mut evs = events();
    evs.push(GovernanceEvent::SentinelBreach {
        at: "2026-10-04T00:00:00Z".into(),
        actor: "sentinel:latency".into(),
        sentinel: "latency".into(),
        environment: "production".into(),
        metric: "p95_latency_ms".into(),
        op: SentinelOp::Gt,
        threshold: 900.0,
        value: 100.0,
        calls: 50,
        action: SentinelAction::Alert,
    });
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "does not breach");
}

// Environments are a closed set, spelled exactly: a near-miss of
// `production` must not slip past the certification rule.
#[test]
fn an_unknown_or_misspelled_environment_fails() {
    for env in ["Production", "production ", " production", "prod", "PRODUCTION", "prd", "dev", ""] {
        let p = pack_with(vec![registered(), promoted(env, "2026-10-02T00:00:00Z", false, None)]);
        assert_fails(&check(&serde_json::to_value(p).unwrap()), "environment");
    }
    let mut evs = events();
    evs.push(GovernanceEvent::ReleaseSuperseded {
        at: "2026-10-05T00:00:00Z".into(),
        actor: "alice@acme".into(),
        environment: "Production".into(),
        to_release: other_release(),
    });
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "environment");
    let mut evs = events();
    evs.push(breach("prod", SentinelAction::Alert, "2026-10-04T00:00:00Z"));
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "environment");
}

#[test]
fn every_known_environment_is_accepted() {
    let mut evs = vec![registered()];
    for (i, env) in ["draft", "candidate", "staging", "rollback"].iter().enumerate() {
        evs.push(promoted(env, &format!("2026-09-30T1{i}:00:00Z"), false, None));
    }
    assert_ok(&check(&serde_json::to_value(pack_with(evs)).unwrap()));
}

fn breach(environment: &str, action: SentinelAction, at: &str) -> GovernanceEvent {
    GovernanceEvent::SentinelBreach {
        at: at.into(),
        actor: "sentinel:block-rate".into(),
        sentinel: "block-rate".into(),
        environment: environment.into(),
        metric: "guardrail_block_rate".into(),
        op: SentinelOp::Gt,
        threshold: 0.2,
        value: 0.4,
        calls: 50,
        action,
    }
}

fn revoke(at: &str) -> GovernanceEvent {
    GovernanceEvent::CertificationRevoked {
        at: at.into(),
        actor: "sentinel:block-rate".into(),
        statement_digest: statement_digest(&envelope()),
        reason: "sentinel breach".into(),
    }
}

#[test]
fn a_revoking_sentinel_breach_without_the_revocation_fails() {
    let mut evs = events();
    evs.push(breach("production", SentinelAction::Revoke, "2026-10-04T00:00:00Z"));
    let r = check(&serde_json::to_value(pack_with(evs)).unwrap());
    assert_fails(&r, "sentinel");
}

#[test]
fn a_revoking_sentinel_breach_is_consistent_with_the_revocation_before_or_after_it() {
    // CloakPipe Cloud revokes first and records the breach after; a breach
    // folded into an earlier window row can carry an earlier time.
    for evs in [
        vec![revoke("2026-10-04T00:00:00Z"), breach("production", SentinelAction::Revoke, "2026-10-04T00:00:01Z")],
        vec![breach("production", SentinelAction::Revoke, "2026-10-04T00:00:00Z"), revoke("2026-10-04T00:05:00Z")],
    ] {
        let mut all = events();
        all.extend(evs);
        assert_ok(&check(&serde_json::to_value(pack_with(all)).unwrap()));
    }
}

#[test]
fn an_alerting_breach_or_one_with_nothing_to_revoke_needs_no_revocation() {
    let mut evs = events();
    evs.push(breach("production", SentinelAction::Alert, "2026-10-04T00:00:00Z"));
    evs.push(breach("staging", SentinelAction::Revoke, "2026-10-04T00:00:00Z"));
    assert_ok(&check(&serde_json::to_value(pack_with(evs)).unwrap()));
}

#[test]
fn a_live_production_release_without_a_valid_certification_warns() {
    let mut evs = events();
    evs.push(GovernanceEvent::CertificationRevoked {
        at: "2026-10-03T00:00:00Z".into(),
        actor: "bob@acme".into(),
        statement_digest: statement_digest(&envelope()),
        reason: "key compromise".into(),
    });
    let r = check(&serde_json::to_value(pack_with(evs)).unwrap());
    assert_ok(&r);
    assert!(
        r.warnings.iter().any(|w| w.contains("production") && w.contains("no certification valid now")),
        "{:#?}",
        r.warnings
    );
    // Expiry is the same situation.
    let opts = VerifyOptions { now: "2026-11-15T00:00:00Z".parse().unwrap(), ..options() };
    let r = verify_pack(&pack_value(), &opts);
    assert!(r.warnings.iter().any(|w| w.contains("no certification valid now")), "{:#?}", r.warnings);
    // A certified live release does not warn.
    assert!(check(&pack_value()).warnings.is_empty());
}

#[test]
fn a_pack_without_a_registration_fails() {
    let p = cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .run(run())
        .certification(envelope())
        .event(promoted("production", "2026-10-02T00:00:00Z", false, None));
    assert!(matches!(p.clone().build(&key(EXPORTER_SEED)), Err(BuildError::MissingRegistration)));
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"].as_array_mut().unwrap().remove(0);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "release_registered");
}

#[test]
fn the_registration_must_come_first() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][0]["at"] = json!("2026-09-30T12:00:00Z");
    doc["spec"]["governance"]["events"].as_array_mut().unwrap().swap(0, 1);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "first");
}

#[test]
fn a_promotion_from_this_release_fails() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][2]["fromRelease"] = json!(release());
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "fromRelease");
}

#[test]
fn a_revocation_before_the_certification_was_issued_fails() {
    let evs = vec![
        registered(),
        GovernanceEvent::CertificationRevoked {
            at: "2026-09-30T10:00:00Z".into(),
            actor: "bob@acme".into(),
            statement_digest: statement_digest(&envelope()),
            reason: "x".into(),
        },
    ];
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "before");
}

#[test]
fn events_out_of_order_fail() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"].as_array_mut().unwrap().swap(0, 2);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "order");
}

#[test]
fn events_after_now_or_after_creation_fail() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][2]["at"] = json!("2026-10-06T12:00:00Z");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "createdAt");
    let opts = VerifyOptions { now: "2026-10-05T00:00:00Z".parse().unwrap(), ..options() };
    assert_fails(&verify_pack(&pack_value(), &opts), "after now");
}

#[test]
fn unparseable_timestamps_fail() {
    for bad in ["2026-10-02 00:00:00Z", "yesterday", ""] {
        let mut doc = pack_value();
        doc["spec"]["governance"]["events"][2]["at"] = json!(bad);
        assert_fails(&check(&resign(doc, EXPORTER_SEED)), "RFC 3339");
    }
}

#[test]
fn an_empty_actor_fails() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][1]["actor"] = json!(" ");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "actor");
}

#[test]
fn a_registration_that_does_not_match_the_manifest_fails() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][0]["version"] = json!("185");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "registered");
}

#[test]
fn a_superseding_release_must_be_another_release() {
    let mut evs = events();
    evs.push(GovernanceEvent::ReleaseSuperseded {
        at: "2026-10-05T00:00:00Z".into(),
        actor: "alice@acme".into(),
        environment: "production".into(),
        to_release: release(),
    });
    assert_fails(&check(&serde_json::to_value(pack_with(evs)).unwrap()), "toRelease");
}

#[test]
fn superseded_environments_are_no_longer_live() {
    let mut evs = events();
    evs.push(GovernanceEvent::ReleaseSuperseded {
        at: "2026-10-05T00:00:00Z".into(),
        actor: "alice@acme".into(),
        environment: "production".into(),
        to_release: other_release(),
    });
    let r = check(&serde_json::to_value(pack_with(evs)).unwrap());
    assert_ok(&r);
    let prod = r.environments.iter().find(|e| e.environment == "production").unwrap();
    assert!(!prod.live);
    assert_eq!(prod.until.as_deref(), Some("2026-10-05T00:00:00Z"));
}

#[test]
fn an_unknown_event_type_or_field_fails() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][1]["type"] = json!("release_teleported");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "malformed");
    let mut doc = pack_value();
    doc["spec"]["governance"]["events"][1]["approvedBy"] = json!("nobody");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "malformed");
}

#[test]
fn an_unknown_attestation_fails() {
    let mut doc = pack_value();
    doc["spec"]["governance"]["attestedBy"] = json!("actors");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "attestedBy");
}

// ── Ledger ──────────────────────────────────────────────────────────────

#[test]
fn a_tampered_ledger_hop_fails() {
    let mut doc = pack_value();
    let rec = &mut doc["spec"]["ledgerExports"][0]["records"][1]["canonical_bytes"];
    *rec = json!(rec.as_str().unwrap().replace("hop=mcp_tool_result", "hop=unmask"));
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "ledgerExports[0]");
}

#[test]
fn a_dropped_ledger_hop_fails() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"][0]["records"].as_array_mut().unwrap().remove(1);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "ledgerExports[0]");
}

#[test]
fn a_ledger_from_an_untrusted_signer_fails() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"] = json!([ledger_with(2, 0, 77)]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "not trusted");
}

#[test]
fn a_ledger_with_no_hop_for_this_release_fails() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"] = json!([ledger_with(0, 3, LEDGER_SEED)]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "no hop bound to this release");
}

#[test]
fn a_ledger_export_without_a_signed_chain_tip_fails() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"][0]["format_version"] = json!(3);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "v4");
}

#[test]
fn a_hop_whose_metadata_does_not_parse_one_way_fails() {
    let mut doc = pack_value();
    let rec = &mut doc["spec"]["ledgerExports"][0]["records"][4]["canonical_bytes"];
    *rec = json!(format!("{}gate=id:x=y;", rec.as_str().unwrap()));
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "metadata");
}

/// The reviewer's injection: an opaque id that spells out a release binding.
/// The ledger refuses to build it, so canonical metadata reads one way only.
#[test]
fn the_ledger_refuses_an_opaque_id_that_could_forge_a_binding() {
    let forged = format!("x;release_hash=hash:{}", release().trim_start_matches("sha256:"));
    let r = cloakpipe_ledger::RecordBuilder::new()
        .metadata("gate", cloakpipe_ledger::MetadataValue::OpaqueId(forged))
        .build();
    assert!(r.is_err(), "{r:?}");
}

#[test]
fn a_key_merely_ending_in_release_hash_is_not_a_binding() {
    let mut store = cloakpipe_ledger::LedgerStore::open(":memory:").unwrap();
    let tenant = uuid::Uuid::from_u128(42);
    for (seq, bound) in [(0, true), (1, false)] {
        let mut b = cloakpipe_ledger::RecordBuilder::new()
            .seq(seq)
            .tenant(tenant)
            .metadata("prev_release_hash", cloakpipe_ledger::MetadataValue::Hash(release_bytes()));
        if bound {
            b = b.release(release_bytes());
        }
        let mut r = b.build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    let signer = cloakpipe_ledger::Ed25519Signer::from_bytes(&[LEDGER_SEED; 32]);
    let bundle = to_verify_bundle(cloakpipe_ledger::export::export_bundle(&store, &tenant, &signer).unwrap());
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"] = json!([bundle]);
    let r = check(&resign(doc, EXPORTER_SEED));
    assert_ok(&r);
    assert_eq!((r.ledger[0].release_hops, r.ledger[0].other_hops), (1, 1));
}

#[test]
fn the_same_ledger_export_twice_fails() {
    let p = builder_with(events()).ledger_export(ledger());
    assert!(matches!(p.clone().build(&key(EXPORTER_SEED)), Err(BuildError::Ledger { index: 1, .. })));
    let mut doc = pack_value();
    let l = doc["spec"]["ledgerExports"][0].clone();
    doc["spec"]["ledgerExports"].as_array_mut().unwrap().push(l);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "overlaps");
}

#[test]
fn hops_are_counted_by_type() {
    let r = check(&pack_value());
    let l = &r.ledger[0];
    assert_eq!(l.release_hops_by_type.get("mcp_tool_call"), Some(&2));
    assert_eq!(l.release_hops_by_type.get("mcp_tool_result"), Some(&2));
    assert_eq!(l.first_hop_at.as_deref(), Some("2026-10-03T10:00:00Z"));
}

/// Operation outcomes (docs/ACTION_BOUNDARY.md): a result hop with
/// `operation_state=unknown`, then the operator's reconciliation, are their
/// own release-bound categories in the auditor's report.
#[test]
fn operation_reconciliation_hops_are_counted_by_type() {
    use cloakpipe_ledger::{Hop, MetadataValue, RecordBuilder};
    let mut store = cloakpipe_ledger::LedgerStore::open(":memory:").unwrap();
    let tenant = uuid::Uuid::from_u128(42);
    let ts: chrono::DateTime<chrono::Utc> = "2026-10-03T10:00:00Z".parse().unwrap();
    let op = || MetadataValue::OpaqueId("op-0123456789abcdef0123456789abcdef".into());
    let hops = [
        (Hop::McpToolCall, None),
        (Hop::McpToolResult, Some("unknown")),
        (Hop::OperationReconciled, Some("done")),
    ];
    for (seq, (hop, state)) in hops.into_iter().enumerate() {
        let mut b = RecordBuilder::new().seq(seq as u64).tenant(tenant).ts(ts).hop(hop).release(release_bytes()).metadata("operation_id", op());
        if let Some(state) = state {
            b = b.metadata("operation_state", MetadataValue::OpaqueId(state.into()));
        }
        let mut r = b.build().unwrap();
        store.append(&tenant, &mut r).unwrap();
    }
    let signer = cloakpipe_ledger::Ed25519Signer::from_bytes(&[LEDGER_SEED; 32]);
    let bundle = to_verify_bundle(cloakpipe_ledger::export::export_bundle(&store, &tenant, &signer).unwrap());
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"] = json!([bundle]);
    let r = check(&resign(doc, EXPORTER_SEED));
    assert_ok(&r);
    let l = &r.ledger[0];
    assert_eq!(l.release_hops, 3);
    assert_eq!(l.release_hops_by_type.get("operation_reconciled"), Some(&1));
    assert_eq!(l.release_hops_by_type.get("mcp_tool_result"), Some(&1));
}

// ── Malformed documents ─────────────────────────────────────────────────

#[test]
fn not_json_fails() {
    let r = verify_pack_bytes(b"not json", &options());
    assert_fails(&r, "JSON");
}

#[test]
fn duplicate_keys_fail() {
    let text = String::from_utf8(to_bytes(&pack_value())).unwrap();
    let dup = text.replacen("\"kind\": \"ReleaseAuditPack\"", "\"kind\": \"ReleaseAuditPack\", \"kind\": \"Other\"", 1);
    assert_ne!(dup, text);
    assert_fails(&verify_pack_bytes(dup.as_bytes(), &options()), "duplicate");
}

#[test]
fn an_unknown_spec_field_fails() {
    let mut doc = pack_value();
    doc["spec"]["approvals"] = json!([]);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "malformed");
}

#[test]
fn integers_beyond_two_to_the_53_fail() {
    let mut doc = pack_value();
    doc["spec"]["ledgerExports"][0]["records"][0]["seq"] = json!(9_007_199_254_740_993u64);
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "2^53");
}

#[test]
fn a_wrong_kind_or_api_version_fails() {
    let mut doc = pack_value();
    doc["kind"] = json!("AgentRelease");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "kind");
    let mut doc = pack_value();
    doc["apiVersion"] = json!("cloakpipe.dev/v2");
    assert_fails(&check(&resign(doc, EXPORTER_SEED)), "apiVersion");
}

// ── Builder ─────────────────────────────────────────────────────────────

#[test]
fn the_builder_sorts_events_by_time() {
    let mut evs = events();
    evs.reverse();
    let p = pack_with(evs);
    let ats: Vec<&str> = p.spec.governance.events.iter().map(|e| e.at()).collect();
    assert_eq!(ats, ["2026-09-30T09:00:00Z", "2026-09-30T12:00:00Z", "2026-10-02T00:00:00Z"]);
    assert_ok(&check(&serde_json::to_value(p).unwrap()));
}

#[test]
fn the_builder_rejects_inputs_that_could_never_verify() {
    let b = || cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT);
    let k = key(EXPORTER_SEED);
    assert!(matches!(b().run(run_for(&other_release())).build(&k), Err(BuildError::RunNotForRelease { .. })));
    let mut bad = manifest();
    bad.spec.model.reference = "model:x@latest".into();
    assert!(matches!(
        cloakpipe_verify::pack::PackBuilder::new(bad, "cli", CREATED_AT).build(&k),
        Err(BuildError::InvalidManifest(_))
    ));
    assert!(matches!(
        b().event(promoted("production", "not a time", false, None)).build(&k),
        Err(BuildError::BadTimestamp { .. })
    ));
    assert!(matches!(
        cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", "later").build(&k),
        Err(BuildError::BadTimestamp { .. })
    ));
    assert!(matches!(b().ledger_export(ledger_with(0, 2, LEDGER_SEED)).build(&k), Err(BuildError::Ledger { .. })));
    let mut c = certification();
    c.release = other_release();
    c.decision.release = other_release();
    assert!(matches!(
        b().certification(sign_cert(&c, CERT_SEED)).build(&k),
        Err(BuildError::CertificationNotForRelease { .. })
    ));
    assert!(matches!(
        cloakpipe_verify::pack::PackBuilder::new(manifest(), " ", CREATED_AT).build(&k),
        Err(BuildError::EmptyExporter)
    ));
}

#[test]
fn the_builder_accepts_a_producer_bundle_as_json() {
    let ledger_json = serde_json::to_value(ledger()).unwrap();
    let p = cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .run(run())
        .event(registered())
        .ledger_export_json(ledger_json)
        .unwrap()
        .build(&key(EXPORTER_SEED))
        .unwrap();
    assert_ok(&check(&serde_json::to_value(p).unwrap()));
    assert!(cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
        .ledger_export_json(json!({"format": "nope"}))
        .is_err());
}

#[test]
fn building_is_deterministic() {
    // Ledger exports carry their own creation time; the same inputs give the
    // same pack.
    let l = ledger();
    let build = || {
        cloakpipe_verify::pack::PackBuilder::new(manifest(), "cli", CREATED_AT)
            .run(run())
            .certification(envelope())
            .ledger_export(l.clone())
            .events(events())
            .build(&key(EXPORTER_SEED))
            .unwrap()
    };
    assert_eq!(build().digest, build().digest);
    assert_eq!(build().signature, build().signature);
}
