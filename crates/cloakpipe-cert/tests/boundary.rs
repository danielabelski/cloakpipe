//! Two-way boundary certification (`rules.boundary`, `CaseResult.expect`).
//!
//! A release must not pass the authorization-style suites by refusing
//! everything: labelled deny cases measure blocking, labelled allow cases
//! measure over-refusal, and both must be present.

use cloakpipe_cert::import::{from_braintrust, from_json, from_junit, from_langfuse_experiment, ImportError, ImportMeta, ScoreRules};
use cloakpipe_cert::policy::{decide, DecisionInput};
use cloakpipe_cert::{
    BoundaryRule, CaseResult, CaseStatus, CertificationPolicy, Decision, EvaluationRun, Expect, Outcome, Reason,
    ReasonCode, Rules, RunSource, SourceKind, SuiteRef, API_VERSION, POLICY_KIND, RUN_KIND,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

// ── Fixtures ────────────────────────────────────────────────────────────

fn release() -> String {
    format!("sha256:{}", "ae".repeat(32))
}

fn case(id: &str, status: CaseStatus, expect: Option<Expect>) -> CaseResult {
    CaseResult { id: id.into(), critical: false, status, score: None, metrics: BTreeMap::new(), duration_ms: None, expect }
}

/// `allow_pass`/`allow_fail` allow cases and `deny_pass`/`deny_fail` deny
/// cases with the given outcomes.
fn labelled(allow_pass: usize, allow_fail: usize, deny_pass: usize, deny_fail: usize) -> Vec<CaseResult> {
    let mut out = Vec::new();
    let mut add = |prefix: &str, n: usize, status: CaseStatus, expect: Expect| {
        for i in 0..n {
            out.push(case(&format!("{prefix}{i:03}"), status, Some(expect)));
        }
    };
    add("allow-ok-", allow_pass, CaseStatus::Pass, Expect::Allow);
    add("allow-ko-", allow_fail, CaseStatus::Fail, Expect::Allow);
    add("deny-ok-", deny_pass, CaseStatus::Pass, Expect::Deny);
    add("deny-ko-", deny_fail, CaseStatus::Fail, Expect::Deny);
    out
}

fn run(run_id: &str, covers: &[&str], cases: Vec<CaseResult>) -> EvaluationRun {
    EvaluationRun {
        api_version: API_VERSION.into(),
        kind: RUN_KIND.into(),
        run_id: run_id.into(),
        release: release(),
        suite: SuiteRef { name: format!("{run_id}-suite"), version: "1".into() },
        covers: covers.iter().map(|s| s.to_string()).collect(),
        dataset: None,
        evaluators: Vec::new(),
        source: RunSource { kind: SourceKind::Native, tool: None },
        cases,
    }
}

fn boundary(suites: &[&str], min_deny: f64, min_allow: f64) -> BoundaryRule {
    BoundaryRule { suites: suites.iter().map(|s| s.to_string()).collect(), min_deny_rate: min_deny, min_allow_rate: min_allow }
}

fn policy(boundary: Option<BoundaryRule>) -> CertificationPolicy {
    CertificationPolicy {
        api_version: API_VERSION.into(),
        kind: POLICY_KIND.into(),
        name: "support-prod".into(),
        version: "12".into(),
        rules: Rules { min_coverage: 0.0, boundary, ..Rules::default() },
        validity_days: 30,
    }
}

fn standard() -> Option<BoundaryRule> {
    Some(boundary(&["authorization", "access_control", "side_effect"], 1.0, 0.9))
}

fn go(runs: &[EvaluationRun], policy: &CertificationPolicy) -> Decision {
    let rel = release();
    let required = BTreeSet::new();
    decide(&DecisionInput { release: &rel, required_suites: &required, runs, baseline_runs: &[], policy })
}

fn codes(d: &Decision) -> Vec<ReasonCode> {
    d.reasons.iter().map(|r| r.code).collect()
}

fn only(d: &Decision, code: ReasonCode) -> Vec<&Reason> {
    d.reasons.iter().filter(|r| r.code == code).collect()
}

// ── Decision ────────────────────────────────────────────────────────────

#[test]
fn refuse_everything_is_blocked_with_over_refusal() {
    // Every deny case passes (it was refused), every allow case fails (it
    // was refused too): pass rate alone would look like 50%.
    let r = run("authz", &["authorization"], labelled(0, 10, 10, 0));
    let d = go(&[r], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Blocked);
    assert_eq!(codes(&d), vec![ReasonCode::OverRefusal]);
    let reason = &d.reasons[0];
    assert_eq!(reason.suite.as_deref(), Some("authorization"));
    assert_eq!(reason.observed, Some(0.0));
    assert_eq!(reason.required, Some(0.9));
    assert!(reason.message.contains("allow rate"), "{}", reason.message);
}

#[test]
fn allow_everything_is_blocked_with_under_blocking() {
    let r = run("authz", &["authorization"], labelled(10, 0, 0, 10));
    let d = go(&[r], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Blocked);
    assert_eq!(codes(&d), vec![ReasonCode::UnderBlocking]);
    let reason = &d.reasons[0];
    assert_eq!(reason.suite.as_deref(), Some("authorization"));
    assert_eq!(reason.observed, Some(0.0));
    assert_eq!(reason.required, Some(1.0));
    assert!(reason.message.contains("deny rate"), "{}", reason.message);
}

#[test]
fn a_balanced_run_is_certified() {
    // 9/10 allowed (exactly the minimum) and every deny case blocked.
    let r = run("authz", &["authorization"], labelled(9, 1, 10, 0));
    let d = go(&[r], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn one_missed_deny_is_under_blocking_at_the_default_minimum() {
    let r = run("authz", &["authorization"], labelled(10, 0, 9, 1));
    let d = go(&[r], &policy(standard()));
    let r = only(&d, ReasonCode::UnderBlocking);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].observed, Some(0.9));
}

#[test]
fn unlabelled_cases_are_boundary_incomplete() {
    let cases = vec![case("a", CaseStatus::Pass, None), case("b", CaseStatus::Pass, None)];
    let d = go(&[run("authz", &["authorization"], cases)], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::BoundaryIncomplete]);
    assert_eq!(d.reasons[0].suite.as_deref(), Some("authorization"));
    assert!(d.reasons[0].message.contains("no labelled"), "{}", d.reasons[0].message);
}

#[test]
fn a_suite_without_allow_cases_is_boundary_incomplete() {
    // A suite of deny cases only is exactly what a refuse-everything agent
    // passes: it cannot be certified two-way.
    let d = go(&[run("authz", &["authorization"], labelled(0, 0, 5, 0))], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::BoundaryIncomplete]);
    assert!(d.reasons[0].message.contains("allow"), "{}", d.reasons[0].message);
}

#[test]
fn a_suite_without_deny_cases_is_boundary_incomplete() {
    let d = go(&[run("authz", &["authorization"], labelled(5, 0, 0, 0))], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::BoundaryIncomplete]);
    assert!(d.reasons[0].message.contains("deny"), "{}", d.reasons[0].message);
}

#[test]
fn incomplete_side_is_reported_and_the_other_side_still_checked() {
    // No deny cases, and the allow cases are refused.
    let d = go(&[run("authz", &["authorization"], labelled(0, 4, 0, 0))], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::OverRefusal, ReasonCode::BoundaryIncomplete]);
}

#[test]
fn a_listed_suite_no_run_covers_is_not_checked() {
    // Which suites a release needs comes from required suites (MissingSuite).
    let d = go(&[run("support", &["functional"], vec![case("a", CaseStatus::Pass, None)])], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn suites_not_listed_are_not_checked() {
    // A refuse-everything privacy run is not a boundary suite here.
    let d = go(&[run("privacy", &["privacy"], labelled(0, 0, 10, 0))], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn every_listed_suite_is_checked_separately() {
    let authz = run("authz", &["authorization"], labelled(10, 0, 10, 0));
    let acl = run("acl", &["access_control"], labelled(0, 10, 10, 0));
    let side = run("side", &["side_effect"], labelled(10, 0, 0, 10));
    let d = go(&[authz, acl, side], &policy(standard()));
    let got: Vec<(ReasonCode, Option<&str>)> = d.reasons.iter().map(|r| (r.code, r.suite.as_deref())).collect();
    assert_eq!(
        got,
        vec![(ReasonCode::UnderBlocking, Some("side_effect")), (ReasonCode::OverRefusal, Some("access_control"))]
    );
}

#[test]
fn cases_of_every_run_covering_a_suite_are_pooled() {
    // One run holds the deny cases, another the allow cases: complete.
    let denies = run("deny", &["authorization"], labelled(0, 0, 10, 0));
    let allows = run("allow", &["authorization", "functional"], labelled(10, 0, 0, 0));
    let d = go(&[denies.clone(), allows.clone()], &policy(standard()));
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
    // Order of runs does not matter.
    assert_eq!(d, go(&[allows, denies], &policy(standard())));
}

#[test]
fn skipped_and_errored_labelled_cases_count_as_not_passed() {
    let mut cases = labelled(9, 0, 10, 0);
    cases.push(case("allow-skip", CaseStatus::Skipped, Some(Expect::Allow)));
    cases.push(case("deny-err", CaseStatus::Error, Some(Expect::Deny)));
    let d = go(&[run("authz", &["authorization"], cases)], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::UnderBlocking]);
    assert_eq!(only(&d, ReasonCode::UnderBlocking)[0].observed, Some(10.0 / 11.0));
    // 9 of 10 allow cases passed (the skipped one counts): exactly 0.9.
    assert!(only(&d, ReasonCode::OverRefusal).is_empty());
}

#[test]
fn custom_minimums_apply() {
    let r = run("authz", &["authorization"], labelled(5, 5, 8, 2));
    let lax = policy(Some(boundary(&["authorization"], 0.8, 0.5)));
    assert_eq!(go(std::slice::from_ref(&r), &lax).outcome, Outcome::Certified);
    let strict = policy(Some(boundary(&["authorization"], 0.81, 0.51)));
    assert_eq!(codes(&go(&[r], &strict)), vec![ReasonCode::UnderBlocking, ReasonCode::OverRefusal]);
}

#[test]
fn without_a_boundary_rule_labels_are_ignored() {
    let r = run("authz", &["authorization"], labelled(0, 0, 10, 0));
    let d = go(&[r], &policy(None));
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn reason_codes_serialize_snake_case() {
    for (code, name) in [
        (ReasonCode::UnderBlocking, "under_blocking"),
        (ReasonCode::OverRefusal, "over_refusal"),
        (ReasonCode::BoundaryIncomplete, "boundary_incomplete"),
    ] {
        assert_eq!(serde_json::to_value(code).unwrap(), json!(name));
    }
}

// ── Policy model ────────────────────────────────────────────────────────

#[test]
fn boundary_policy_parses_with_defaults() {
    let p: CertificationPolicy = serde_json::from_value(json!({
        "apiVersion": API_VERSION, "kind": POLICY_KIND, "name": "p", "version": "1",
        "rules": {"boundary": {"suites": ["authorization", "access_control", "side_effect"]}}
    }))
    .unwrap();
    let b = p.rules.boundary.as_ref().unwrap();
    assert_eq!(b.min_deny_rate, 1.0);
    assert_eq!(b.min_allow_rate, 0.9);
    assert_eq!(p.validate(), Vec::<String>::new());
}

#[test]
fn boundary_policy_rejects_unknown_fields() {
    let r: Result<CertificationPolicy, _> = serde_json::from_value(json!({
        "apiVersion": API_VERSION, "kind": POLICY_KIND, "name": "p", "version": "1",
        "rules": {"boundary": {"suites": ["authorization"], "minDenyRatio": 1.0}}
    }));
    assert!(r.is_err());
}

#[test]
fn invalid_boundary_rules_are_reported() {
    let mut p = policy(Some(boundary(&["authorization", "access-control", "authorization"], 1.5, f64::NAN)));
    let issues = p.validate().join("\n");
    assert!(issues.contains("unknown assurance suite \"access-control\""), "{issues}");
    assert!(issues.contains("duplicate"), "{issues}");
    assert!(issues.contains("rules.boundary.minDenyRate"), "{issues}");
    assert!(issues.contains("rules.boundary.minAllowRate"), "{issues}");
    p.rules.boundary = Some(boundary(&[], 1.0, 0.9));
    assert!(p.validate().join("\n").contains("rules.boundary.suites"), "{:?}", p.validate());
    // An invalid policy blocks the decision.
    let d = go(&[run("authz", &["authorization"], labelled(1, 0, 1, 0))], &p);
    assert_eq!(codes(&d), vec![ReasonCode::InvalidInput]);
}

#[test]
fn policy_hash_without_boundary_is_unchanged() {
    // Pinned before `boundary` existed: an absent rule is not serialized.
    let p: CertificationPolicy = serde_json::from_value(json!({
        "apiVersion": API_VERSION, "kind": POLICY_KIND, "name": "support-prod", "version": "11",
        "rules": {"minPassRate": 0.95}
    }))
    .unwrap();
    assert!(!serde_json::to_string(&p).unwrap().contains("boundary"));
    assert_eq!(p.policy_hash(), "sha256:e9a43e48063ea9f113a965361b925c34b3e0501a94debc5a6dcee63c9bf72959");
    let with = CertificationPolicy { rules: Rules { boundary: standard(), ..p.rules.clone() }, ..p.clone() };
    assert_ne!(with.policy_hash(), p.policy_hash());
}

// ── Run model ───────────────────────────────────────────────────────────

#[test]
fn run_hash_without_labels_is_unchanged() {
    // Pinned before `expect` existed: an absent label is not serialized.
    let r = run("authz", &["authorization"], vec![case("a", CaseStatus::Pass, None), case("b", CaseStatus::Fail, None)]);
    assert!(!serde_json::to_string(&r).unwrap().contains("expect"));
    assert_eq!(r.run_hash(), "sha256:21593ec7db8411553ef9dc26d81ea4893d3448fab5668e25d7b41d93b941775d");
    let mut labelled = r.clone();
    labelled.cases[0].expect = Some(Expect::Allow);
    assert_ne!(labelled.run_hash(), r.run_hash());
}

#[test]
fn native_json_reads_expect() {
    let mut v = serde_json::to_value(run("authz", &["authorization"], labelled(1, 0, 1, 0))).unwrap();
    assert_eq!(v["cases"][0]["expect"], json!("allow"));
    assert_eq!(v["cases"][1]["expect"], json!("deny"));
    let back = from_json(&v.to_string()).unwrap();
    assert_eq!(back.cases[0].expect, Some(Expect::Allow));
    assert_eq!(back.cases[1].expect, Some(Expect::Deny));
    v["cases"][0]["expect"] = json!("maybe");
    assert!(from_json(&v.to_string()).is_err());
}

// ── JUnit ───────────────────────────────────────────────────────────────

fn meta() -> ImportMeta {
    ImportMeta {
        run_id: "authz@1".into(),
        release: release(),
        suite: SuiteRef { name: "authz".into(), version: "1".into() },
        covers: vec!["authorization".into()],
        dataset: None,
        evaluators: vec![],
        tool: Some("pytest".into()),
        critical: vec![],
    }
}

fn junit(cases: &str) -> String {
    format!(r#"<?xml version="1.0"?><testsuites><testsuite name="authz">{cases}</testsuite></testsuites>"#)
}

fn expect_prop(value: &str) -> String {
    format!(r#"<properties><property name="cloakpipe.expect" value="{value}"/></properties>"#)
}

#[test]
fn junit_reads_cloakpipe_expect() {
    let xml = junit(&format!(
        r#"<testcase classname="authz" name="reads_own_ticket">{}</testcase>
           <testcase classname="authz" name="reads_other_tenant">{}</testcase>
           <testcase classname="authz" name="unlabelled"/>"#,
        expect_prop("allow"),
        expect_prop(" deny ")
    ));
    let run = from_junit(&xml, &meta()).unwrap();
    let by_id = |id: &str| run.cases.iter().find(|c| c.id == id).unwrap().expect;
    assert_eq!(by_id("authz::reads_own_ticket"), Some(Expect::Allow));
    assert_eq!(by_id("authz::reads_other_tenant"), Some(Expect::Deny));
    assert_eq!(by_id("authz::unlabelled"), None);
}

fn junit_invalid(xml: &str) -> String {
    match from_junit(xml, &meta()) {
        Err(ImportError::Invalid(issues)) => issues.join("\n"),
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn junit_rejects_a_bad_expect_value() {
    let issues = junit_invalid(&junit(&format!(r#"<testcase name="x">{}</testcase>"#, expect_prop("refuse"))));
    assert!(issues.contains("cloakpipe.expect"), "{issues}");
    assert!(issues.contains("allow or deny"), "{issues}");
}

#[test]
fn junit_rejects_expect_given_twice() {
    let props = r#"<properties><property name="cloakpipe.expect" value="allow"/><property name="cloakpipe.expect" value="allow"/></properties>"#;
    let issues = junit_invalid(&junit(&format!(r#"<testcase name="x">{props}</testcase>"#)));
    assert!(issues.contains("more than once"), "{issues}");
}

#[test]
fn junit_rejects_expect_without_value() {
    let props = r#"<properties><property name="cloakpipe.expect"/></properties>"#;
    let issues = junit_invalid(&junit(&format!(r#"<testcase name="x">{props}</testcase>"#)));
    assert!(issues.contains("missing value"), "{issues}");
}

#[test]
fn junit_refuse_everything_report_is_blocked_end_to_end() {
    // The JUnit a refuse-everything agent produces: deny tests pass, allow
    // tests fail.
    let xml = junit(&format!(
        r#"<testcase classname="authz" name="own_ticket">{a}<failure message="refused"/></testcase>
           <testcase classname="authz" name="own_order">{a}<failure message="refused"/></testcase>
           <testcase classname="authz" name="other_tenant">{d}</testcase>
           <testcase classname="authz" name="admin_tool">{d}</testcase>"#,
        a = expect_prop("allow"),
        d = expect_prop("deny"),
    ));
    let run = from_junit(&xml, &meta()).unwrap();
    let d = go(&[run], &policy(standard()));
    assert_eq!(codes(&d), vec![ReasonCode::OverRefusal]);
}

// ── Braintrust ──────────────────────────────────────────────────────────

fn bt(metadata: serde_json::Value) -> Result<EvaluationRun, ImportError> {
    let event = json!({"id": "row", "span_id": "s", "root_span_id": "s", "is_root": true,
        "scores": {"acc": 1.0}, "metadata": metadata});
    from_braintrust(&json!({"events": [event]}).to_string(), &meta(), &ScoreRules::default())
}

#[test]
fn braintrust_reads_cloakpipe_expect_from_metadata() {
    let run = bt(json!({"case_id": "c1", "cloakpipe.expect": "deny"})).unwrap();
    assert_eq!(run.cases[0].expect, Some(Expect::Deny));
    let run = bt(json!({"case_id": "c1"})).unwrap();
    assert_eq!(run.cases[0].expect, None);
}

#[test]
fn braintrust_rejects_a_bad_expect_value() {
    for bad in [json!("refuse"), json!(null), json!(true)] {
        match bt(json!({"case_id": "c1", "cloakpipe.expect": bad})) {
            Err(ImportError::Invalid(issues)) => {
                let issues = issues.join("\n");
                assert!(issues.contains("metadata.cloakpipe.expect"), "{issues}");
            }
            other => panic!("expected Invalid for {bad}, got {other:?}"),
        }
    }
}

// ── Langfuse experiments ────────────────────────────────────────────────

fn lf(item_extra: serde_json::Value) -> Result<EvaluationRun, ImportError> {
    let experiment = json!({"id": "exp-1", "itemCount": 1, "datasetId": null});
    let mut item = json!({"experimentItemId": "item-1", "traceId": "t1", "experimentId": "exp-1",
        "scores": [{"name": "acc", "dataType": "NUMERIC", "value": 1.0}]});
    for (k, v) in item_extra.as_object().unwrap() {
        item[k] = v.clone();
    }
    let items = json!({"data": [item], "meta": {}});
    from_langfuse_experiment(&experiment.to_string(), &items.to_string(), &meta(), &ScoreRules::default())
}

#[test]
fn langfuse_experiment_reads_cloakpipe_expect_from_item_metadata() {
    let run = lf(json!({"metadata": {"cloakpipe.expect": "allow"}})).unwrap();
    assert_eq!(run.cases[0].expect, Some(Expect::Allow));
    assert_eq!(lf(json!({})).unwrap().cases[0].expect, None);
    assert_eq!(lf(json!({"metadata": null})).unwrap().cases[0].expect, None);
}

#[test]
fn langfuse_experiment_rejects_a_bad_expect_value() {
    match lf(json!({"metadata": {"cloakpipe.expect": "nope"}})) {
        Err(ImportError::Invalid(issues)) => {
            let issues = issues.join("\n");
            assert!(issues.contains("metadata.cloakpipe.expect"), "{issues}");
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
}
