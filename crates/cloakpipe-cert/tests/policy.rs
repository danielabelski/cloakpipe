//! Contract tests for `cloakpipe_cert::policy::decide`.

use cloakpipe_cert::policy::{decide, DecisionInput};
use cloakpipe_cert::{
    Aggregate, CaseResult, CaseStatus, CertificationPolicy, Comparison, Decision, EvaluationRun,
    MetricRule, Outcome, PolicyRef, Reason, ReasonCode, Rules, RunRef, RunSource, SourceKind,
    SuiteRef, API_VERSION, POLICY_KIND, RUN_KIND,
};
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

// ── Fixtures ────────────────────────────────────────────────────────────

fn release() -> String {
    format!("sha256:{}", "ae".repeat(32))
}

fn other_release() -> String {
    format!("sha256:{}", "af".repeat(32))
}

fn case(id: &str, status: CaseStatus) -> CaseResult {
    CaseResult {
        id: id.into(),
        critical: false,
        status,
        score: None,
        metrics: BTreeMap::new(),
        duration_ms: None,
        expect: None,
    }
}

fn critical(id: &str, status: CaseStatus) -> CaseResult {
    CaseResult {
        critical: true,
        ..case(id, status)
    }
}

fn with_metric(mut c: CaseResult, name: &str, v: f64) -> CaseResult {
    c.metrics.insert(name.into(), v);
    c
}

/// `pass` passing and `fail` failing non-critical cases.
fn cases(pass: usize, fail: usize) -> Vec<CaseResult> {
    let mut out = Vec::new();
    for i in 0..pass {
        out.push(case(&format!("p{i:04}"), CaseStatus::Pass));
    }
    for i in 0..fail {
        out.push(case(&format!("f{i:04}"), CaseStatus::Fail));
    }
    out
}

fn run(run_id: &str, suite: &str, covers: &[&str], cases: Vec<CaseResult>) -> EvaluationRun {
    EvaluationRun {
        api_version: API_VERSION.into(),
        kind: RUN_KIND.into(),
        run_id: run_id.into(),
        release: release(),
        suite: SuiteRef {
            name: suite.into(),
            version: "1".into(),
        },
        covers: covers.iter().map(|s| s.to_string()).collect(),
        dataset: None,
        evaluators: Vec::new(),
        source: RunSource {
            kind: SourceKind::Native,
            tool: None,
        },
        cases,
    }
}

fn baseline(run_id: &str, suite: &str, cases: Vec<CaseResult>) -> EvaluationRun {
    EvaluationRun {
        release: other_release(),
        ..run(run_id, suite, &["functional"], cases)
    }
}

fn policy(rules: Rules) -> CertificationPolicy {
    CertificationPolicy {
        api_version: API_VERSION.into(),
        kind: POLICY_KIND.into(),
        name: "support-prod".into(),
        version: "11".into(),
        rules,
        validity_days: 30,
    }
}

/// Default rules with coverage relaxed so it does not interfere.
fn rules() -> Rules {
    Rules {
        min_coverage: 0.0,
        ..Rules::default()
    }
}

fn suites(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

fn go(
    required: &BTreeSet<String>,
    runs: &[EvaluationRun],
    baseline_runs: &[EvaluationRun],
    policy: &CertificationPolicy,
) -> Decision {
    let rel = release();
    decide(&DecisionInput {
        release: &rel,
        required_suites: required,
        runs,
        baseline_runs,
        policy,
    })
}

fn codes(d: &Decision) -> Vec<ReasonCode> {
    d.reasons.iter().map(|r| r.code).collect()
}

fn reasons_with(d: &Decision, code: ReasonCode) -> Vec<&Reason> {
    d.reasons.iter().filter(|r| r.code == code).collect()
}

fn assert_outcome_consistent(d: &Decision) {
    assert_eq!(
        d.outcome == Outcome::Certified,
        d.reasons.is_empty(),
        "{d:#?}"
    );
}

// ── Happy path and output shape ─────────────────────────────────────────

#[test]
fn clean_runs_are_certified() {
    let r = run("r1", "support", &["functional", "privacy"], cases(10, 0));
    let p = policy(Rules {
        min_pass_rate: Some(1.0),
        ..Rules::default()
    });
    let d = go(&suites(&["privacy"]), &[r], &[], &p);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
    assert!(d.reasons.is_empty());
}

#[test]
fn decision_echoes_release_and_policy() {
    let p = policy(rules());
    let r = run("r1", "support", &["functional"], cases(1, 0));
    let d = go(&suites(&[]), std::slice::from_ref(&r), &[], &p);
    assert_eq!(d.release, release());
    assert_eq!(d.policy, PolicyRef::from(&p));
    assert_eq!(d.policy.hash, p.policy_hash());
}

#[test]
fn required_suites_are_sorted_and_deduplicated() {
    let r = run(
        "r1",
        "support",
        &["privacy", "functional", "safety"],
        cases(1, 0),
    );
    let d = go(
        &suites(&["safety", "privacy", "functional", "privacy"]),
        &[r],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.required_suites, vec!["functional", "privacy", "safety"]);
}

#[test]
fn run_refs_cover_all_input_runs_sorted() {
    let good = run("r2", "b-suite", &["functional"], cases(1, 0));
    let also = run("r1", "b-suite", &["functional"], cases(1, 0));
    let first = run("r9", "a-suite", &["functional"], cases(1, 0));
    let mismatched = EvaluationRun {
        release: other_release(),
        ..run("r0", "z", &["functional"], cases(1, 0))
    };
    let invalid = EvaluationRun {
        kind: "Nope".into(),
        ..run("r5", "c", &["functional"], cases(1, 0))
    };
    let runs = vec![
        good.clone(),
        mismatched.clone(),
        invalid.clone(),
        also.clone(),
        first.clone(),
    ];
    let base = vec![
        baseline("x2", "s", cases(1, 0)),
        baseline("x1", "s", cases(1, 0)),
    ];
    let d = go(&suites(&[]), &runs, &base, &policy(rules()));
    let expect: Vec<RunRef> = [&first, &also, &good, &invalid, &mismatched]
        .into_iter()
        .map(RunRef::from)
        .collect();
    assert_eq!(d.runs, expect);
    let expect_base: Vec<RunRef> = [&base[1], &base[0]].into_iter().map(RunRef::from).collect();
    assert_eq!(d.baseline_runs, expect_base);
}

#[test]
fn run_refs_tie_break_on_hash() {
    let a = run("r1", "s", &["functional"], cases(1, 0));
    let b = run("r1", "s", &["functional"], cases(0, 1));
    let d1 = go(&suites(&[]), &[a.clone(), b.clone()], &[], &policy(rules()));
    let d2 = go(&suites(&[]), &[b.clone(), a.clone()], &[], &policy(rules()));
    assert_eq!(d1.runs, d2.runs);
    let mut hashes = vec![a.run_hash(), b.run_hash()];
    hashes.sort();
    assert_eq!(
        d1.runs.iter().map(|r| r.hash.clone()).collect::<Vec<_>>(),
        hashes
    );
}

#[test]
fn summaries_count_statuses_and_rates() {
    let mut cs = cases(6, 1);
    cs.push(case("e", CaseStatus::Error));
    cs.push(case("s1", CaseStatus::Skipped));
    cs.push(case("s2", CaseStatus::Skipped));
    let d = go(
        &suites(&[]),
        &[run("r1", "support", &["functional"], cs)],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.summaries.len(), 1);
    let s = &d.summaries[0];
    assert_eq!(s.suite, "support");
    assert_eq!(
        (s.cases, s.passed, s.failed, s.errored, s.skipped),
        (10, 6, 1, 1, 2)
    );
    assert_eq!(s.pass_rate, 6.0 / 8.0);
    assert_eq!(s.coverage, 8.0 / 10.0);
}

#[test]
fn summaries_only_for_remaining_candidate_runs_sorted() {
    let runs = vec![
        run("r2", "b", &["functional"], cases(1, 0)),
        run("r1", "b", &["functional"], cases(2, 0)),
        run("r3", "a", &["functional"], cases(3, 0)),
        EvaluationRun {
            release: other_release(),
            ..run("r0", "0", &["functional"], cases(1, 0))
        },
        EvaluationRun {
            run_id: " ".into(),
            ..run("r", "1", &["functional"], cases(1, 0))
        },
    ];
    let d = go(
        &suites(&[]),
        &runs,
        &[baseline("b1", "b", cases(9, 0))],
        &policy(rules()),
    );
    let got: Vec<(String, u32)> = d
        .summaries
        .iter()
        .map(|s| (s.suite.clone(), s.cases))
        .collect();
    assert_eq!(got, vec![("a".into(), 3), ("b".into(), 2), ("b".into(), 1)]);
}

#[test]
fn empty_input_with_no_requirements_is_blocked_for_lack_of_evidence() {
    let d = go(&suites(&[]), &[], &[], &policy(rules()));
    assert_eq!(d.outcome, Outcome::Blocked);
    assert_eq!(codes(&d), vec![ReasonCode::NoEvidence]);
    assert!(d.runs.is_empty() && d.summaries.is_empty());
}

// ── 1. Input validity ───────────────────────────────────────────────────

#[test]
fn invalid_candidate_run_is_reported_and_ignored() {
    let mut bad = run(
        "bad",
        "support",
        &["privacy"],
        vec![critical("c", CaseStatus::Fail)],
    );
    bad.api_version = "v0".into();
    let d = go(&suites(&["privacy"]), &[bad], &[], &policy(rules()));
    assert_eq!(
        codes(&d),
        vec![ReasonCode::InvalidInput, ReasonCode::NoEvidence, ReasonCode::MissingSuite]
    );
    assert!(d.summaries.is_empty());
    assert!(
        d.reasons[0].message.contains("apiVersion"),
        "{}",
        d.reasons[0].message
    );
}

#[test]
fn each_validation_problem_is_its_own_reason() {
    let mut bad = run(
        "bad",
        "support",
        &["vibes"],
        vec![case("a", CaseStatus::Pass), case("a", CaseStatus::Pass)],
    );
    bad.kind = "Run".into();
    let expected = bad.validate().len();
    assert!(expected >= 3);
    let d = go(&suites(&[]), &[bad], &[], &policy(rules()));
    assert_eq!(reasons_with(&d, ReasonCode::InvalidInput).len(), expected);
    assert_eq!(d.outcome, Outcome::Blocked);
}

#[test]
fn invalid_baseline_run_is_reported_and_ignored() {
    let cand = run(
        "r1",
        "support",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let mut base = baseline("b1", "support", vec![critical("c", CaseStatus::Fail)]);
    base.release = "not-a-hash".into();
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    // The baseline is ignored, so the critical failure counts as new.
    assert_eq!(
        codes(&d),
        vec![ReasonCode::InvalidInput, ReasonCode::NewCriticalFailure]
    );
}

#[test]
fn invalid_policy_is_reported_and_still_evaluated() {
    let p = policy(Rules {
        min_coverage: 1.5,
        min_pass_rate: Some(-0.1),
        ..Rules::default()
    });
    let issues = p.validate().len();
    assert_eq!(issues, 2);
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(1, 0))],
        &[],
        &p,
    );
    assert_eq!(reasons_with(&d, ReasonCode::InvalidInput).len(), issues);
    assert_eq!(d.outcome, Outcome::Blocked);
}

#[test]
fn invalid_policy_with_nan_values_does_not_panic() {
    let p = policy(Rules {
        min_coverage: f64::NAN,
        min_pass_rate: Some(f64::NAN),
        max_pass_rate_regression: Some(f64::INFINITY),
        metrics: vec![MetricRule {
            metric: "m".into(),
            aggregate: Aggregate::Mean,
            op: Comparison::Lte,
            value: f64::NAN,
            suite: None,
        }],
        ..Rules::default()
    });
    let r = run(
        "r1",
        "s",
        &["functional"],
        vec![with_metric(case("a", CaseStatus::Pass), "m", 1.0)],
    );
    let d = go(&suites(&[]), &[r], &[baseline("b", "s", cases(1, 0))], &p);
    assert_eq!(d.outcome, Outcome::Blocked);
    assert!(!reasons_with(&d, ReasonCode::InvalidInput).is_empty());
}

#[test]
fn non_finite_metrics_in_runs_are_invalid_not_panics() {
    let r = run(
        "r1",
        "s",
        &["functional"],
        vec![with_metric(case("a", CaseStatus::Pass), "m", f64::NAN)],
    );
    let p = policy(Rules {
        metrics: vec![MetricRule {
            metric: "m".into(),
            aggregate: Aggregate::P95,
            op: Comparison::Lte,
            value: 1.0,
            suite: None,
        }],
        ..rules()
    });
    let d = go(&suites(&[]), &[r], &[], &p);
    assert_eq!(codes(&d), vec![ReasonCode::InvalidInput, ReasonCode::NoEvidence]);
}

// ── 2. Release binding ──────────────────────────────────────────────────

#[test]
fn candidate_for_other_release_is_mismatch_and_ignored() {
    let r = EvaluationRun {
        release: other_release(),
        ..run(
            "r1",
            "support",
            &["privacy"],
            vec![critical("c", CaseStatus::Fail)],
        )
    };
    let d = go(&suites(&["privacy"]), &[r], &[], &policy(rules()));
    assert_eq!(
        codes(&d),
        vec![ReasonCode::ReleaseMismatch, ReasonCode::NoEvidence, ReasonCode::MissingSuite]
    );
    assert_eq!(d.reasons[0].suite.as_deref(), Some("support"));
    assert!(d.summaries.is_empty());
}

#[test]
fn invalid_run_with_wrong_release_is_invalid_not_mismatch() {
    let r = EvaluationRun {
        release: "garbage".into(),
        ..run("r1", "s", &["functional"], cases(1, 0))
    };
    let d = go(&suites(&[]), &[r], &[], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::InvalidInput, ReasonCode::NoEvidence]);
}

#[test]
fn baseline_runs_may_be_for_any_release() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b1", "s", vec![critical("c", CaseStatus::Fail)]);
    assert_ne!(base.release, cand.release);
    let p = policy(Rules {
        block_persisting_critical_failures: false,
        ..rules()
    });
    let d = go(&suites(&[]), &[cand], &[base], &p);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

// ── 3. Required assurance ───────────────────────────────────────────────

#[test]
fn missing_required_suite_is_reported_per_suite() {
    let r = run("r1", "support", &["functional"], cases(1, 0));
    let d = go(
        &suites(&["privacy", "functional", "safety"]),
        &[r],
        &[],
        &policy(rules()),
    );
    let missing: Vec<_> = reasons_with(&d, ReasonCode::MissingSuite)
        .iter()
        .map(|r| r.suite.clone().unwrap())
        .collect();
    assert_eq!(missing, vec!["privacy", "safety"]);
    assert!(d.reasons.iter().all(|r| r.case.is_none()));
}

#[test]
fn required_suite_covered_by_any_remaining_run() {
    let a = run("r1", "a", &["functional"], cases(1, 0));
    let b = run("r2", "b", &["privacy", "safety"], cases(1, 0));
    let d = go(
        &suites(&["privacy", "functional", "safety"]),
        &[a, b],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn coverage_from_baseline_runs_does_not_count() {
    let base = EvaluationRun {
        covers: vec!["privacy".into()],
        ..baseline("b", "s", cases(1, 0))
    };
    let d = go(&suites(&["privacy"]), &[], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::NoEvidence, ReasonCode::MissingSuite]);
}

#[test]
fn run_with_no_executed_cases_still_covers_but_reports_no_cases() {
    let r = run("r1", "s", &["privacy"], vec![]);
    let d = go(&suites(&["privacy"]), &[r], &[], &policy(rules()));
    assert!(reasons_with(&d, ReasonCode::MissingSuite).is_empty());
    assert_eq!(reasons_with(&d, ReasonCode::NoCases).len(), 1);
}

// ── 4. Per-run checks ───────────────────────────────────────────────────

#[test]
fn no_cases_at_all() {
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], vec![])],
        &[],
        &policy(rules()),
    );
    let r = reasons_with(&d, ReasonCode::NoCases);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].suite.as_deref(), Some("s"));
    assert_eq!(d.summaries[0].pass_rate, 0.0);
    assert_eq!(d.summaries[0].coverage, 0.0);
}

#[test]
fn all_skipped_is_no_cases() {
    let cs = vec![
        case("a", CaseStatus::Skipped),
        case("b", CaseStatus::Skipped),
    ];
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &policy(rules()),
    );
    assert_eq!(reasons_with(&d, ReasonCode::NoCases).len(), 1);
    assert_eq!(d.outcome, Outcome::Blocked);
}

#[test]
fn coverage_exactly_at_minimum_passes() {
    let mut cs = cases(99, 0);
    cs.push(case("skip", CaseStatus::Skipped));
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &policy(Rules::default()),
    );
    assert_eq!(d.summaries[0].coverage, 0.99);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn coverage_just_below_minimum_blocks() {
    let mut cs = cases(98, 0);
    cs.push(case("skip1", CaseStatus::Skipped));
    cs.push(case("skip2", CaseStatus::Skipped));
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &policy(Rules::default()),
    );
    let r = reasons_with(&d, ReasonCode::CoverageBelowMinimum);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].observed, Some(0.98));
    assert_eq!(r[0].required, Some(0.99));
    assert_eq!(r[0].suite.as_deref(), Some("s"));
}

#[test]
fn pass_rate_exactly_at_minimum_passes() {
    let p = policy(Rules {
        min_pass_rate: Some(0.95),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(19, 1))],
        &[],
        &p,
    );
    assert_eq!(d.summaries[0].pass_rate, 0.95);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn pass_rate_below_minimum_blocks() {
    let p = policy(Rules {
        min_pass_rate: Some(0.95),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(18, 2))],
        &[],
        &p,
    );
    let r = reasons_with(&d, ReasonCode::PassRateBelowMinimum);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].observed, Some(0.9));
    assert_eq!(r[0].required, Some(0.95));
}

#[test]
fn errors_count_against_pass_rate_and_skips_do_not() {
    let p = policy(Rules {
        min_pass_rate: Some(0.5),
        ..rules()
    });
    let cs = vec![
        case("a", CaseStatus::Pass),
        case("b", CaseStatus::Error),
        case("c", CaseStatus::Skipped),
    ];
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &p,
    );
    assert_eq!(d.summaries[0].pass_rate, 0.5);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn no_min_pass_rate_means_no_check() {
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(0, 5))],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn pass_rate_regression_exactly_at_maximum_passes() {
    let p = policy(Rules {
        max_pass_rate_regression: Some(0.5),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(1, 1))],
        &[baseline("b", "s", cases(4, 0))],
        &p,
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn pass_rate_regression_above_maximum_blocks() {
    let p = policy(Rules {
        max_pass_rate_regression: Some(0.25),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(1, 1))],
        &[baseline("b", "s", cases(4, 0))],
        &p,
    );
    let r = reasons_with(&d, ReasonCode::PassRateRegression);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].observed, Some(0.5));
    assert_eq!(r[0].required, Some(0.25));
    assert_eq!(r[0].suite.as_deref(), Some("s"));
}

#[test]
fn pass_rate_regression_skipped_without_baseline_for_suite() {
    let p = policy(Rules {
        max_pass_rate_regression: Some(0.0),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(1, 1))],
        &[baseline("b", "other", cases(4, 0))],
        &p,
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn improvement_over_baseline_is_not_regression() {
    let p = policy(Rules {
        max_pass_rate_regression: Some(0.0),
        ..rules()
    });
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(4, 0))],
        &[baseline("b", "s", cases(1, 1))],
        &p,
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn regression_checked_for_each_run_sharing_a_suite() {
    let p = policy(Rules {
        max_pass_rate_regression: Some(0.1),
        ..rules()
    });
    let runs = [
        run("r1", "s", &["functional"], cases(1, 1)),
        run("r2", "s", &["functional"], cases(1, 3)),
    ];
    let d = go(&suites(&[]), &runs, &[baseline("b", "s", cases(1, 0))], &p);
    assert_eq!(reasons_with(&d, ReasonCode::PassRateRegression).len(), 2);
}

#[test]
fn new_critical_failure_without_baseline() {
    let cs = vec![
        critical("refunds::identity", CaseStatus::Fail),
        case("ok", CaseStatus::Pass),
    ];
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &policy(rules()),
    );
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
    assert_eq!(d.reasons[0].case.as_deref(), Some("refunds::identity"));
    assert_eq!(d.reasons[0].suite.as_deref(), Some("s"));
}

#[test]
fn critical_error_counts_as_failure() {
    let d = go(
        &suites(&[]),
        &[run(
            "r1",
            "s",
            &["functional"],
            vec![critical("c", CaseStatus::Error)],
        )],
        &[],
        &policy(rules()),
    );
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
}

#[test]
fn critical_skipped_or_passing_is_not_a_failure() {
    let cs = vec![
        critical("a", CaseStatus::Pass),
        critical("b", CaseStatus::Skipped),
    ];
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cs)],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn non_critical_failure_is_not_a_critical_failure() {
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], cases(1, 3))],
        &[],
        &policy(rules()),
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn critical_failing_in_baseline_is_persisting() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "s", vec![case("c", CaseStatus::Error)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::PersistingCriticalFailure]);
    assert_eq!(d.reasons[0].case.as_deref(), Some("c"));
}

#[test]
fn persisting_not_blocking_when_disabled() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "s", vec![critical("c", CaseStatus::Fail)]);
    let p = policy(Rules {
        block_persisting_critical_failures: false,
        ..rules()
    });
    let d = go(&suites(&[]), &[cand], &[base], &p);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn critical_passing_in_baseline_is_new() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "s", vec![critical("c", CaseStatus::Pass)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
}

#[test]
fn critical_skipped_in_baseline_is_new() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "s", vec![critical("c", CaseStatus::Skipped)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
}

#[test]
fn critical_absent_from_baseline_is_new() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "s", vec![case("other", CaseStatus::Fail)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
}

#[test]
fn baseline_for_a_different_suite_does_not_make_failure_persisting() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let base = baseline("b", "other", vec![critical("c", CaseStatus::Fail)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(codes(&d), vec![ReasonCode::NewCriticalFailure]);
}

#[test]
fn new_critical_failures_within_allowance_pass() {
    let a = run(
        "r1",
        "a",
        &["functional"],
        vec![critical("c1", CaseStatus::Fail)],
    );
    let b = run(
        "r2",
        "b",
        &["functional"],
        vec![critical("c2", CaseStatus::Fail)],
    );
    let p = policy(Rules {
        max_new_critical_failures: 2,
        ..rules()
    });
    let d = go(&suites(&[]), &[a, b], &[], &p);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn new_critical_failures_counted_across_runs_report_every_case() {
    let a = run(
        "r1",
        "a",
        &["functional"],
        vec![
            critical("c1", CaseStatus::Fail),
            critical("c3", CaseStatus::Error),
        ],
    );
    let b = run(
        "r2",
        "b",
        &["functional"],
        vec![critical("c2", CaseStatus::Fail)],
    );
    let p = policy(Rules {
        max_new_critical_failures: 2,
        ..rules()
    });
    let d = go(&suites(&[]), &[a, b], &[], &p);
    let got: Vec<_> = reasons_with(&d, ReasonCode::NewCriticalFailure)
        .iter()
        .map(|r| (r.suite.clone().unwrap(), r.case.clone().unwrap()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("a".into(), "c1".into()),
            ("a".into(), "c3".into()),
            ("b".into(), "c2".into())
        ]
    );
}

#[test]
fn persisting_failures_do_not_count_toward_new_allowance() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![
            critical("old", CaseStatus::Fail),
            critical("new", CaseStatus::Fail),
        ],
    );
    let base = baseline("b", "s", vec![critical("old", CaseStatus::Fail)]);
    let p = policy(Rules {
        max_new_critical_failures: 1,
        block_persisting_critical_failures: false,
        ..rules()
    });
    let d = go(&suites(&[]), &[cand], &[base], &p);
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn new_and_persisting_reported_together() {
    let cand = run(
        "r1",
        "s",
        &["functional"],
        vec![
            critical("old", CaseStatus::Fail),
            critical("new", CaseStatus::Fail),
        ],
    );
    let base = baseline("b", "s", vec![critical("old", CaseStatus::Fail)]);
    let d = go(&suites(&[]), &[cand], &[base], &policy(rules()));
    assert_eq!(
        codes(&d),
        vec![
            ReasonCode::NewCriticalFailure,
            ReasonCode::PersistingCriticalFailure
        ]
    );
    assert_eq!(d.reasons[0].case.as_deref(), Some("new"));
    assert_eq!(d.reasons[1].case.as_deref(), Some("old"));
}

#[test]
fn runs_sharing_a_suite_name_are_checked_independently() {
    let a = run(
        "r1",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let b = run(
        "r2",
        "s",
        &["functional"],
        vec![critical("c", CaseStatus::Fail)],
    );
    let d = go(&suites(&[]), &[a, b], &[], &policy(rules()));
    assert_eq!(reasons_with(&d, ReasonCode::NewCriticalFailure).len(), 2);
    assert_eq!(d.summaries.len(), 2);
}

#[test]
fn every_failing_check_is_reported_for_one_run() {
    // Zero executed: NoCases, plus coverage 0 < min and pass rate 0 < min.
    let p = policy(Rules {
        min_pass_rate: Some(0.5),
        ..Rules::default()
    });
    let d = go(
        &suites(&[]),
        &[run(
            "r1",
            "s",
            &["functional"],
            vec![case("x", CaseStatus::Skipped)],
        )],
        &[],
        &p,
    );
    assert_eq!(
        codes(&d),
        vec![
            ReasonCode::NoCases,
            ReasonCode::CoverageBelowMinimum,
            ReasonCode::PassRateBelowMinimum
        ]
    );
}

// ── 5. Metrics ──────────────────────────────────────────────────────────

fn metric_rule(aggregate: Aggregate, op: Comparison, value: f64) -> MetricRule {
    MetricRule {
        metric: "latency_ms".into(),
        aggregate,
        op,
        value,
        suite: None,
    }
}

/// Values 1..=10 for `latency_ms` on passing cases, given in shuffled order.
fn latency_run() -> EvaluationRun {
    let vals = [7.0, 3.0, 10.0, 1.0, 5.0, 9.0, 2.0, 8.0, 4.0, 6.0];
    let cs = vals
        .iter()
        .enumerate()
        .map(|(i, v)| with_metric(case(&format!("c{i}"), CaseStatus::Pass), "latency_ms", *v))
        .collect();
    run("r1", "s", &["performance"], cs)
}

fn observed(agg: Aggregate, runs: &[EvaluationRun]) -> f64 {
    // An always-violated rule reveals the observed aggregate.
    let p = policy(Rules {
        metrics: vec![metric_rule(agg, Comparison::Gte, f64::MAX)],
        ..rules()
    });
    let d = go(&suites(&[]), runs, &[], &p);
    let r = reasons_with(&d, ReasonCode::MetricThreshold);
    assert_eq!(r.len(), 1, "{:#?}", d.reasons);
    assert_eq!(r[0].required, Some(f64::MAX));
    r[0].observed.unwrap()
}

#[test]
fn metric_aggregates() {
    let r = [latency_run()];
    assert_eq!(observed(Aggregate::Mean, &r), 5.5);
    assert_eq!(observed(Aggregate::Min, &r), 1.0);
    assert_eq!(observed(Aggregate::Max, &r), 10.0);
    // Nearest rank: ceil(0.50 * 10) = 5th, ceil(0.95 * 10) = 10th.
    assert_eq!(observed(Aggregate::P50, &r), 5.0);
    assert_eq!(observed(Aggregate::P95, &r), 10.0);
}

#[test]
fn nearest_rank_percentiles_small_samples() {
    let mk = |vals: &[f64]| {
        let cs = vals
            .iter()
            .enumerate()
            .map(|(i, v)| with_metric(case(&format!("c{i}"), CaseStatus::Pass), "latency_ms", *v))
            .collect();
        [run("r1", "s", &["performance"], cs)]
    };
    assert_eq!(observed(Aggregate::P50, &mk(&[42.0])), 42.0);
    assert_eq!(observed(Aggregate::P95, &mk(&[42.0])), 42.0);
    // n = 4: p50 rank ceil(2) = 2, p95 rank ceil(3.8) = 4.
    assert_eq!(
        observed(Aggregate::P50, &mk(&[40.0, 10.0, 30.0, 20.0])),
        20.0
    );
    assert_eq!(
        observed(Aggregate::P95, &mk(&[40.0, 10.0, 30.0, 20.0])),
        40.0
    );
    // n = 3: p50 rank ceil(1.5) = 2.
    assert_eq!(observed(Aggregate::P50, &mk(&[3.0, 1.0, 2.0])), 2.0);
    // n = 20: p95 rank ceil(19) = 19 (not 20).
    let twenty: Vec<f64> = (1..=20).map(f64::from).collect();
    assert_eq!(observed(Aggregate::P95, &mk(&twenty)), 19.0);
    // n = 21: p95 rank ceil(19.95) = 20.
    let twenty_one: Vec<f64> = (1..=21).map(f64::from).collect();
    assert_eq!(observed(Aggregate::P95, &mk(&twenty_one)), 20.0);
    // Negative values sort numerically.
    assert_eq!(observed(Aggregate::Min, &mk(&[-1.0, -5.0, 0.0])), -5.0);
}

#[test]
fn metric_threshold_lte_boundary() {
    let at = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Max, Comparison::Lte, 10.0)],
        ..rules()
    });
    assert_eq!(
        go(&suites(&[]), &[latency_run()], &[], &at).outcome,
        Outcome::Certified
    );
    let below = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Max, Comparison::Lte, 9.999)],
        ..rules()
    });
    let d = go(&suites(&[]), &[latency_run()], &[], &below);
    let r = reasons_with(&d, ReasonCode::MetricThreshold);
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].observed, r[0].required), (Some(10.0), Some(9.999)));
    assert!(r[0].message.contains("latency_ms"), "{}", r[0].message);
}

#[test]
fn metric_threshold_gte_boundary() {
    let at = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Min, Comparison::Gte, 1.0)],
        ..rules()
    });
    assert_eq!(
        go(&suites(&[]), &[latency_run()], &[], &at).outcome,
        Outcome::Certified
    );
    let above = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Min, Comparison::Gte, 1.5)],
        ..rules()
    });
    let d = go(&suites(&[]), &[latency_run()], &[], &above);
    assert_eq!(codes(&d), vec![ReasonCode::MetricThreshold]);
}

#[test]
fn metric_ignores_skipped_cases_and_cases_without_metric() {
    let cs = vec![
        with_metric(case("a", CaseStatus::Pass), "latency_ms", 10.0),
        with_metric(case("b", CaseStatus::Fail), "latency_ms", 20.0),
        with_metric(case("c", CaseStatus::Skipped), "latency_ms", 1000.0),
        case("d", CaseStatus::Pass),
        with_metric(case("e", CaseStatus::Pass), "other", 1000.0),
    ];
    assert_eq!(
        observed(
            Aggregate::Max,
            &[run("r1", "s", &["functional"], cs.clone())]
        ),
        20.0
    );
    assert_eq!(
        observed(Aggregate::Mean, &[run("r1", "s", &["functional"], cs)]),
        15.0
    );
}

#[test]
fn metric_with_no_values_is_skipped() {
    let p = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Mean, Comparison::Lte, 0.0)],
        ..rules()
    });
    let only_skipped = vec![
        with_metric(case("a", CaseStatus::Skipped), "latency_ms", 5.0),
        case("b", CaseStatus::Pass),
    ];
    let d = go(
        &suites(&[]),
        &[run("r1", "s", &["functional"], only_skipped)],
        &[],
        &p,
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:#?}", d.reasons);
}

#[test]
fn metric_rule_scoped_to_suite_pools_matching_runs() {
    let mk = |id: &str, suite: &str, v: f64| {
        run(
            id,
            suite,
            &["performance"],
            vec![with_metric(case("c", CaseStatus::Pass), "latency_ms", v)],
        )
    };
    let runs = [
        mk("r1", "fast", 1.0),
        mk("r2", "fast", 3.0),
        mk("r3", "slow", 100.0),
    ];
    let scoped = MetricRule {
        suite: Some("fast".into()),
        ..metric_rule(Aggregate::Mean, Comparison::Lte, 2.0)
    };
    let p = policy(Rules {
        metrics: vec![scoped],
        ..rules()
    });
    assert_eq!(go(&suites(&[]), &runs, &[], &p).outcome, Outcome::Certified);

    let scoped = MetricRule {
        suite: Some("fast".into()),
        ..metric_rule(Aggregate::Mean, Comparison::Lte, 1.5)
    };
    let p = policy(Rules {
        metrics: vec![scoped],
        ..rules()
    });
    let d = go(&suites(&[]), &runs, &[], &p);
    let r = reasons_with(&d, ReasonCode::MetricThreshold);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].suite.as_deref(), Some("fast"));
    assert_eq!(r[0].observed, Some(2.0));

    // Unscoped pools all runs: mean of 1, 3, 100.
    let p = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Max, Comparison::Lte, 50.0)],
        ..rules()
    });
    let d = go(&suites(&[]), &runs, &[], &p);
    assert_eq!(
        reasons_with(&d, ReasonCode::MetricThreshold)[0].observed,
        Some(100.0)
    );
    assert_eq!(reasons_with(&d, ReasonCode::MetricThreshold)[0].suite, None);
}

#[test]
fn metric_ignores_mismatched_invalid_and_baseline_runs() {
    let mk = |id: &str, v: f64| {
        run(
            id,
            "s",
            &["performance"],
            vec![with_metric(case("c", CaseStatus::Pass), "latency_ms", v)],
        )
    };
    let good = mk("r1", 1.0);
    let mismatched = EvaluationRun {
        release: other_release(),
        ..mk("r2", 500.0)
    };
    let invalid = EvaluationRun {
        run_id: "".into(),
        ..mk("r3", 500.0)
    };
    let base = mk("b1", 500.0);
    let p = policy(Rules {
        metrics: vec![metric_rule(Aggregate::Max, Comparison::Lte, 2.0)],
        ..rules()
    });
    let d = go(&suites(&[]), &[good, mismatched, invalid], &[base], &p);
    assert!(
        reasons_with(&d, ReasonCode::MetricThreshold).is_empty(),
        "{:#?}",
        d.reasons
    );
}

#[test]
fn every_metric_rule_is_evaluated() {
    let p = policy(Rules {
        metrics: vec![
            metric_rule(Aggregate::Max, Comparison::Lte, 1.0),
            metric_rule(Aggregate::Min, Comparison::Gte, 2.0),
            metric_rule(Aggregate::Mean, Comparison::Lte, 100.0),
        ],
        ..rules()
    });
    let d = go(&suites(&[]), &[latency_run()], &[], &p);
    assert_eq!(reasons_with(&d, ReasonCode::MetricThreshold).len(), 2);
}

// ── Reason ordering and outcome ─────────────────────────────────────────

fn is_sorted_by_contract(reasons: &[Reason]) -> bool {
    reasons.windows(2).all(|w| {
        let k = |r: &Reason| (r.code, r.suite.clone(), r.case.clone(), r.message.clone());
        k(&w[0]) <= k(&w[1])
    })
}

#[test]
fn reasons_sorted_by_code_suite_case_message() {
    let p = policy(Rules {
        min_pass_rate: Some(0.9),
        metrics: vec![metric_rule(Aggregate::Max, Comparison::Lte, 0.0)],
        ..Rules::default()
    });
    let runs = vec![
        run(
            "r1",
            "zeta",
            &["functional"],
            vec![
                critical("z2", CaseStatus::Fail),
                critical("z1", CaseStatus::Fail),
                with_metric(case("m", CaseStatus::Pass), "latency_ms", 3.0),
            ],
        ),
        run(
            "r2",
            "alpha",
            &["functional"],
            vec![
                critical("a1", CaseStatus::Fail),
                case("s", CaseStatus::Skipped),
            ],
        ),
        EvaluationRun {
            release: other_release(),
            ..run("r3", "mid", &["functional"], cases(1, 0))
        },
        EvaluationRun {
            kind: "X".into(),
            ..run("r4", "mid", &["functional"], cases(1, 0))
        },
        run("r5", "empty", &["functional"], vec![]),
    ];
    let d = go(&suites(&["privacy", "safety"]), &runs, &[], &p);
    assert!(is_sorted_by_contract(&d.reasons), "{:#?}", d.reasons);
    let mut distinct = codes(&d);
    distinct.dedup();
    assert_eq!(
        distinct,
        vec![
            ReasonCode::InvalidInput,
            ReasonCode::ReleaseMismatch,
            ReasonCode::MissingSuite,
            ReasonCode::NoCases,
            ReasonCode::NewCriticalFailure,
            ReasonCode::CoverageBelowMinimum,
            ReasonCode::PassRateBelowMinimum,
            ReasonCode::MetricThreshold,
        ]
    );
    let new: Vec<_> = reasons_with(&d, ReasonCode::NewCriticalFailure)
        .iter()
        .map(|r| r.case.clone().unwrap())
        .collect();
    assert_eq!(new, vec!["a1", "z1", "z2"]);
    assert_eq!(d.outcome, Outcome::Blocked);
}

#[test]
fn decision_round_trips_through_json() {
    let d = go(
        &suites(&["privacy"]),
        &[latency_run()],
        &[],
        &policy(rules()),
    );
    let json = serde_json::to_value(&d).unwrap();
    let back: Decision = serde_json::from_value(json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn identical_input_gives_identical_decision() {
    let runs = [
        latency_run(),
        run(
            "r2",
            "s",
            &["privacy"],
            vec![critical("c", CaseStatus::Fail)],
        ),
    ];
    let p = policy(Rules {
        min_pass_rate: Some(0.99),
        ..Rules::default()
    });
    let a = go(&suites(&["safety"]), &runs, &[], &p);
    let b = go(&suites(&["safety"]), &runs, &[], &p);
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

// ── Property tests ──────────────────────────────────────────────────────

const COVERS: &[&str] = &["functional", "privacy", "safety"];
const SUITE_NAMES: &[&str] = &["a", "b", "c"];

fn arb_status() -> impl Strategy<Value = CaseStatus> {
    prop_oneof![
        4 => Just(CaseStatus::Pass),
        2 => Just(CaseStatus::Fail),
        1 => Just(CaseStatus::Error),
        1 => Just(CaseStatus::Skipped),
    ]
}

fn arb_case() -> impl Strategy<Value = CaseResult> {
    (
        0u8..8,
        any::<bool>(),
        arb_status(),
        proptest::option::of(-1.0e6f64..1.0e6),
    )
        .prop_map(|(id, crit, status, metric)| {
            let mut c = CaseResult {
                critical: crit,
                ..case(&format!("case{id}"), status)
            };
            if let Some(m) = metric {
                c.metrics.insert("latency_ms".into(), m);
            }
            c
        })
}

fn arb_run(prefix: &'static str) -> impl Strategy<Value = EvaluationRun> {
    (
        0u8..4,
        proptest::sample::select(SUITE_NAMES),
        proptest::sample::subsequence(COVERS, 0..=COVERS.len()),
        proptest::collection::vec(arb_case(), 0..8),
        any::<bool>(),
        0u8..10,
    )
        .prop_map(
            move |(id, suite, covers, mut cases, same_release, mutate)| {
                // Keep runs mostly valid: drop duplicate case ids.
                let mut seen = BTreeSet::new();
                cases.retain(|c| seen.insert(c.id.clone()));
                let mut r = run(&format!("{prefix}{id}"), suite, &covers, cases);
                if !same_release {
                    r.release = other_release();
                }
                if mutate == 0 {
                    r.kind = "Broken".into();
                }
                r
            },
        )
}

fn arb_policy() -> impl Strategy<Value = CertificationPolicy> {
    (
        0u32..3,
        any::<bool>(),
        proptest::option::of(0.0f64..=1.0),
        proptest::option::of(0.0f64..=1.0),
        0.0f64..=1.0,
        proptest::collection::vec(
            (
                proptest::sample::select(
                    &[
                        Aggregate::Mean,
                        Aggregate::P50,
                        Aggregate::P95,
                        Aggregate::Min,
                        Aggregate::Max,
                    ][..],
                ),
                proptest::sample::select(&[Comparison::Lte, Comparison::Gte][..]),
                -1.0e6f64..1.0e6,
                proptest::option::of(proptest::sample::select(SUITE_NAMES)),
            ),
            0..3,
        ),
    )
        .prop_map(|(max_new, block, min_pr, max_reg, min_cov, metrics)| {
            policy(Rules {
                max_new_critical_failures: max_new,
                block_persisting_critical_failures: block,
                min_pass_rate: min_pr,
                max_pass_rate_regression: max_reg,
                min_coverage: min_cov,
                metrics: metrics
                    .into_iter()
                    .map(|(aggregate, op, value, suite)| MetricRule {
                        metric: "latency_ms".into(),
                        aggregate,
                        op,
                        value,
                        suite: suite.map(str::to_string),
                    })
                    .collect(),
                boundary: None,
            })
        })
}

fn permuted<T: Clone>(items: &[T], seed: &[usize]) -> Vec<T> {
    let mut out = items.to_vec();
    for (i, s) in seed.iter().enumerate() {
        if out.len() > 1 {
            let a = i % out.len();
            let b = s % out.len();
            out.swap(a, b);
        }
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn decision_is_invariant_under_permutation(
        runs in proptest::collection::vec(arb_run("r"), 0..6),
        base in proptest::collection::vec(arb_run("b"), 0..4),
        required in proptest::sample::subsequence(COVERS, 0..=COVERS.len()),
        p in arb_policy(),
        seed in proptest::collection::vec(any::<usize>(), 0..12),
    ) {
        let req = suites(&required);
        let expected = go(&req, &runs, &base, &p);

        let mut runs2 = permuted(&runs, &seed);
        for r in &mut runs2 {
            r.cases = permuted(&r.cases, &seed);
            r.covers.reverse();
        }
        let mut base2 = permuted(&base, &seed);
        base2.reverse();
        for r in &mut base2 {
            r.cases.reverse();
        }
        let got = go(&req, &runs2, &base2, &p);
        prop_assert_eq!(
            serde_json::to_string(&expected).unwrap(),
            serde_json::to_string(&got).unwrap()
        );
    }

    #[test]
    fn outcome_iff_no_reasons_and_reasons_sorted(
        runs in proptest::collection::vec(arb_run("r"), 0..6),
        base in proptest::collection::vec(arb_run("b"), 0..4),
        required in proptest::sample::subsequence(COVERS, 0..=COVERS.len()),
        p in arb_policy(),
    ) {
        let d = go(&suites(&required), &runs, &base, &p);
        assert_outcome_consistent(&d);
        prop_assert!(is_sorted_by_contract(&d.reasons));
        prop_assert_eq!(d.runs.len(), runs.len());
        prop_assert_eq!(d.baseline_runs.len(), base.len());
        let remaining = runs.iter().filter(|r| r.validate().is_empty() && r.release == release()).count();
        prop_assert_eq!(d.summaries.len(), remaining);
    }

    #[test]
    fn never_panics_on_arbitrary_values(
        rel in ".{0,80}",
        run_id in ".{0,8}",
        suite in ".{0,4}",
        covers in proptest::collection::vec(".{0,10}", 0..3),
        metric in proptest::num::f64::ANY,
        score in proptest::option::of(proptest::num::f64::ANY),
        min_cov in proptest::num::f64::ANY,
        min_pr in proptest::option::of(proptest::num::f64::ANY),
        max_reg in proptest::option::of(proptest::num::f64::ANY),
        rule_value in proptest::num::f64::ANY,
        n_cases in 0usize..4,
    ) {
        let cs: Vec<CaseResult> = (0..n_cases)
            .map(|i| CaseResult { score, ..with_metric(critical(&format!("c{}", i % 2), CaseStatus::Fail), "m", metric) })
            .collect();
        let mut r = run(&run_id, &suite, &[], cs);
        r.covers = covers;
        r.release = rel.clone();
        let p = policy(Rules {
            min_coverage: min_cov,
            min_pass_rate: min_pr,
            max_pass_rate_regression: max_reg,
            metrics: vec![MetricRule { metric: "m".into(), aggregate: Aggregate::P95, op: Comparison::Gte, value: rule_value, suite: None }],
            ..Rules::default()
        });
        let req = suites(&["privacy"]);
        let d = decide(&DecisionInput {
            release: &rel,
            required_suites: &req,
            runs: std::slice::from_ref(&r),
            baseline_runs: std::slice::from_ref(&r),
            policy: &p,
        });
        assert_outcome_consistent(&d);
    }
}

// ── Regressions: overflow-safe mean and case-order independence ─────────

fn metric_run(values: &[f64]) -> EvaluationRun {
    let cs = values
        .iter()
        .enumerate()
        .map(|(i, v)| with_metric(case(&format!("c{i}"), CaseStatus::Pass), "m", *v))
        .collect();
    run("r", "s", &["functional"], cs)
}

fn mean_rule(op: Comparison, value: f64) -> CertificationPolicy {
    policy(Rules {
        metrics: vec![MetricRule {
            metric: "m".into(),
            aggregate: Aggregate::Mean,
            op,
            value,
            suite: None,
        }],
        ..rules()
    })
}

#[test]
fn mean_of_huge_values_does_not_overflow_to_negative_infinity() {
    // True mean is 0.0 > -1.0: the rule is violated and must block.
    let r = metric_run(&[-1e308, -1e308, 1e308, 1e308]);
    let d = go(&suites(&[]), &[r], &[], &mean_rule(Comparison::Lte, -1.0));
    assert_eq!(d.outcome, Outcome::Blocked, "{:?}", d.reasons);
    let m = reasons_with(&d, ReasonCode::MetricThreshold);
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].observed, Some(0.0));
}

#[test]
fn mean_of_huge_values_does_not_overflow_to_positive_infinity() {
    // True mean 1e308 <= 1.5e308: certified.
    let r = metric_run(&[1e308, 1e308]);
    let d = go(
        &suites(&[]),
        &[r],
        &[],
        &mean_rule(Comparison::Lte, 1.5e308),
    );
    assert_eq!(d.outcome, Outcome::Certified, "{:?}", d.reasons);
}

#[test]
fn mean_observed_is_finite_and_round_trips_when_violated() {
    let r = metric_run(&[f64::MAX, f64::MAX, f64::MAX]);
    let d = go(&suites(&[]), &[r], &[], &mean_rule(Comparison::Lte, 1.0));
    assert_eq!(d.outcome, Outcome::Blocked);
    let m = reasons_with(&d, ReasonCode::MetricThreshold);
    assert_eq!(m[0].observed, Some(f64::MAX));
    let json = serde_json::to_string(&d).unwrap();
    let back: Decision = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn invalid_input_messages_do_not_depend_on_case_order() {
    let bad = with_metric(case("b", CaseStatus::Pass), "m", f64::NAN);
    let a = run(
        "r",
        "s",
        &["functional"],
        vec![case("a", CaseStatus::Pass), bad.clone()],
    );
    let b = run(
        "r",
        "s",
        &["functional"],
        vec![bad, case("a", CaseStatus::Pass)],
    );
    let p = policy(rules());
    let da = go(&suites(&[]), &[a], &[], &p);
    assert_eq!(da.outcome, Outcome::Blocked);
    assert_eq!(da, go(&suites(&[]), &[b], &[], &p));
}

#[test]
fn run_hash_does_not_depend_on_order_of_duplicate_case_ids() {
    let a = run(
        "r",
        "s",
        &["functional"],
        vec![case("a", CaseStatus::Pass), case("a", CaseStatus::Fail)],
    );
    let b = run(
        "r",
        "s",
        &["functional"],
        vec![case("a", CaseStatus::Fail), case("a", CaseStatus::Pass)],
    );
    let p = policy(rules());
    let da = go(
        &suites(&[]),
        std::slice::from_ref(&a),
        std::slice::from_ref(&a),
        &p,
    );
    assert_eq!(da.outcome, Outcome::Blocked);
    assert_eq!(
        da,
        go(
            &suites(&[]),
            std::slice::from_ref(&b),
            std::slice::from_ref(&b),
            &p
        )
    );
}


// ── Evidence is required ────────────────────────────────────────────────

#[test]
fn no_runs_is_blocked_for_lack_of_evidence_even_with_no_required_suites() {
    let d = go(&suites(&[]), &[], &[], &policy(rules()));
    assert_eq!(d.outcome, Outcome::Blocked);
    assert_eq!(codes(&d), vec![ReasonCode::NoEvidence]);
}

#[test]
fn runs_for_another_release_are_not_evidence() {
    let mut r = run("r1", "s", &["functional"], cases(3, 0));
    r.release = other_release();
    let d = go(&suites(&[]), &[r], &[], &policy(rules()));
    assert_eq!(d.outcome, Outcome::Blocked);
    let c = codes(&d);
    assert!(c.contains(&ReasonCode::ReleaseMismatch) && c.contains(&ReasonCode::NoEvidence), "{c:?}");
}
