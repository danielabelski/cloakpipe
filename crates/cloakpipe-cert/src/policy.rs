//! The certification decision.
//!
//! Contract (see docs/CERTIFICATION.md §Decision). `decide` is a pure,
//! deterministic function: the same input always yields an identical
//! `Decision` (including reason order), regardless of the order of runs or
//! cases in the input. It never panics.
//!
//! Checks, in this order (all are evaluated; any reason ⇒ `Blocked`):
//!
//! 1. **Input validity** — every candidate and baseline run must pass
//!    `EvaluationRun::validate`, and the policy `CertificationPolicy::validate`;
//!    each problem → `InvalidInput` (invalid runs are then ignored by the
//!    remaining checks).
//! 2. **Release binding** — a candidate run whose `release` ≠ input `release`
//!    → `ReleaseMismatch` (and the run is ignored by the remaining checks).
//!    Baseline runs may be for any release.
//!    If no valid candidate run of the release remains after checks 1–2 →
//!    `NoEvidence` (a release is never certified on zero runs, even when no
//!    assurance suite is required).
//! 3. **Required assurance** — each name in `required_suites` must appear in
//!    the `covers` of at least one remaining candidate run, else
//!    `MissingSuite` (reason.suite = the assurance suite name).
//! 4. Per remaining candidate run (keyed by run suite name; if two runs share
//!    a suite name, both are checked independently):
//!    - zero executed cases (all skipped or none) → `NoCases`;
//!    - coverage = executed / total < `rules.minCoverage` → `CoverageBelowMinimum`;
//!    - `rules.minPassRate`: pass rate < min → `PassRateBelowMinimum`;
//!    - `rules.maxPassRateRegression`: if a baseline run with the same suite
//!      name exists, baseline pass rate − candidate pass rate > max →
//!      `PassRateRegression` (no baseline ⇒ check skipped);
//!    - critical cases (`critical: true`) whose status is Fail/Error:
//!      **new** if the baseline run for the suite does not have a failing
//!      case with that id (absent baseline or absent case counts as new),
//!      otherwise **persisting**. New critical failures above
//!      `rules.maxNewCriticalFailures` (counted across all runs) → one
//!      `NewCriticalFailure` reason per new failing case; persisting ones →
//!      one `PersistingCriticalFailure` each when
//!      `rules.blockPersistingCriticalFailures`.
//! 5. **Metrics** — for each `MetricRule`, over the executed cases of every
//!    remaining candidate run whose suite name matches `rule.suite` (all runs
//!    when `None`) that carry the metric: aggregate (mean; p50/p95 by
//!    nearest-rank on the sorted values; min; max) and compare. Violation →
//!    `MetricThreshold` with `observed` and `required`. No values ⇒ rule
//!    skipped.
//! 6. **Boundary** (`rules.boundary`, absent ⇒ skipped) — for each listed
//!    assurance suite that at least one remaining candidate run covers,
//!    pool the labelled cases (`expect`) of every such run. Unlabelled cases
//!    are ignored. Deny rate = passed deny cases / deny cases; allow rate =
//!    passed allow cases / allow cases; a skipped, failed or errored
//!    labelled case is not passed. No labelled case, no deny case or no
//!    allow case → `BoundaryIncomplete` (one reason per missing side);
//!    deny rate < `minDenyRate` → `UnderBlocking`; allow rate <
//!    `minAllowRate` → `OverRefusal` (both with `observed` and `required`;
//!    reason.suite = the assurance suite name). A listed suite that no
//!    remaining candidate run covers → `BoundaryIncomplete`, unless it is
//!    also a required suite (already `MissingSuite` in step 3).
//!
//! Comparisons use the exact thresholds (no epsilon): pass rate exactly equal
//! to `minPassRate` passes.
//!
//! The returned `Decision`: `release` and `policy` (`PolicyRef`) as given;
//! `requiredSuites` sorted and de-duplicated; `runs` / `baselineRuns` are
//! `RunRef`s of all input runs sorted by (suite, runId, hash); `summaries` one
//! per remaining candidate run sorted by (suite, then runId); `reasons` sorted
//! by (code, suite, case, message). `outcome = Certified` iff `reasons` is
//! empty.

use crate::model::{
    Aggregate, BoundaryRule, CaseResult, CaseStatus, CertificationPolicy, Comparison, Decision,
    EvaluationRun, Expect, MetricRule, Outcome, PolicyRef, Reason, ReasonCode, RunRef,
    SuiteSummary,
};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Everything a certification decision is made from.
#[derive(Debug, Clone, Copy)]
pub struct DecisionInput<'a> {
    /// `sha256:<hex>` manifest hash of the candidate release.
    pub release: &'a str,
    /// Assurance suites the release must have evidence for (from
    /// `cloakpipe_release::diff` and/or policy).
    pub required_suites: &'a BTreeSet<String>,
    /// Candidate evaluation runs of `release`.
    pub runs: &'a [EvaluationRun],
    /// Runs of a previously certified release to compare against.
    pub baseline_runs: &'a [EvaluationRun],
    /// The policy to apply.
    pub policy: &'a CertificationPolicy,
}

/// Apply `input.policy` to the evidence in `input` (see the module contract).
///
/// Pure and deterministic: the result does not depend on the order of runs,
/// cases or covers in the input, and no input makes it panic.
pub fn decide(input: &DecisionInput<'_>) -> Decision {
    let policy = input.policy;
    let rules = &policy.rules;
    let mut reasons = Vec::new();

    // 1. Input validity.
    for issue in policy.validate() {
        reasons.push(reason(
            ReasonCode::InvalidInput,
            None,
            format!("policy: {issue}"),
        ));
    }
    let runs = Indexed::new(input.runs);
    let baseline_runs = Indexed::new(input.baseline_runs);
    let candidates = valid_runs(&runs, "run", &mut reasons);
    let baselines = valid_runs(&baseline_runs, "baseline run", &mut reasons);

    // 2. Release binding.
    let candidates: Vec<&EvaluationRun> = candidates
        .into_iter()
        .filter(|run| {
            let bound = run.release == input.release;
            if !bound {
                reasons.push(reason(
                    ReasonCode::ReleaseMismatch,
                    Some(&run.suite.name),
                    format!(
                        "run {:?} evaluated release {}, not {}",
                        run.run_id, run.release, input.release
                    ),
                ));
            }
            bound
        })
        .collect();

    if candidates.is_empty() {
        reasons.push(reason(
            ReasonCode::NoEvidence,
            None,
            format!("no valid evaluation run of release {} to certify on", input.release),
        ));
    }

    // 3. Required assurance.
    let covered: BTreeSet<&str> = candidates
        .iter()
        .flat_map(|run| run.covers.iter().map(String::as_str))
        .collect();
    for suite in input.required_suites {
        if !covered.contains(suite.as_str()) {
            reasons.push(reason(
                ReasonCode::MissingSuite,
                Some(suite),
                format!("no run covers required assurance suite {suite:?}"),
            ));
        }
    }

    // 4. Per-run checks. The baseline for a suite is the first valid
    // baseline run with that suite name in canonical order.
    let mut baseline_by_suite: BTreeMap<&str, &EvaluationRun> = BTreeMap::new();
    for run in &baselines {
        baseline_by_suite
            .entry(run.suite.name.as_str())
            .or_insert(run);
    }
    let mut summaries = Vec::with_capacity(candidates.len());
    let mut new_critical = Vec::new();
    for run in &candidates {
        let suite = run.suite.name.as_str();
        let baseline = baseline_by_suite.get(suite).copied();
        let summary = summarize(run);
        let label = format!("run {:?}", run.run_id);

        if summary.executed == 0 {
            reasons.push(reason(
                ReasonCode::NoCases,
                Some(suite),
                format!("{label}: no executed cases"),
            ));
        }
        if !at_least(summary.coverage, rules.min_coverage) {
            reasons.push(measured(
                reason(
                    ReasonCode::CoverageBelowMinimum,
                    Some(suite),
                    format!(
                        "{label}: coverage {} is below the minimum {}",
                        summary.coverage, rules.min_coverage
                    ),
                ),
                summary.coverage,
                rules.min_coverage,
            ));
        }
        if let Some(min) = rules.min_pass_rate {
            if !at_least(summary.pass_rate, min) {
                reasons.push(measured(
                    reason(
                        ReasonCode::PassRateBelowMinimum,
                        Some(suite),
                        format!(
                            "{label}: pass rate {} is below the minimum {min}",
                            summary.pass_rate
                        ),
                    ),
                    summary.pass_rate,
                    min,
                ));
            }
        }
        if let (Some(max), Some(baseline)) = (rules.max_pass_rate_regression, baseline) {
            let base_rate = summarize(baseline).pass_rate;
            let regression = base_rate - summary.pass_rate;
            if !at_most(regression, max) {
                reasons.push(measured(
                    reason(
                        ReasonCode::PassRateRegression,
                        Some(suite),
                        format!(
                            "{label}: pass rate fell by {regression} from baseline {:?} \
                             ({base_rate} -> {}), more than the allowed {max}",
                            baseline.run_id, summary.pass_rate
                        ),
                    ),
                    regression,
                    max,
                ));
            }
        }
        for case in run
            .cases
            .iter()
            .filter(|c| c.critical && c.status.is_failure())
        {
            let persisting = baseline.is_some_and(|b| {
                b.cases
                    .iter()
                    .any(|bc| bc.id == case.id && bc.status.is_failure())
            });
            if !persisting {
                new_critical.push((suite, &run.run_id, case.id.as_str()));
            } else if rules.block_persisting_critical_failures {
                reasons.push(Reason {
                    case: Some(case.id.clone()),
                    ..reason(
                        ReasonCode::PersistingCriticalFailure,
                        Some(suite),
                        format!(
                            "{label}: critical case {:?} also fails in the baseline",
                            case.id
                        ),
                    )
                });
            }
        }
        summaries.push(summary.into_summary(suite));
    }
    let allowed = usize::try_from(rules.max_new_critical_failures).unwrap_or(usize::MAX);
    if new_critical.len() > allowed {
        for (suite, run_id, case) in new_critical {
            reasons.push(Reason {
                case: Some(case.to_owned()),
                ..reason(
                    ReasonCode::NewCriticalFailure,
                    Some(suite),
                    format!("run {run_id:?}: critical case {case:?} fails (new failure)"),
                )
            });
        }
    }

    // 5. Metrics.
    for rule in &rules.metrics {
        if let Some(r) = check_metric(rule, &candidates) {
            reasons.push(r);
        }
    }

    // 6. Boundary.
    if let Some(rule) = &rules.boundary {
        check_boundary(rule, &candidates, input.required_suites, &mut reasons);
    }

    reasons.sort_by(compare_reasons);
    Decision {
        outcome: if reasons.is_empty() {
            Outcome::Certified
        } else {
            Outcome::Blocked
        },
        release: input.release.to_owned(),
        policy: PolicyRef::from(policy),
        required_suites: input.required_suites.iter().cloned().collect(),
        runs: runs.refs(),
        baseline_runs: baseline_runs.refs(),
        summaries,
        reasons,
    }
}

/// Canonical copies of the runs paired with their `RunRef`, in canonical
/// (suite, runId, hash) order.
struct Indexed(Vec<(RunRef, EvaluationRun)>);

impl Indexed {
    fn new(runs: &[EvaluationRun]) -> Self {
        let mut indexed: Vec<_> = runs
            .iter()
            .map(|run| {
                let run = canonical(run);
                (RunRef::from(&run), run)
            })
            .collect();
        indexed.sort_by(|(a, _), (b, _)| {
            (&a.suite, &a.run_id, &a.hash).cmp(&(&b.suite, &b.run_id, &b.hash))
        });
        Indexed(indexed)
    }

    fn refs(&self) -> Vec<RunRef> {
        self.0.iter().map(|(r, _)| r.clone()).collect()
    }
}

/// A copy of `run` with its cases in a total order (id, then every other
/// field) and `covers` / `evaluators` sorted. Everything `decide` derives
/// from a run (its hash, the positional `cases[i]` in validation messages)
/// is computed from this copy, so the order of cases in the input cannot
/// change the decision, even when case ids are duplicated.
fn canonical(run: &EvaluationRun) -> EvaluationRun {
    let mut run = run.clone();
    run.cases.sort_by(compare_cases);
    run.covers.sort();
    run.evaluators.sort();
    run
}

/// A total order on cases: id first, then all remaining fields.
fn compare_cases(a: &CaseResult, b: &CaseResult) -> Ordering {
    let score = |x: Option<f64>, y: Option<f64>| match (x, y) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (x, y) => x.is_some().cmp(&y.is_some()),
    };
    a.id.cmp(&b.id)
        .then_with(|| a.status.cmp(&b.status))
        .then_with(|| a.critical.cmp(&b.critical))
        .then_with(|| score(a.score, b.score))
        .then_with(|| a.duration_ms.cmp(&b.duration_ms))
        .then_with(|| a.expect.cmp(&b.expect))
        .then_with(|| {
            a.metrics
                .iter()
                .map(|(k, v)| (k, v.to_bits()))
                .cmp(b.metrics.iter().map(|(k, v)| (k, v.to_bits())))
        })
}

/// The structurally valid runs, in canonical order; each problem of the
/// others becomes an `InvalidInput` reason.
fn valid_runs<'a>(
    runs: &'a Indexed,
    what: &str,
    reasons: &mut Vec<Reason>,
) -> Vec<&'a EvaluationRun> {
    let mut valid = Vec::with_capacity(runs.0.len());
    for (_, run) in &runs.0 {
        let issues = run.validate();
        if issues.is_empty() {
            valid.push(run);
        }
        for issue in issues {
            reasons.push(reason(
                ReasonCode::InvalidInput,
                Some(&run.suite.name),
                format!("{what} {:?}: {issue}", run.run_id),
            ));
        }
    }
    valid
}

/// Case counts and rates of one run.
struct Stats {
    cases: usize,
    passed: usize,
    failed: usize,
    errored: usize,
    skipped: usize,
    executed: usize,
    pass_rate: f64,
    coverage: f64,
}

impl Stats {
    fn into_summary(self, suite: &str) -> SuiteSummary {
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        SuiteSummary {
            suite: suite.to_owned(),
            cases: count(self.cases),
            passed: count(self.passed),
            failed: count(self.failed),
            errored: count(self.errored),
            skipped: count(self.skipped),
            pass_rate: self.pass_rate,
            coverage: self.coverage,
        }
    }
}

fn summarize(run: &EvaluationRun) -> Stats {
    let count = |status: CaseStatus| run.cases.iter().filter(|c| c.status == status).count();
    let (passed, failed, errored, skipped) = (
        count(CaseStatus::Pass),
        count(CaseStatus::Fail),
        count(CaseStatus::Error),
        count(CaseStatus::Skipped),
    );
    let cases = run.cases.len();
    let executed = cases - skipped;
    let ratio = |n: usize, d: usize| if d == 0 { 0.0 } else { n as f64 / d as f64 };
    Stats {
        cases,
        passed,
        failed,
        errored,
        skipped,
        executed,
        pass_rate: ratio(passed, executed),
        coverage: ratio(executed, cases),
    }
}

/// Evaluate one metric rule over the executed cases of the matching runs.
fn check_metric(rule: &MetricRule, runs: &[&EvaluationRun]) -> Option<Reason> {
    let mut values: Vec<f64> = runs
        .iter()
        .filter(|run| rule.suite.as_ref().is_none_or(|s| *s == run.suite.name))
        .flat_map(|run| &run.cases)
        .filter(|case| case.status != CaseStatus::Skipped)
        .filter_map(|case| case.metrics.get(&rule.metric).copied())
        .collect();
    // Sorting first also makes the mean independent of input order.
    values.sort_by(f64::total_cmp);
    let observed = aggregate(&values, rule.aggregate)?;
    let (holds, symbol) = match rule.op {
        Comparison::Lte => (at_most(observed, rule.value), "<="),
        Comparison::Gte => (at_least(observed, rule.value), ">="),
    };
    if holds {
        return None;
    }
    let scope = rule
        .suite
        .as_ref()
        .map_or_else(|| "all runs".to_owned(), |s| format!("suite {s:?}"));
    Some(measured(
        reason(
            ReasonCode::MetricThreshold,
            rule.suite.as_deref(),
            format!(
                "{}({}) over {scope} is {observed}, required {symbol} {}",
                aggregate_name(rule.aggregate),
                rule.metric,
                rule.value
            ),
        ),
        observed,
        rule.value,
    ))
}

/// Two-way boundary check of every listed suite. A listed suite no run
/// covers is incomplete (fail closed), unless it is required: step 3 has
/// already reported it as `MissingSuite`.
fn check_boundary(
    rule: &BoundaryRule,
    runs: &[&EvaluationRun],
    required: &BTreeSet<String>,
    reasons: &mut Vec<Reason>,
) {
    let listed: BTreeSet<&str> = rule.suites.iter().map(String::as_str).collect();
    for suite in listed {
        let covering: Vec<&EvaluationRun> = runs
            .iter()
            .copied()
            .filter(|run| run.covers.iter().any(|c| c == suite))
            .collect();
        if covering.is_empty() {
            if !required.contains(suite) {
                reasons.push(reason(
                    ReasonCode::BoundaryIncomplete,
                    Some(suite),
                    format!(
                        "boundary suite {suite:?}: no run covers it; import a run that covers {suite:?} \
                         with labelled cases, or remove it from rules.boundary.suites"
                    ),
                ));
            }
            continue;
        }
        // (passed, total) per label.
        let tally = |expect: Expect| {
            covering
                .iter()
                .flat_map(|run| &run.cases)
                .filter(|case| case.expect == Some(expect))
                .fold((0usize, 0usize), |(passed, total), case| {
                    (passed + usize::from(case.status == CaseStatus::Pass), total + 1)
                })
        };
        let (deny_passed, denies) = tally(Expect::Deny);
        let (allow_passed, allows) = tally(Expect::Allow);
        let incomplete = |what: &str| {
            reason(
                ReasonCode::BoundaryIncomplete,
                Some(suite),
                format!(
                    "boundary suite {suite:?} has {what}; label cases with expect allow and deny \
                     so the boundary is measured both ways"
                ),
            )
        };
        if denies + allows == 0 {
            reasons.push(incomplete("no labelled cases"));
            continue;
        }
        if denies == 0 {
            reasons.push(incomplete("no deny cases"));
        }
        if allows == 0 {
            reasons.push(incomplete("no allow cases"));
        }
        let rate = |n: usize, d: usize| n as f64 / d as f64;
        if denies > 0 {
            let observed = rate(deny_passed, denies);
            if !at_least(observed, rule.min_deny_rate) {
                reasons.push(measured(
                    reason(
                        ReasonCode::UnderBlocking,
                        Some(suite),
                        format!(
                            "boundary suite {suite:?}: deny rate {observed} ({deny_passed}/{denies} deny cases \
                             refused) is below the minimum {}",
                            rule.min_deny_rate
                        ),
                    ),
                    observed,
                    rule.min_deny_rate,
                ));
            }
        }
        if allows > 0 {
            let observed = rate(allow_passed, allows);
            if !at_least(observed, rule.min_allow_rate) {
                reasons.push(measured(
                    reason(
                        ReasonCode::OverRefusal,
                        Some(suite),
                        format!(
                            "boundary suite {suite:?}: allow rate {observed} ({allow_passed}/{allows} allow cases \
                             completed) is below the minimum {}",
                            rule.min_allow_rate
                        ),
                    ),
                    observed,
                    rule.min_allow_rate,
                ));
            }
        }
    }
}

/// Aggregate ascending-sorted values; `None` when there are none.
fn aggregate(sorted: &[f64], aggregate: Aggregate) -> Option<f64> {
    match aggregate {
        Aggregate::Mean => mean(sorted),
        Aggregate::P50 => nearest_rank(sorted, 50),
        Aggregate::P95 => nearest_rank(sorted, 95),
        Aggregate::Min => sorted.first().copied(),
        Aggregate::Max => sorted.last().copied(),
    }
}

/// Arithmetic mean of ascending-sorted finite values, without overflow.
///
/// The plain sum is used when it is finite; otherwise the values are scaled
/// down by an exact power of two so the partial sums cannot overflow. The
/// result is clamped to `[min, max]`, where the true mean always lies.
fn mean(sorted: &[f64]) -> Option<f64> {
    let (&lo, &hi) = (sorted.first()?, sorted.last()?);
    let n = sorted.len() as f64;
    let sum: f64 = sorted.iter().sum();
    let mean = if sum.is_finite() {
        sum / n
    } else {
        // 2^-k with 2^k >= n keeps |sum of scaled values| <= f64::MAX.
        let k = sorted.len().next_power_of_two().trailing_zeros() as i32;
        let scale = 2f64.powi(k);
        let scaled: f64 = sorted.iter().map(|v| v / scale).sum();
        scaled / n * scale
    };
    // NaN inputs (rejected by validation) propagate rather than clamp.
    Some(if mean < lo {
        lo
    } else if mean > hi {
        hi
    } else {
        mean
    })
}

fn aggregate_name(aggregate: Aggregate) -> &'static str {
    match aggregate {
        Aggregate::Mean => "mean",
        Aggregate::P50 => "p50",
        Aggregate::P95 => "p95",
        Aggregate::Min => "min",
        Aggregate::Max => "max",
    }
}

/// Nearest-rank percentile: the value at 1-based rank `ceil(pct / 100 * n)`.
fn nearest_rank(sorted: &[f64], pct: usize) -> Option<f64> {
    let rank = pct.saturating_mul(sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// `x >= min`; false when either is NaN, so a check fails closed.
fn at_least(x: f64, min: f64) -> bool {
    matches!(
        x.partial_cmp(&min),
        Some(Ordering::Greater | Ordering::Equal)
    )
}

/// `x <= max`; false when either is NaN, so a check fails closed.
fn at_most(x: f64, max: f64) -> bool {
    matches!(x.partial_cmp(&max), Some(Ordering::Less | Ordering::Equal))
}

fn reason(code: ReasonCode, suite: Option<&str>, message: String) -> Reason {
    Reason {
        code,
        message,
        suite: suite.map(str::to_owned),
        case: None,
        observed: None,
        required: None,
    }
}

fn measured(reason: Reason, observed: f64, required: f64) -> Reason {
    Reason {
        observed: Some(observed),
        required: Some(required),
        ..reason
    }
}

/// Contract order (code, suite, case, message); the measured values break
/// any remaining tie so the order never depends on the input order.
fn compare_reasons(a: &Reason, b: &Reason) -> Ordering {
    let num = |x: Option<f64>, y: Option<f64>| match (x, y) {
        (Some(x), Some(y)) => x.total_cmp(&y),
        (x, y) => x.is_some().cmp(&y.is_some()),
    };
    (a.code, &a.suite, &a.case, &a.message)
        .cmp(&(b.code, &b.suite, &b.case, &b.message))
        .then_with(|| num(a.observed, b.observed))
        .then_with(|| num(a.required, b.required))
}
