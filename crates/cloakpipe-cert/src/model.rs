//! Shared certification data model.
//!
//! Every object that feeds a certification decision has a canonical,
//! domain-separated hash (RFC 8785 JSON, like Agent Release manifests), so a
//! decision pins the exact release, runs and policy it was made from.

use cloakpipe_release::namespace::{self, Namespace};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The `apiVersion` writers emit; readers also accept the legacy
/// `cloakpipe.dev/v1alpha1` (see [`cloakpipe_release::namespace`]).
pub const API_VERSION: &str = namespace::API_VERSION;
pub const RUN_KIND: &str = "EvaluationRun";
pub const POLICY_KIND: &str = "CertificationPolicy";

/// Hash domains of current-namespace runs and policies. An object issued
/// under the legacy `cloakpipe.dev/v1alpha1` hashes with the legacy domain
/// ([`Namespace::for_hashing`]), so its issued hash stays valid.
pub const RUN_HASH_DOMAIN: &str = namespace::EVALUATION_RUN_HASH_DOMAIN;
pub const POLICY_HASH_DOMAIN: &str = namespace::CERTIFICATION_POLICY_HASH_DOMAIN;

/// The `apiVersion` problem of an object, if any.
fn api_version_issue(api_version: &str) -> Option<String> {
    (!namespace::is_known_api_version(api_version))
        .then(|| format!("apiVersion: expected {API_VERSION} (or legacy {})", namespace::LEGACY_API_VERSION))
}

/// `sha256:<hex>` of `SHA-256(domain || "\n" || RFC8785(value))`.
pub fn domain_hash(domain: &str, value: &serde_json::Value) -> String {
    let bytes = serde_json_canonicalizer::to_vec(value).expect("JSON-representable value");
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\n");
    h.update(bytes);
    format!("sha256:{}", hex::encode(h.finalize()))
}

// ── Evaluation runs ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Pass,
    Fail,
    /// The case could not be evaluated (crash, timeout). Counts as a failure.
    Error,
    /// Not executed. Excluded from pass rate; reduces coverage.
    Skipped,
}

impl CaseStatus {
    /// Fail and Error are both failures for certification purposes.
    pub fn is_failure(self) -> bool {
        matches!(self, CaseStatus::Fail | CaseStatus::Error)
    }
}

/// What a correct agent does in a boundary case (`CaseResult::expect`): the
/// action is legitimate and must go through, or it must be refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Allow,
    Deny,
}

impl std::str::FromStr for Expect {
    type Err = String;

    /// `allow` or `deny`, surrounding whitespace ignored.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "allow" => Ok(Expect::Allow),
            "deny" => Ok(Expect::Deny),
            other => Err(format!("{other:?} is not allow or deny")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseResult {
    /// Stable case identity across runs, e.g. `refunds::requires_identity`.
    pub id: String,
    /// Critical cases have zero tolerance for failure.
    #[serde(default)]
    pub critical: bool,
    pub status: CaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metrics: BTreeMap<String, f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Boundary label: whether the case's action should be allowed or
    /// denied (`rules.boundary`). Not serialized when absent, so unlabelled
    /// runs keep their hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<Expect>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteRef {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluatorRef {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Junit,
    Json,
    Braintrust,
    Langfuse,
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunSource {
    pub kind: SourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// One execution of one suite against one exact Agent Release.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvaluationRun {
    pub api_version: String,
    pub kind: String,
    pub run_id: String,
    /// The evaluated release: its `sha256:<hex>` manifest hash.
    pub release: String,
    pub suite: SuiteRef,
    /// Assurance suites this run provides evidence for (names from
    /// `cloakpipe_release::Suite`, e.g. `privacy`, `trajectory`).
    pub covers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluators: Vec<EvaluatorRef>,
    pub source: RunSource,
    pub cases: Vec<CaseResult>,
}

impl EvaluationRun {
    /// Order-insensitive canonical view: cases sorted by id, `covers` and
    /// `evaluators` sorted. Case order within a run is not meaningful.
    pub fn canonical_view(&self) -> serde_json::Value {
        let mut run = self.clone();
        run.cases.sort_by(|a, b| a.id.cmp(&b.id));
        run.covers.sort();
        run.evaluators.sort();
        serde_json::to_value(run).expect("serialisable")
    }

    pub fn run_hash(&self) -> String {
        domain_hash(Namespace::for_hashing(&self.api_version).evaluation_run_hash_domain(), &self.canonical_view())
    }

    /// Structural problems that make the run unusable as evidence.
    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        issues.extend(api_version_issue(&self.api_version));
        if self.kind != RUN_KIND {
            issues.push(format!("kind: expected {RUN_KIND}"));
        }
        if self.run_id.trim().is_empty() {
            issues.push("runId: must not be empty".into());
        }
        if self.release.parse::<cloakpipe_release::ReleaseHash>().is_err() {
            issues.push(format!("release: {:?} is not a sha256:<hex> manifest hash", self.release));
        }
        if self.suite.name.trim().is_empty() || self.suite.version.trim().is_empty() {
            issues.push("suite: name and version are required".into());
        }
        if self.covers.is_empty() {
            issues.push("covers: at least one assurance suite is required".into());
        }
        for c in &self.covers {
            if c.parse::<cloakpipe_release::Suite>().is_err() {
                issues.push(format!("covers: unknown assurance suite {c:?}"));
            }
        }
        let mut ids = BTreeSet::new();
        for (i, case) in self.cases.iter().enumerate() {
            if case.id.trim().is_empty() {
                issues.push(format!("cases[{i}].id: must not be empty"));
            } else if !ids.insert(case.id.as_str()) {
                issues.push(format!("cases[{i}].id: duplicate case id {:?}", case.id));
            }
            if case.score.is_some_and(|s| !s.is_finite()) {
                issues.push(format!("cases[{i}].score: must be finite"));
            }
            for (k, v) in &case.metrics {
                if !v.is_finite() {
                    issues.push(format!("cases[{i}].metrics.{k}: must be finite"));
                }
            }
        }
        issues
    }
}

// ── Certification policy ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Aggregate {
    Mean,
    P50,
    P95,
    Min,
    Max,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    /// observed <= value
    Lte,
    /// observed >= value
    Gte,
}

/// A threshold on a per-case metric aggregated over a suite's executed cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricRule {
    pub metric: String,
    pub aggregate: Aggregate,
    pub op: Comparison,
    pub value: f64,
    /// Restrict to runs of this suite name; all runs when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
}

fn default_min_coverage() -> f64 {
    0.99
}

fn default_true() -> bool {
    true
}

fn default_min_deny_rate() -> f64 {
    1.0
}

fn default_min_allow_rate() -> f64 {
    0.9
}

/// Two-way boundary rule: in the listed assurance suites, labelled deny
/// cases must be refused (no under-blocking) *and* labelled allow cases must
/// go through (no over-refusal), so refusing everything cannot pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BoundaryRule {
    /// Assurance suite names (`cloakpipe_release::Suite`, e.g.
    /// `authorization`, `access_control`, `side_effect`).
    pub suites: Vec<String>,
    /// Passed deny cases / deny cases must be >= this (0..=1).
    #[serde(default = "default_min_deny_rate")]
    pub min_deny_rate: f64,
    /// Passed allow cases / allow cases must be >= this (0..=1).
    #[serde(default = "default_min_allow_rate")]
    pub min_allow_rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Rules {
    /// Critical cases failing in the candidate but not in the baseline.
    #[serde(default)]
    pub max_new_critical_failures: u32,
    /// Also block on critical cases that fail in both candidate and baseline.
    #[serde(default = "default_true")]
    pub block_persisting_critical_failures: bool,
    /// Per suite: passed / (executed) must be >= this (0..=1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_pass_rate: Option<f64>,
    /// Per suite: baseline pass rate - candidate pass rate must be <= this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_pass_rate_regression: Option<f64>,
    /// Per suite: executed / total cases must be >= this (0..=1).
    #[serde(default = "default_min_coverage")]
    pub min_coverage: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricRule>,
    /// Two-way boundary certification; not serialized when absent, so
    /// policies without it keep their hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<BoundaryRule>,
}

impl Default for Rules {
    fn default() -> Self {
        Rules {
            max_new_critical_failures: 0,
            block_persisting_critical_failures: true,
            min_pass_rate: None,
            max_pass_rate_regression: None,
            min_coverage: default_min_coverage(),
            metrics: Vec::new(),
            boundary: None,
        }
    }
}

fn default_validity_days() -> u32 {
    30
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificationPolicy {
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub rules: Rules,
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
}

impl CertificationPolicy {
    pub fn policy_hash(&self) -> String {
        domain_hash(
            Namespace::for_hashing(&self.api_version).certification_policy_hash_domain(),
            &serde_json::to_value(self).expect("serialisable"),
        )
    }

    pub fn validate(&self) -> Vec<String> {
        let mut issues = Vec::new();
        issues.extend(api_version_issue(&self.api_version));
        if self.kind != POLICY_KIND {
            issues.push(format!("kind: expected {POLICY_KIND}"));
        }
        if self.name.trim().is_empty() || self.version.trim().is_empty() {
            issues.push("name and version are required".into());
        }
        let unit = |v: f64| (0.0..=1.0).contains(&v);
        if self.rules.min_pass_rate.is_some_and(|v| !unit(v)) {
            issues.push("rules.minPassRate: must be within 0..=1".into());
        }
        if self.rules.max_pass_rate_regression.is_some_and(|v| !unit(v)) {
            issues.push("rules.maxPassRateRegression: must be within 0..=1".into());
        }
        if !unit(self.rules.min_coverage) {
            issues.push("rules.minCoverage: must be within 0..=1".into());
        }
        for (i, m) in self.rules.metrics.iter().enumerate() {
            if !m.value.is_finite() {
                issues.push(format!("rules.metrics[{i}].value: must be finite"));
            }
        }
        if let Some(b) = &self.rules.boundary {
            if b.suites.is_empty() {
                issues.push("rules.boundary.suites: at least one assurance suite is required".into());
            }
            let mut seen = BTreeSet::new();
            for s in &b.suites {
                if s.parse::<cloakpipe_release::Suite>().is_err() {
                    issues.push(format!("rules.boundary.suites: unknown assurance suite {s:?}"));
                } else if !seen.insert(s.as_str()) {
                    issues.push(format!("rules.boundary.suites: duplicate suite {s:?}"));
                }
            }
            if !unit(b.min_deny_rate) {
                issues.push("rules.boundary.minDenyRate: must be within 0..=1".into());
            }
            if !unit(b.min_allow_rate) {
                issues.push("rules.boundary.minAllowRate: must be within 0..=1".into());
            }
        }
        if self.validity_days == 0 {
            issues.push("validityDays: must be at least 1".into());
        }
        issues
    }
}

// ── Decision ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Certified,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    /// A run (or the policy) is structurally invalid.
    InvalidInput,
    /// A candidate run evaluated a different release.
    ReleaseMismatch,
    /// No valid candidate run of this release remains: nothing to certify on.
    NoEvidence,
    /// A required assurance suite has no run covering it.
    MissingSuite,
    /// A covering run has no executed cases.
    NoCases,
    NewCriticalFailure,
    PersistingCriticalFailure,
    CoverageBelowMinimum,
    PassRateBelowMinimum,
    PassRateRegression,
    MetricThreshold,
    /// A boundary suite's deny rate (refused deny cases / deny cases) is
    /// below `rules.boundary.minDenyRate`: actions that must be refused
    /// went through.
    UnderBlocking,
    /// A boundary suite's allow rate (completed allow cases / allow cases)
    /// is below `rules.boundary.minAllowRate`: legitimate actions were
    /// refused.
    OverRefusal,
    /// A boundary suite with evidence lacks allow cases, deny cases, or any
    /// labelled case, so the boundary is not measured both ways.
    BoundaryIncomplete,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Reason {
    pub code: ReasonCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRef {
    pub run_id: String,
    pub suite: String,
    pub hash: String,
}

impl From<&EvaluationRun> for RunRef {
    fn from(r: &EvaluationRun) -> Self {
        RunRef { run_id: r.run_id.clone(), suite: r.suite.name.clone(), hash: r.run_hash() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyRef {
    pub name: String,
    pub version: String,
    pub hash: String,
}

impl From<&CertificationPolicy> for PolicyRef {
    fn from(p: &CertificationPolicy) -> Self {
        PolicyRef { name: p.name.clone(), version: p.version.clone(), hash: p.policy_hash() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SuiteSummary {
    /// Run suite name (`EvaluationRun.suite.name`).
    pub suite: String,
    pub cases: u32,
    pub passed: u32,
    pub failed: u32,
    pub errored: u32,
    pub skipped: u32,
    /// passed / (cases - skipped); 0 when nothing executed.
    pub pass_rate: f64,
    /// (cases - skipped) / cases; 0 when there are no cases.
    pub coverage: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Decision {
    pub outcome: Outcome,
    pub release: String,
    pub policy: PolicyRef,
    pub required_suites: Vec<String>,
    pub runs: Vec<RunRef>,
    pub baseline_runs: Vec<RunRef>,
    pub summaries: Vec<SuiteSummary>,
    pub reasons: Vec<Reason>,
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn run() -> EvaluationRun {
        serde_json::from_value(serde_json::json!({
            "apiVersion": API_VERSION,
            "kind": RUN_KIND,
            "runId": "run-1",
            "release": format!("sha256:{}", "ae".repeat(32)),
            "suite": {"name": "support-critical", "version": "23"},
            "covers": ["privacy", "functional"],
            "source": {"kind": "junit", "tool": "pytest"},
            "cases": [
                {"id": "b", "status": "pass"},
                {"id": "a", "status": "fail", "critical": true, "metrics": {"latency_ms": 120.0}}
            ]
        }))
        .unwrap()
    }

    #[test]
    fn valid_run_has_no_issues() {
        assert_eq!(run().validate(), Vec::<String>::new());
    }

    #[test]
    fn run_hash_ignores_case_and_covers_order() {
        let a = run();
        let mut b = run();
        b.cases.reverse();
        b.covers.reverse();
        assert_eq!(a.run_hash(), b.run_hash());
        assert!(a.run_hash().starts_with("sha256:"));
    }

    #[test]
    fn run_hash_changes_with_any_result() {
        let a = run();
        let mut b = run();
        b.cases[0].status = CaseStatus::Fail;
        assert_ne!(a.run_hash(), b.run_hash());
        let mut c = run();
        c.release = format!("sha256:{}", "af".repeat(32));
        assert_ne!(a.run_hash(), c.run_hash());
    }

    #[test]
    fn invalid_runs_are_reported() {
        let mut r = run();
        r.cases.push(CaseResult { id: "a".into(), critical: false, status: CaseStatus::Pass, score: None, metrics: Default::default(), duration_ms: None, expect: None });
        r.covers.push("vibes".into());
        r.release = "support-agent@184".into();
        let issues = r.validate().join("\n");
        assert!(issues.contains("duplicate case id"), "{issues}");
        assert!(issues.contains("unknown assurance suite"), "{issues}");
        assert!(issues.contains("release"), "{issues}");
    }

    #[test]
    fn policy_defaults_and_hash() {
        let p: CertificationPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": API_VERSION, "kind": POLICY_KIND, "name": "support-prod", "version": "11"
        }))
        .unwrap();
        assert_eq!(p.rules.min_coverage, 0.99);
        assert!(p.rules.block_persisting_critical_failures);
        assert_eq!(p.validity_days, 30);
        assert_eq!(p.validate(), Vec::<String>::new());
        let mut q = p.clone();
        q.rules.min_pass_rate = Some(0.95);
        assert_ne!(p.policy_hash(), q.policy_hash());
    }
}
