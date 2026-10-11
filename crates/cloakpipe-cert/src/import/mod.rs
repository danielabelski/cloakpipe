//! Import external evaluation results as [`EvaluationRun`]s.
//!
//! Contract (see docs/CERTIFICATION.md §Import):
//!
//! **JUnit XML** (`from_junit`) — the de-facto CI format (pytest, Jest, Go,
//! JUnit, cargo-nextest):
//! - Accepts a `<testsuites>` root with any number of `<testsuite>` children,
//!   or a bare `<testsuite>` root. Nested `<testsuite>` elements are walked.
//! - Each `<testcase>` becomes one [`CaseResult`] with
//!   `id = "{classname}::{name}"`, or just `name` when `classname` is absent
//!   or empty.
//! - Status: a `<failure>` child → `Fail`; `<error>` → `Error`; `<skipped>` →
//!   `Skipped`; otherwise `Pass`. If several are present, precedence is
//!   error > failure > skipped.
//! - `time="<seconds>"` → `duration_ms` (rounded to nearest ms); absent or
//!   unparseable → `None`.
//! - Case-level `<properties><property name=… value=…/></properties>`:
//!   `cloakpipe.critical` = `true`/`false`; `cloakpipe.score` = f64;
//!   `cloakpipe.metric.<name>` = f64 → `metrics[<name>]`;
//!   `cloakpipe.expect` = `allow`/`deny` → `expect` (boundary label). Non-finite or
//!   unparseable numeric values, any other `expect` value, and a property
//!   given twice are an error. Unknown properties are ignored.
//! - A case is also critical if its id matches any pattern in
//!   `ImportMeta::critical`: a pattern ending in `*` is a prefix match,
//!   otherwise an exact match.
//! - Duplicate case ids → `ImportError::Invalid`. Malformed XML →
//!   `ImportError::Xml`. Zero test cases is allowed (the decision reports it).
//! - Run fields (`runId`, `release`, `suite`, `covers`, `dataset`,
//!   `evaluators`) come from [`ImportMeta`]; `source = {kind: junit, tool}`.
//! - The resulting run must pass [`EvaluationRun::validate`], else
//!   `ImportError::Invalid` with the issues.
//! - Never panics on any input.
//!
//! **Native JSON** (`from_json`): the [`EvaluationRun`] JSON format itself
//! (camelCase, unknown fields rejected), validated with
//! [`EvaluationRun::validate`].
//!
//! **Scores** (shared by `from_braintrust`, `from_langfuse_experiment` and
//! `from_langfuse`): eval
//! platforms report per-case scores, not verdicts. With [`ScoreRules`]
//! (`pass_threshold`, default 0.5, must be finite and within `0..=1`, else
//! `ImportError::Invalid`; `score_names`, default empty = every score
//! counts, else only scores with these names count and all others are
//! ignored without validation):
//! - Status: an explicit error → `Error`; no numeric score at all, or a
//!   selected score name missing → `Error` (unscored is no evidence: fail
//!   closed); otherwise `Pass` iff every score is `>= pass_threshold`, else
//!   `Fail`. Nothing is `Skipped`.
//! - `score` = arithmetic mean of the case's scores; each score is also
//!   `metrics["score.<name>"]` (name verbatim).
//! - A score outside `0..=1`, or a score name given twice on one case (even
//!   if one occurrence is `null`), is `ImportError::Invalid` naming the case.
//! - Critical: the source's own flag (if it has one) OR an
//!   [`ImportMeta::critical`] pattern.
//! - Duplicate case ids → `ImportError::Invalid`; malformed JSON →
//!   `ImportError::Json`; zero cases is allowed. A JSON object key the
//!   importer reads that appears twice is `Invalid` (never last-wins);
//!   unknown fields are ignored. `source = {kind, tool: meta.tool}`; the run
//!   must pass [`EvaluationRun::validate`]. Never panics on any input.
//!
//! **Braintrust** (`from_braintrust`) — an experiment's events, as returned
//! by `POST/GET /v1/experiment/{id}/fetch` or the SDK:
//! - Accepts `{"events": [...]}` (other keys such as `cursor` ignored), a
//!   top-level array of events, or JSONL (one event object per non-blank
//!   line; a JSONL parse error names the line). A lone object without
//!   `events` is a one-line JSONL file. A leading BOM is ignored.
//! - Only root spans are cases: `is_root == true`, or `span_parents`
//!   absent/`null`/`[]`, or `span_id == root_span_id`.
//!   `is_root` must be a bool and `span_parents` an array when present.
//! - Scorer spans (`span_attributes.type == "score"`) are where current
//!   SDKs log each scorer's result: their `scores` and `error` belong to the
//!   root whose `span_id` is their `root_span_id` (in any order in the
//!   input). Every other non-root span (task, LLM calls, an LLM judge's own
//!   calls) is ignored entirely; its scores are not merged. A score name on
//!   two scorer spans of one root is `Invalid`; the same name on the root
//!   and a scorer span counts once if the root's value is `null` or equal,
//!   else `Invalid`. Scorer spans whose root is not in the input are
//!   ignored.
//! - Case id: the first present (non-`null`) of `metadata.cloakpipe_case_id`,
//!   `metadata.case_id`, `origin.id` when `origin.object_type == "dataset"`
//!   (the dataset record, current SDKs), `dataset_record_id` (older SDKs);
//!   it must be a non-empty string without leading or trailing whitespace.
//!   None present → `Invalid`: the row `id` changes between runs, so it is
//!   never used. `origin` must be an object when present. An experiment
//!   run with `trial_count > 1` has one root per trial and so duplicate
//!   case ids (`Invalid`, saying so).
//! - `scores`: object of name → number | `null`; `null` means not scored
//!   and is not counted; any other type is `Invalid`. Absent/`null` = no
//!   scores.
//! - `error` on the root or a scorer span, or a non-empty
//!   `metadata.scorer_errors` (a scorer that raised logs no score): anything
//!   but absent, `null`, `""`, `[]` or `{}` → `Error`.
//! - `metrics.start`/`metrics.end` (unix seconds) → `duration_ms` when both
//!   are numbers and `end >= start`; `metrics.prompt_tokens`,
//!   `completion_tokens`, `tokens` → `metrics["tokens.prompt"]`,
//!   `["tokens.completion"]`, `["tokens.total"]` when numbers. Other metrics
//!   are not imported. `metrics` and `metadata` must be objects when present.
//! - `metadata.critical`: `true`/`false`; present with any other value
//!   (including `null`) → `Invalid`.
//!
//! **Langfuse experiments** (`from_langfuse_experiment`) — Langfuse v4
//! public API (Langfuse Cloud, self-hosted v4+), an experiment plus its
//! items with their scores:
//! - `experiment_json`: `GET /api/public/experiments?id=<id>&fromStartTime=…`,
//!   an `ExperimentsResponse` page `{"data": [experiment], "meta": {…}}`
//!   holding exactly one experiment, or the bare experiment object. `id`
//!   must be a non-empty string, `itemCount` a whole number, `datasetId` a
//!   string or `null`; experiment-level scores are ignored (they summarize
//!   the run, not a case).
//! - `items_json`: every page of
//!   `GET /api/public/experiment-items?experimentId=<id>&fromStartTime=…&fields=core,dataset,scores&scoreLimit=50`,
//!   one `ExperimentItemsResponse` page `{"data": [...], "meta": {...}}` or
//!   an array of pages in fetch order. Pagination is by cursor: a page
//!   whose `meta.cursor` is a non-empty string has a next page. Fail
//!   closed: the last page must have no cursor (else the items are
//!   incomplete), every earlier page must have one, cursors must be
//!   distinct, and every page needs an object `meta` (bare items, without
//!   pages, are `Invalid`). The number of items must equal the
//!   experiment's `itemCount` (fetch both with the same
//!   `fromStartTime`/`toStartTime`), which also catches a dropped middle
//!   page.
//! - Each item is a case with `id = experimentItemId` (the dataset item id
//!   for a Langfuse dataset; non-empty, no leading or trailing whitespace);
//!   `traceId` must be a non-empty string and `experimentId` must equal the
//!   experiment's `id` (else `Invalid`: files from different experiments).
//!   A repeated `experimentItemId` is `Invalid`. `level == "ERROR"` → `Error`
//!   (`level` must be a string when present).
//! - `scores`: an array of `ScoreV3` objects or absent/`null` (no scores);
//!   Langfuse returns the item's own and its trace's scores here. If no item
//!   has a `scores` key at all, the items were fetched without
//!   `fields=scores`: `Invalid`. An item listing 50 or more scores (the
//!   maximum `scoreLimit`) may have been truncated: `Invalid`.
//! - `dataType` is required: `NUMERIC` → `value` must be a number;
//!   `BOOLEAN` → `value` must be a bool (`true` = 1, `false` = 0);
//!   `CATEGORICAL`, `TEXT`, `CORRECTION` → ignored; anything else →
//!   `Invalid`. A counted score needs a non-empty `name`; the same name
//!   twice on one item (e.g. a trace and an observation score) is
//!   `Invalid`.
//! - No critical flag: critical cases come from [`ImportMeta::critical`]
//!   patterns only. No `duration_ms` or other metrics are imported.
//! - `dataset` = [`ImportMeta::dataset`], else the experiment's `datasetId`.
//!
//! **Langfuse dataset runs** (`from_langfuse`, deprecated upstream: Langfuse
//! Cloud removes these endpoints on 2026-11-16, self-hosted with v4; use
//! `from_langfuse_experiment`) — a dataset run plus its scores:
//! - `run_json`: `GET /api/public/datasets/{dataset}/runs/{run}`, an object
//!   with a `datasetRunItems` array. Each item is a case with
//!   `id = datasetItemId` (non-empty string without leading or trailing
//!   whitespace, else `Invalid`); `traceId` must be a non-empty string and
//!   `observationId` a string or `null`.
//! - `scores_json`: `GET /api/public/v2/scores` output — one page
//!   `{"data": [...], "meta": {...}}`, a bare array of score objects, or an
//!   array of pages. When a page's `meta` has `page` and `totalPages`, every
//!   page `1..=totalPages` of that listing (same `totalPages`, `totalItems`
//!   and `limit`) must be present, else `Invalid` (a missing page could
//!   hold a failing score). A score repeating an `id` already seen
//!   (overlapping pages) counts once if its `name`, `value`, `traceId`,
//!   `observationId`, `dataType` and `stringValue` are the same, else
//!   `Invalid`. `traceId` must be a string when present. v3 output (scores
//!   with a `subject` and no `traceId`) is `Invalid`.
//! - Join: a score belongs to an item when `traceId` matches and the score's
//!   `observationId` is `null` (a trace score) or equals the item's
//!   `observationId`. Scores of other traces, or with no `traceId` (session
//!   or dataset-run scores), are ignored.
//! - `dataType`: `NUMERIC` (or absent) → `value` must be a number;
//!   `BOOLEAN` → `value` must be 0 or 1; `CATEGORICAL`, `TEXT`,
//!   `CORRECTION` → ignored (not numeric); anything else → `Invalid`. A joined score needs a non-empty
//!   `name`.
//! - Langfuse has no error flag on a run item, so status comes from scores
//!   alone (an item with no numeric score is `Error`), and no critical
//!   flag: critical cases come from [`ImportMeta::critical`] patterns only.
//!   No `duration_ms` or other metrics are imported.
//! - `dataset` = [`ImportMeta::dataset`], else the run's `datasetName`.

mod braintrust;
mod langfuse;
mod langfuse_experiment;
mod scores;

pub use braintrust::from_braintrust;
pub use langfuse::from_langfuse;
pub use langfuse_experiment::from_langfuse_experiment;
pub use scores::ScoreRules;

use crate::model::{
    CaseResult, CaseStatus, EvaluationRun, EvaluatorRef, RunSource, SourceKind, SuiteRef, API_VERSION, RUN_KIND,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::collections::BTreeMap;

/// Run-level metadata the imported report does not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportMeta {
    /// Becomes [`EvaluationRun::run_id`].
    pub run_id: String,
    /// `sha256:<hex>` manifest hash of the evaluated release.
    pub release: String,
    /// The evaluation suite that produced the report.
    pub suite: SuiteRef,
    /// Assurance suites the run provides evidence for, e.g. `privacy`.
    pub covers: Vec<String>,
    /// Dataset the suite ran against, if any.
    pub dataset: Option<String>,
    /// Evaluators (judges, scorers) used by the suite.
    pub evaluators: Vec<EvaluatorRef>,
    /// Name of the producing tool, e.g. `pytest`.
    pub tool: Option<String>,
    /// Case-id patterns marking cases critical (`prefix*` or exact).
    pub critical: Vec<String>,
}

impl ImportMeta {
    /// Whether `id` matches any of the [`ImportMeta::critical`] patterns.
    fn is_critical(&self, id: &str) -> bool {
        self.critical.iter().any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => id == pattern,
        })
    }
}

/// Why an import was rejected.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// The input is not well-formed XML.
    #[error("malformed XML: {0}")]
    Xml(String),
    /// The input is not valid JSON for an [`EvaluationRun`].
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The input parsed, but does not yield a valid [`EvaluationRun`]; one
    /// message per problem.
    #[error("invalid evaluation run: {}", .0.join("; "))]
    Invalid(Vec<String>),
}

/// Import a JUnit XML report as an [`EvaluationRun`] (see the module docs).
pub fn from_junit(xml: &str, meta: &ImportMeta) -> Result<EvaluationRun, ImportError> {
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let parsed = JunitParser::default().parse(xml)?;
    let issues = parsed.issues;

    let cases = parsed
        .cases
        .into_iter()
        .map(|case| {
            let critical = case.critical || meta.is_critical(&case.id);
            CaseResult { critical, ..case }
        })
        .collect();

    build_run(meta, SourceKind::Junit, meta.dataset.clone(), cases, issues)
}

/// The run of `cases` with its fields from `meta`; `Invalid` with `issues`
/// plus any [`EvaluationRun::validate`] problems unless both are empty.
fn build_run(
    meta: &ImportMeta,
    kind: SourceKind,
    dataset: Option<String>,
    cases: Vec<CaseResult>,
    mut issues: Vec<String>,
) -> Result<EvaluationRun, ImportError> {
    let run = EvaluationRun {
        api_version: API_VERSION.to_string(),
        kind: RUN_KIND.to_string(),
        run_id: meta.run_id.clone(),
        release: meta.release.clone(),
        suite: meta.suite.clone(),
        covers: meta.covers.clone(),
        dataset,
        evaluators: meta.evaluators.clone(),
        source: RunSource { kind, tool: meta.tool.clone() },
        cases,
    };
    issues.extend(run.validate());
    if issues.is_empty() {
        Ok(run)
    } else {
        Err(ImportError::Invalid(issues))
    }
}

/// Import an [`EvaluationRun`] from its native JSON form (see the module docs).
pub fn from_json(json: &str) -> Result<EvaluationRun, ImportError> {
    let run: EvaluationRun = serde_json::from_str(json)?;
    let issues = run.validate();
    if issues.is_empty() {
        Ok(run)
    } else {
        Err(ImportError::Invalid(issues))
    }
}

// ── JUnit parsing ───────────────────────────────────────────────────────

const PROP_CRITICAL: &str = "cloakpipe.critical";
const PROP_SCORE: &str = "cloakpipe.score";
const PROP_METRIC_PREFIX: &str = "cloakpipe.metric.";
/// Boundary label: the JUnit property, and the metadata key score-based
/// sources read.
pub(crate) const PROP_EXPECT: &str = "cloakpipe.expect";

/// Where an open element sits, which decides how its children are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    /// `<testsuites>`, `<testsuite>` or any other element outside a test
    /// case: a `<testcase>` child starts a new case.
    Container,
    /// An open `<testcase>`: status markers and `<properties>` apply to it.
    Case,
    /// `<properties>` directly inside a `<testcase>`.
    CaseProperties,
    /// Anything else inside a test case; its content is not interpreted.
    Opaque,
}

/// The test case currently being read.
#[derive(Debug)]
struct PendingCase {
    result: CaseResult,
    failure: bool,
    error: bool,
    skipped: bool,
    critical_set: bool,
    score_set: bool,
    expect_set: bool,
}

impl PendingCase {
    fn finish(self) -> CaseResult {
        let status = if self.error {
            CaseStatus::Error
        } else if self.failure {
            CaseStatus::Fail
        } else if self.skipped {
            CaseStatus::Skipped
        } else {
            CaseStatus::Pass
        };
        CaseResult { status, ..self.result }
    }
}

/// Cases read from a well-formed JUnit document, plus content problems.
#[derive(Debug, Default)]
struct Parsed {
    cases: Vec<CaseResult>,
    issues: Vec<String>,
}

#[derive(Debug, Default)]
struct JunitParser {
    stack: Vec<Frame>,
    seen_root: bool,
    pending: Option<PendingCase>,
    out: Parsed,
}

impl JunitParser {
    fn parse(mut self, xml: &str) -> Result<Parsed, ImportError> {
        if let Some((at, c)) = xml.char_indices().find(|&(_, c)| !is_xml_char(c)) {
            return Err(ImportError::Xml(format!("character {c:?} is not allowed in XML at byte {at}")));
        }
        let mut reader = Reader::from_str(xml);
        let mut seen_doctype = false;
        loop {
            let start = reader.buffer_position();
            let event = reader.read_event().map_err(|e| xml_error(&reader, e))?;
            match event {
                Event::Start(e) => {
                    let frame = self.open(&e)?;
                    self.stack.push(frame);
                }
                Event::Empty(e) => {
                    let frame = self.open(&e)?;
                    self.close(frame);
                }
                Event::End(_) => {
                    // quick-xml has already checked the name matches.
                    if let Some(frame) = self.stack.pop() {
                        self.close(frame);
                    }
                }
                Event::Text(t) => {
                    let text = t.xml10_content();
                    if self.stack.is_empty() {
                        if !text.chars().all(is_xml_space) {
                            return Err(ImportError::Xml("text outside the root element".into()));
                        }
                    } else if text.contains("]]>") {
                        return Err(ImportError::Xml(format!("']]>' in character data at byte {start}")));
                    }
                }
                Event::CData(_) | Event::GeneralRef(_) if self.stack.is_empty() => {
                    return Err(ImportError::Xml("content outside the root element".into()));
                }
                Event::GeneralRef(r) => {
                    resolve_reference(&r)?;
                }
                Event::Decl(d) => {
                    // The XML declaration may only open the document.
                    if start != 0 {
                        return Err(ImportError::Xml(format!("XML declaration not at the start of the document (byte {start})")));
                    }
                    d.version().map_err(|err| ImportError::Xml(format!("XML declaration: {err}")))?;
                }
                Event::PI(pi) => {
                    let target = pi.target();
                    if !is_xml_name(target) || target.eq_ignore_ascii_case("xml") {
                        return Err(ImportError::Xml(format!("invalid processing instruction target {target:?}")));
                    }
                }
                Event::DocType(_) => {
                    if self.seen_root || std::mem::replace(&mut seen_doctype, true) {
                        return Err(ImportError::Xml(format!("misplaced document type declaration at byte {start}")));
                    }
                }
                Event::Comment(c) => {
                    if c.contains("--") || c.ends_with('-') {
                        return Err(ImportError::Xml(format!("'--' in comment at byte {start}")));
                    }
                }
                Event::Eof => break,
                _ => {}
            }
        }
        if !self.seen_root {
            return Err(ImportError::Xml("no root element".into()));
        }
        if !self.stack.is_empty() {
            return Err(ImportError::Xml(format!("unexpected end of input: {} unclosed element(s)", self.stack.len())));
        }
        Ok(self.out)
    }

    /// Handle an opening (or self-closing) tag; returns the frame it opens.
    fn open(&mut self, e: &BytesStart<'_>) -> Result<Frame, ImportError> {
        let qname = e.name();
        if !is_xml_name(qname.as_ref()) {
            return Err(ImportError::Xml(format!("invalid element name {:?}", qname.as_ref())));
        }
        // Every element's attributes are checked, whether or not they are read.
        let attrs = attributes(e)?;
        let name = e.local_name();
        let name = name.as_ref();
        let Some(&parent) = self.stack.last() else {
            if self.seen_root {
                return Err(ImportError::Xml("more than one root element".into()));
            }
            self.seen_root = true;
            if name != "testsuites" && name != "testsuite" {
                self.out.issues.push(format!("root element must be <testsuites> or <testsuite>, found <{name}>"));
            }
            return Ok(Frame::Container);
        };
        Ok(match (parent, name) {
            (Frame::Container, "testcase") => {
                self.start_case(attrs);
                Frame::Case
            }
            (Frame::Container, _) => Frame::Container,
            (Frame::Case, "testcase") => {
                let id = self.pending.as_ref().map(|c| c.result.id.as_str()).unwrap_or_default();
                self.out.issues.push(format!("case {id:?}: nested <testcase> elements are not allowed"));
                Frame::Opaque
            }
            (Frame::Case, "properties") => Frame::CaseProperties,
            (Frame::Case, marker) => {
                if let Some(case) = self.pending.as_mut() {
                    match marker {
                        "failure" => case.failure = true,
                        "error" => case.error = true,
                        "skipped" => case.skipped = true,
                        _ => {}
                    }
                }
                Frame::Opaque
            }
            (Frame::CaseProperties, "property") => {
                self.read_property(attrs);
                Frame::Opaque
            }
            (Frame::CaseProperties | Frame::Opaque, _) => Frame::Opaque,
        })
    }

    /// Handle the end of an element opened with `frame`.
    fn close(&mut self, frame: Frame) {
        if frame == Frame::Case {
            if let Some(case) = self.pending.take() {
                self.out.cases.push(case.finish());
            }
        }
    }

    fn start_case(&mut self, mut attrs: BTreeMap<String, String>) {
        let name = attrs.remove("name").unwrap_or_default();
        let classname = attrs.remove("classname").unwrap_or_default();
        let id = if classname.is_empty() { name.clone() } else { format!("{classname}::{name}") };
        if name.trim().is_empty() {
            self.out.issues.push(format!("cases[{}]: <testcase> has no name", self.out.cases.len()));
        }
        let duration_ms = attrs.get("time").and_then(|t| seconds_to_ms(t));
        self.pending = Some(PendingCase {
            result: CaseResult {
                id,
                critical: false,
                status: CaseStatus::Pass,
                score: None,
                metrics: BTreeMap::new(),
                duration_ms,
                expect: None,
            },
            failure: false,
            error: false,
            skipped: false,
            critical_set: false,
            score_set: false,
            expect_set: false,
        });
    }

    fn read_property(&mut self, mut attrs: BTreeMap<String, String>) {
        let Some(case) = self.pending.as_mut() else { return };
        let Some(key) = attrs.remove("name") else { return };
        let value = attrs.remove("value");
        if let Err(problem) = apply_property(case, &key, value.as_deref()) {
            self.out.issues.push(format!("case {:?}: property {key}: {problem}", case.result.id));
        }
    }
}

/// Apply one case-level property; unknown keys are ignored.
fn apply_property(case: &mut PendingCase, key: &str, value: Option<&str>) -> Result<(), String> {
    let is_known =
        key == PROP_CRITICAL || key == PROP_SCORE || key == PROP_EXPECT || key.starts_with(PROP_METRIC_PREFIX);
    if !is_known {
        return Ok(());
    }
    let value = value.ok_or("missing value attribute")?.trim();
    if key == PROP_CRITICAL {
        if std::mem::replace(&mut case.critical_set, true) {
            return Err("given more than once".into());
        }
        case.result.critical = match value {
            "true" => true,
            "false" => false,
            other => return Err(format!("{other:?} is not true or false")),
        };
    } else if key == PROP_SCORE {
        if std::mem::replace(&mut case.score_set, true) {
            return Err("given more than once".into());
        }
        case.result.score = Some(finite(value)?);
    } else if key == PROP_EXPECT {
        if std::mem::replace(&mut case.expect_set, true) {
            return Err("given more than once".into());
        }
        case.result.expect = Some(value.parse()?);
    } else if let Some(metric) = key.strip_prefix(PROP_METRIC_PREFIX) {
        if metric.is_empty() {
            return Err("metric name is empty".into());
        }
        let v = finite(value)?;
        if case.result.metrics.insert(metric.to_string(), v).is_some() {
            return Err("given more than once".into());
        }
    }
    Ok(())
}

fn finite(value: &str) -> Result<f64, String> {
    match value.parse::<f64>() {
        Ok(v) if v.is_finite() => Ok(v),
        _ => Err(format!("{value:?} is not a finite number")),
    }
}

/// `time` in seconds to whole milliseconds; `None` if not a usable duration.
fn seconds_to_ms(time: &str) -> Option<u64> {
    secs_to_ms(time.trim().parse::<f64>().ok().filter(|s| s.is_sign_positive())?)
}

/// Seconds to whole milliseconds; `None` if negative, non-finite or too large.
fn secs_to_ms(secs: f64) -> Option<u64> {
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    let ms = (secs * 1000.0).round();
    // `u64::MAX as f64` rounds up to 2^64, so `<` excludes every overflow.
    (ms < u64::MAX as f64).then_some(ms as u64)
}

/// Decoded attributes of `e`, keyed by their full (qualified) name, so
/// `xmlns:name` or `foo:classname` never stand in for `name` or `classname`.
///
/// The attribute list is parsed strictly per XML 1.0 (`(S Name S? '=' S?
/// AttValue)* S?`): malformed or duplicate attributes, a raw `<` in a value,
/// undefined entity references and character references to characters XML
/// does not allow are all XML errors. Values are normalized as for CDATA
/// attributes (each literal tab, newline or end-of-line becomes a space).
fn attributes(e: &BytesStart<'_>) -> Result<BTreeMap<String, String>, ImportError> {
    let err = |what: &str| ImportError::Xml(format!("<{}>: {what}", e.name().as_ref()));
    let mut out = BTreeMap::new();
    let mut rest = e.attributes_raw();
    loop {
        let trimmed = rest.trim_start_matches(is_xml_space);
        let had_space = trimmed.len() != rest.len();
        rest = trimmed;
        if rest.is_empty() {
            return Ok(out);
        }
        if !had_space {
            return Err(err("attributes must be separated by whitespace"));
        }
        let name_end = rest.find(|c| is_xml_space(c) || c == '=').unwrap_or(rest.len());
        let (key, after) = rest.split_at(name_end);
        if !is_xml_name(key) {
            return Err(err(&format!("invalid attribute name {key:?}")));
        }
        let after = after.trim_start_matches(is_xml_space);
        let Some(after) = after.strip_prefix('=') else {
            return Err(err(&format!("attribute {key:?} has no value")));
        };
        let after = after.trim_start_matches(is_xml_space);
        let quote = match after.chars().next() {
            Some(q @ ('"' | '\'')) => q,
            _ => return Err(err(&format!("value of attribute {key:?} is not quoted"))),
        };
        let body = &after[1..];
        let Some(close) = body.find(quote) else {
            return Err(err(&format!("value of attribute {key:?} is not terminated")));
        };
        let value = decode_attribute_value(&body[..close]).map_err(|what| err(&format!("attribute {key:?}: {what}")))?;
        if out.insert(key.to_string(), value).is_some() {
            return Err(err(&format!("duplicate attribute {key:?}")));
        }
        rest = &body[close + 1..];
    }
}

/// Decode and normalize a raw attribute value (without its quotes).
fn decode_attribute_value(raw: &str) -> Result<String, ImportError> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(c) = rest.chars().next() {
        match c {
            '<' => return Err(ImportError::Xml("'<' in attribute value".into())),
            '&' => {
                let Some(end) = rest.find(';') else {
                    return Err(ImportError::Xml("unterminated reference in attribute value".into()));
                };
                out.push_str(&resolve(&rest[1..end])?);
                rest = &rest[end + 1..];
                continue;
            }
            '\r' => {
                out.push(' ');
                // `\r\n` is a single end-of-line.
                if rest[1..].starts_with('\n') {
                    rest = &rest[1..];
                }
            }
            '\t' | '\n' => out.push(' '),
            other => out.push(other),
        }
        rest = &rest[c.len_utf8()..];
    }
    Ok(out)
}

/// Check a reference in character data resolves (predefined entity or legal
/// character reference). Its value is not needed: text is never interpreted.
fn resolve_reference(r: &quick_xml::events::BytesRef<'_>) -> Result<(), ImportError> {
    resolve(r).map(drop)
}

/// Resolve the reference `&{name};`. Only the five predefined entities are
/// known (DTDs are not processed, so nothing else is declared), and a
/// character reference must name a character XML allows.
fn resolve(name: &str) -> Result<String, ImportError> {
    let predefined = match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "apos" => Some('\''),
        "quot" => Some('"'),
        _ => None,
    };
    if let Some(c) = predefined {
        return Ok(c.to_string());
    }
    let Some(num) = name.strip_prefix('#') else {
        return Err(ImportError::Xml(format!("undefined entity &{name};")));
    };
    let (digits, radix) = match num.strip_prefix('x') {
        Some(hex) => (hex, 16),
        None => (num, 10),
    };
    let code = (!digits.is_empty() && digits.chars().all(|c| c.is_digit(radix)))
        .then(|| u32::from_str_radix(digits, radix).ok())
        .flatten();
    match code.and_then(char::from_u32).filter(|&c| is_xml_char(c)) {
        Some(c) => Ok(c.to_string()),
        None => Err(ImportError::Xml(format!("invalid character reference &{name};"))),
    }
}

/// XML 1.0 `Char` (surrogates cannot occur in a Rust `char`).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..)
}

/// XML 1.0 `S`.
fn is_xml_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// XML 1.0 (fifth edition) `Name`.
fn is_xml_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start_char) && chars.all(is_name_char)
}

fn is_name_start_char(c: char) -> bool {
    matches!(c,
        ':' | 'A'..='Z' | '_' | 'a'..='z'
        | '\u{C0}'..='\u{D6}' | '\u{D8}'..='\u{F6}' | '\u{F8}'..='\u{2FF}'
        | '\u{370}'..='\u{37D}' | '\u{37F}'..='\u{1FFF}' | '\u{200C}'..='\u{200D}'
        | '\u{2070}'..='\u{218F}' | '\u{2C00}'..='\u{2FEF}' | '\u{3001}'..='\u{D7FF}'
        | '\u{F900}'..='\u{FDCF}' | '\u{FDF0}'..='\u{FFFD}' | '\u{10000}'..='\u{EFFFF}')
}

fn is_name_char(c: char) -> bool {
    is_name_start_char(c)
        || matches!(c, '-' | '.' | '0'..='9' | '\u{B7}' | '\u{300}'..='\u{36F}' | '\u{203F}'..='\u{2040}')
}

fn xml_error(reader: &Reader<&[u8]>, err: quick_xml::Error) -> ImportError {
    ImportError::Xml(format!("{err} at byte {}", reader.error_position()))
}
