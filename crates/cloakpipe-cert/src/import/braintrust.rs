//! Braintrust experiment export → [`EvaluationRun`] (contract in the
//! `import` module docs).

use super::scores::{json_error, metadata_expect, CaseScores, ScoreRules, J};
use super::{build_run, secs_to_ms, ImportError, ImportMeta};
use crate::model::{CaseResult, EvaluationRun, SourceKind};
use std::collections::BTreeMap;

/// Import a Braintrust experiment export as an [`EvaluationRun`] (see the
/// `import` module docs).
pub fn from_braintrust(json: &str, meta: &ImportMeta, rules: &ScoreRules) -> Result<EvaluationRun, ImportError> {
    let events = read_events(json)?;
    let mut issues = rules.issues();
    // Root spans, and the scorer spans of each root (by the root's span id).
    let mut roots = Vec::new();
    let mut scorers: BTreeMap<&str, Vec<(&str, &J)>> = BTreeMap::new();
    for (label, event) in &events {
        if !matches!(event, J::Obj(_)) {
            issues.push(format!("{label}: expected an event object, found {}", event.kind()));
            continue;
        }
        match is_root(label, event) {
            Ok(true) => roots.push((label.as_str(), event)),
            Ok(false) => {
                if let Some(root) = scorer_root(event) {
                    scorers.entry(root).or_default().push((label.as_str(), event));
                }
            }
            Err(problems) => issues.extend(problems),
        }
    }
    let mut cases: Vec<CaseResult> = Vec::new();
    for (label, event) in roots {
        let children = root_key(event).and_then(|k| scorers.get(k)).map_or(&[][..], Vec::as_slice);
        match read_event(label, event, children, meta, rules) {
            Ok(case) => cases.push(case),
            Err(problems) => issues.extend(problems),
        }
    }
    let mut seen = BTreeMap::new();
    for case in &cases {
        let n = seen.entry(case.id.as_str()).or_insert(0);
        *n += 1;
        if *n == 2 {
            issues.push(format!(
                "case id {:?} is on more than one root span: an experiment run with trial_count > 1 logs one \
                 root span per trial; import a run with one trial, or make metadata.cloakpipe_case_id unique \
                 per trial",
                case.id
            ));
        }
    }
    build_run(meta, SourceKind::Braintrust, meta.dataset.clone(), cases, issues)
}

/// Whether `event` is a root span (a case).
fn is_root(label: &str, event: &J) -> Result<bool, Vec<String>> {
    let at = |e: String| vec![format!("{label}: {e}")];
    let get = |key: &str| event.get(key).map_err(at);
    let is_root = match get("is_root")? {
        None => false,
        Some(J::Bool(b)) => *b,
        Some(other) => return Err(at(format!("is_root: expected a bool, found {}", other.kind()))),
    };
    let has_parents = match get("span_parents")? {
        None => false,
        Some(J::Arr(parents)) => !parents.is_empty(),
        Some(other) => return Err(at(format!("span_parents: expected an array, found {}", other.kind()))),
    };
    let same_span = match (get("span_id")?, get("root_span_id")?) {
        (Some(J::Str(a)), Some(J::Str(b))) => a == b,
        _ => false,
    };
    Ok(is_root || !has_parents || same_span)
}

/// The span id children of root `event` name as their `root_span_id`.
fn root_key(event: &J) -> Option<&str> {
    match (event.get("span_id"), event.get("root_span_id")) {
        (Ok(Some(J::Str(id))), _) | (_, Ok(Some(J::Str(id)))) => Some(id),
        _ => None,
    }
}

/// The `root_span_id` of a scorer span (`span_attributes.type == "score"`),
/// where the SDK logs each scorer's result; `None` for any other span.
fn scorer_root(event: &J) -> Option<&str> {
    let kind = event.get("span_attributes").ok()??.get("type").ok()??;
    match (kind, event.get("root_span_id")) {
        (J::Str(k), Ok(Some(J::Str(root)))) if k == "score" => Some(root),
        _ => None,
    }
}

/// The events of `json`, each with a label naming it in issues.
fn read_events(json: &str) -> Result<Vec<(String, J)>, ImportError> {
    let whole = match J::parse(json) {
        Ok(doc) => doc,
        Err(err) => return read_jsonl(json, err),
    };
    let indexed = |items: Vec<J>| items.into_iter().enumerate().map(|(i, e)| (format!("events[{i}]"), e)).collect();
    match whole {
        J::Arr(items) => Ok(indexed(items)),
        // A lone event object: JSONL with one line.
        J::Obj(_) if !has_key(&whole, "events") => Ok(vec![("line 1".into(), whole)]),
        J::Obj(_) => match whole.get("events").map_err(|e| ImportError::Invalid(vec![e]))? {
            Some(J::Arr(items)) => Ok(indexed(items.clone())),
            other => Err(ImportError::Invalid(vec![format!(
                "events: expected an array, found {}",
                other.map_or("null", J::kind)
            )])),
        },
        other => Err(ImportError::Invalid(vec![format!(
            "expected {{\"events\": [...]}}, an array of events or JSONL, found {}",
            other.kind()
        )])),
    }
}

fn has_key(obj: &J, key: &str) -> bool {
    matches!(obj, J::Obj(entries) if entries.iter().any(|(k, _)| k == key))
}

/// One event per non-blank line. If not even the first line parses, the
/// input was not JSONL either: report the whole-document error.
fn read_jsonl(json: &str, whole: serde_json::Error) -> Result<Vec<(String, J)>, ImportError> {
    let json = json.strip_prefix('\u{feff}').unwrap_or(json);
    let mut events = Vec::new();
    for (i, line) in json.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match J::parse(line) {
            Ok(event) => events.push((format!("line {}", i + 1), event)),
            Err(_) if events.is_empty() => return Err(ImportError::Json(whole)),
            Err(e) => return Err(json_error(format_args!("JSONL line {}: {e}", i + 1))),
        }
    }
    if events.is_empty() {
        return Err(ImportError::Json(whole));
    }
    Ok(events)
}

/// The case of root-span `event`, with the scorer spans of its trace.
fn read_event(
    label: &str,
    event: &J,
    children: &[(&str, &J)],
    meta: &ImportMeta,
    rules: &ScoreRules,
) -> Result<CaseResult, Vec<String>> {
    let at = |e: String| vec![format!("{label}: {e}")];
    let get = |key: &str| event.get(key).map_err(at);

    // ── Identity ──
    let mut issues = Vec::new();
    let metadata = match get("metadata")? {
        None => None,
        Some(m @ J::Obj(_)) => Some(m),
        Some(other) => return Err(at(format!("metadata: expected an object, found {}", other.kind()))),
    };
    let meta_get = |key: &str| match metadata {
        Some(m) => m.get(key).map_err(|e| at(format!("metadata: {e}"))),
        None => Ok(None),
    };
    // The dataset record the row was run from: `origin` in current SDKs,
    // `dataset_record_id` in older ones.
    let origin = match get("origin")? {
        None => None,
        Some(o @ J::Obj(_)) => match o.get("object_type").map_err(|e| at(format!("origin: {e}")))? {
            Some(J::Str(kind)) if kind == "dataset" => Some(o),
            _ => None,
        },
        Some(other) => return Err(at(format!("origin: expected an object, found {}", other.kind()))),
    };
    let origin_id = match origin {
        Some(o) => match o.get("id").map_err(|e| at(format!("origin: {e}")))? {
            None => Some(&J::Null),
            some => some,
        },
        None => None,
    };
    let candidates = [
        ("metadata.cloakpipe_case_id", meta_get("cloakpipe_case_id")?),
        ("metadata.case_id", meta_get("case_id")?),
        ("origin.id", origin_id),
        ("dataset_record_id", get("dataset_record_id")?),
    ];
    let Some((field, value)) = candidates.into_iter().find_map(|(f, v)| v.map(|v| (f, v))) else {
        return Err(at(
            "no stable case id: set metadata.cloakpipe_case_id or metadata.case_id, or run from a dataset \
             (origin.id of a dataset origin, or dataset_record_id); row ids differ between runs"
                .into(),
        ));
    };
    let id = match value {
        J::Str(s) if s.trim() != s => {
            return Err(at(format!("{field}: case id {s:?} has leading or trailing whitespace")));
        }
        J::Str(s) if !s.is_empty() => s.clone(),
        other => return Err(at(format!("{field}: expected a non-empty string, found {}", describe(other)))),
    };
    let mut scores = CaseScores::new(format!("{label} (case {id:?})"), rules);

    // ── Critical ──
    let critical_flag = match metadata.map(|m| has_key(m, "critical")) {
        Some(true) => match meta_get("critical")? {
            Some(J::Bool(b)) => *b,
            other => {
                let found = other.map_or("null", J::kind);
                issues.push(scores.issue(format_args!("metadata.critical: expected true or false, found {found}")));
                false
            }
        },
        _ => false,
    };
    let critical = critical_flag || meta.is_critical(&id);

    // ── Boundary label ──
    let expect = metadata_expect(metadata).unwrap_or_else(|e| {
        issues.push(scores.issue(format_args!("{e}")));
        None
    });

    // ── Error ──
    // A scorer that raised logs no score: the SDK records it only in
    // `metadata.scorer_errors`. Missing evidence fails the case closed.
    let mut error =
        get("error")?.is_some_and(|e| !e.is_empty()) || meta_get("scorer_errors")?.is_some_and(|e| !e.is_empty());

    // ── Scores ──
    // Scorer spans first: current SDKs log each scorer's result there.
    let mut child_scores: BTreeMap<&str, f64> = BTreeMap::new();
    for (child_label, child) in children {
        let problem = |what: String| scores.issue(format_args!("scorer span {child_label}: {what}"));
        match child.get("error") {
            Ok(e) => error |= e.is_some_and(|e| !e.is_empty()),
            Err(e) => issues.push(problem(e)),
        }
        match child.get("scores") {
            Ok(None) => {}
            Ok(Some(J::Obj(entries))) => {
                for (name, value) in entries {
                    if !scores.counts(name) {
                        continue;
                    }
                    match value {
                        J::Null => {}
                        J::Num(v) => {
                            if child_scores.insert(name, *v).is_some() {
                                issues.push(scores.issue(format_args!("score {name:?} given more than once")));
                            }
                        }
                        other => issues.push(problem(format!(
                            "score {name:?}: expected a number or null, found {}",
                            other.kind()
                        ))),
                    }
                }
            }
            Ok(Some(other)) => issues.push(problem(format!("scores: expected an object, found {}", other.kind()))),
            Err(e) => issues.push(problem(e)),
        }
    }
    match get("scores")? {
        None => {}
        Some(J::Obj(entries)) => {
            for (name, value) in entries {
                if !scores.counts(name) {
                    continue;
                }
                // The same value on the root and its scorer span counts once.
                if let Some(child) = child_scores.get(name.as_str()) {
                    match value {
                        J::Null => continue,
                        J::Num(v) if v == child => continue,
                        _ => {}
                    }
                    issues.push(scores.issue(format_args!(
                        "score {name:?}: the root span and its scorer span disagree ({} vs {child})",
                        describe(value)
                    )));
                    continue;
                }
                if !scores.name(name, &mut issues) {
                    continue;
                }
                match value {
                    J::Null => {}
                    J::Num(v) => scores.value(name, *v, &mut issues),
                    other => issues.push(
                        scores.issue(format_args!("score {name:?}: expected a number or null, found {}", other.kind())),
                    ),
                }
            }
        }
        Some(other) => issues.push(scores.issue(format_args!("scores: expected an object, found {}", other.kind()))),
    }
    for (name, v) in child_scores {
        if scores.name(name, &mut issues) {
            scores.value(name, v, &mut issues);
        }
    }

    // ── Metrics ──
    let mut metrics = BTreeMap::new();
    let mut duration_ms = None;
    match get("metrics")? {
        None => {}
        Some(m @ J::Obj(_)) => {
            let num = |key: &str| match m.get(key) {
                Ok(Some(J::Num(v))) => Ok(Some(*v)),
                Ok(_) => Ok(None),
                Err(e) => Err(scores.issue(format_args!("metrics: {e}"))),
            };
            match (num("start"), num("end")) {
                (Ok(Some(start)), Ok(Some(end))) if end >= start => duration_ms = secs_to_ms(end - start),
                (Err(e), _) | (_, Err(e)) => issues.push(e),
                _ => {}
            }
            for (key, metric) in [
                ("prompt_tokens", "tokens.prompt"),
                ("completion_tokens", "tokens.completion"),
                ("tokens", "tokens.total"),
            ] {
                match num(key) {
                    Ok(Some(v)) => {
                        metrics.insert(metric.to_string(), v);
                    }
                    Ok(None) => {}
                    Err(e) => issues.push(e),
                }
            }
        }
        Some(other) => issues.push(scores.issue(format_args!("metrics: expected an object, found {}", other.kind()))),
    }

    if !issues.is_empty() {
        return Err(issues);
    }
    Ok(CaseResult { expect, ..scores.into_case(id, critical, error, rules, metrics, duration_ms) })
}

fn describe(v: &J) -> String {
    match v {
        J::Str(s) => format!("{s:?}"),
        J::Num(n) => n.to_string(),
        other => other.kind().to_string(),
    }
}
