//! Langfuse experiment + experiment items → [`EvaluationRun`] (contract in
//! the `import` module docs).
//!
//! Inputs are Langfuse v4 public API responses: one experiment from
//! `GET /api/public/experiments` and every page of its items from
//! `GET /api/public/experiment-items?fields=core,dataset,scores`, whose
//! `scores` are the item's own and its trace's scores (`ScoreV3`).

use super::scores::{metadata_expect, CaseScores, ScoreRules, J};
use super::{build_run, ImportError, ImportMeta};
use crate::model::{CaseResult, EvaluationRun, Expect, SourceKind};
use std::collections::{BTreeMap, BTreeSet};

/// Langfuse's maximum (and default) `scoreLimit`: an item listing this many
/// scores may have had more cut off.
const SCORE_LIMIT: usize = 50;

/// The experiment the items must belong to.
struct Experiment {
    id: String,
    item_count: u64,
    dataset_id: Option<String>,
}

/// Import a Langfuse experiment and its items (with their scores) as an
/// [`EvaluationRun`] (see the `import` module docs).
pub fn from_langfuse_experiment(
    experiment_json: &str,
    items_json: &str,
    meta: &ImportMeta,
    rules: &ScoreRules,
) -> Result<EvaluationRun, ImportError> {
    let experiment_doc = J::parse(experiment_json)?;
    let items_doc = J::parse(items_json)?;
    let mut issues = rules.issues();

    let experiment = read_experiment(&experiment_doc).map_err(|e| ImportError::Invalid(vec![e]))?;
    let items = item_objects(&items_doc, &mut issues);

    if items.len() as u64 != experiment.item_count {
        issues.push(format!(
            "experiment items are incomplete or from another fetch: the experiment's itemCount is {} but {} \
             item(s) were given; fetch the experiment and every page of its items with the same \
             fromStartTime/toStartTime",
            experiment.item_count,
            items.len()
        ));
    }
    if !items.is_empty() && items.iter().all(|(_, item)| matches!(item, J::Obj(e) if !e.iter().any(|(k, _)| k == "scores")))
    {
        issues.push(
            "no experiment item has `scores`: fetch the items with fields=core,dataset,scores (scores are \
             only returned when requested)"
                .into(),
        );
    }

    let mut seen = BTreeSet::new();
    let mut cases = Vec::with_capacity(items.len());
    for (label, item) in items {
        let Some((case_id, error, expect, scores)) = read_item(&label, item, &experiment.id, &mut issues) else {
            continue;
        };
        if !seen.insert(case_id.clone()) {
            issues.push(format!(
                "{label}: experimentItemId {case_id:?} appears more than once (repeated pages, or a \
                 repetition Langfuse does not support)"
            ));
            continue;
        }
        let mut case = CaseScores::new(format!("case {case_id:?}"), rules);
        if scores.len() >= SCORE_LIMIT {
            issues.push(case.issue(format_args!(
                "{} scores listed, the maximum scoreLimit ({SCORE_LIMIT}): more may have been cut off",
                scores.len()
            )));
        }
        for (i, score) in scores.iter().enumerate() {
            if let Err(e) = read_score(score, &mut case, &mut issues) {
                issues.push(case.issue(format_args!("{label}.scores[{i}]: {e}")));
            }
        }
        let critical = meta.is_critical(&case_id);
        cases.push(CaseResult { expect, ..case.into_case(case_id, critical, error, rules, BTreeMap::new(), None) });
    }

    let dataset = meta.dataset.clone().or(experiment.dataset_id);
    build_run(meta, SourceKind::Langfuse, dataset, cases, issues)
}

/// A non-empty string field of `obj`.
fn non_empty(obj: &J, key: &str) -> Result<String, String> {
    match obj.get(key)? {
        Some(J::Str(s)) if !s.trim().is_empty() => Ok(s.clone()),
        other => Err(format!("{key}: expected a non-empty string, found {}", other.map_or("null", describe))),
    }
}

fn describe(v: &J) -> &'static str {
    match v {
        J::Str(_) => "an empty string",
        other => other.kind(),
    }
}

/// The experiment: an `ExperimentsResponse` page holding exactly one
/// experiment, or the bare experiment object.
fn read_experiment(doc: &J) -> Result<Experiment, String> {
    let exp = match doc {
        J::Obj(entries) if entries.iter().any(|(k, _)| k == "data") => match doc.get("data")? {
            Some(J::Arr(list)) => match list.as_slice() {
                [one] => one,
                [] => return Err("experiment: the page holds no experiment; filter by id=<experiment id>".into()),
                many => {
                    return Err(format!(
                        "experiment: the page holds {} experiments; filter by id=<experiment id>",
                        many.len()
                    ))
                }
            },
            other => {
                return Err(format!("experiment.data: expected an array, found {}", other.map_or("null", J::kind)))
            }
        },
        J::Obj(_) => doc,
        other => return Err(format!("experiment: expected an experiment or a page of experiments, found {}", other.kind())),
    };
    if !matches!(exp, J::Obj(_)) {
        return Err(format!("experiment: expected an object, found {}", exp.kind()));
    }
    let id = non_empty(exp, "id").map_err(|e| format!("experiment.{e}"))?;
    let item_count = match exp.get("itemCount").map_err(|e| format!("experiment: {e}"))? {
        Some(J::Num(n)) if n.fract() == 0.0 && *n >= 0.0 && *n <= 1e15 => *n as u64,
        other => {
            return Err(format!(
                "experiment.itemCount: expected a whole number, found {}",
                other.map_or("null".to_string(), |v| match v {
                    J::Num(n) => n.to_string(),
                    v => v.kind().to_string(),
                })
            ))
        }
    };
    let dataset_id = match exp.get("datasetId").map_err(|e| format!("experiment: {e}"))? {
        None => None,
        Some(J::Str(s)) if s.trim().is_empty() => None,
        Some(J::Str(s)) => Some(s.clone()),
        Some(other) => return Err(format!("experiment.datasetId: expected a string or null, found {}", other.kind())),
    };
    Ok(Experiment { id, item_count, dataset_id })
}

/// Every item of an `ExperimentItemsResponse` page, or of an array of pages
/// in fetch order, each with a label naming it in issues. A page's
/// non-empty `meta.cursor` means a next page exists: every page but the
/// last must have one (all distinct), and the last must not.
fn item_objects<'a>(doc: &'a J, issues: &mut Vec<String>) -> Vec<(String, &'a J)> {
    let pages: Vec<(String, &J)> = match doc {
        J::Obj(_) => vec![("items".into(), doc)],
        J::Arr(pages) => pages.iter().enumerate().map(|(i, p)| (format!("items[{i}]"), p)).collect(),
        other => {
            issues.push(format!("items: expected a page of experiment items or an array of pages, found {}", other.kind()));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    let mut cursors = BTreeMap::new();
    let last = pages.len().saturating_sub(1);
    for (n, (label, page)) in pages.into_iter().enumerate() {
        let entries = match page {
            J::Obj(entries) => entries,
            other => {
                issues.push(format!("{label}: expected a page {{\"data\": [...], \"meta\": {{...}}}}, found {}", other.kind()));
                continue;
            }
        };
        if !entries.iter().any(|(k, _)| k == "data") {
            issues.push(format!(
                "{label}: expected a page {{\"data\": [...], \"meta\": {{...}}}}; pass whole API responses, not \
                 bare items"
            ));
            continue;
        }
        match page.get("data") {
            Ok(Some(J::Arr(items))) => out.extend(items.iter().enumerate().map(|(i, it)| (format!("{label}.data[{i}]"), it))),
            Ok(other) => issues.push(format!("{label}.data: expected an array, found {}", other.map_or("null", J::kind))),
            Err(e) => issues.push(format!("{label}: {e}")),
        }
        let cursor = match page.get("meta") {
            Ok(Some(meta @ J::Obj(_))) => match meta.get("cursor") {
                Ok(None) => None,
                Ok(Some(J::Str(c))) if c.is_empty() => None,
                Ok(Some(J::Str(c))) => Some(c.as_str()),
                Ok(Some(other)) => {
                    issues.push(format!("{label}.meta.cursor: expected a string or null, found {}", other.kind()));
                    continue;
                }
                Err(e) => {
                    issues.push(format!("{label}.meta: {e}"));
                    continue;
                }
            },
            Ok(other) => {
                issues.push(format!(
                    "{label}.meta: expected an object, found {}; without it, it is unknown whether more pages exist",
                    other.map_or("nothing", J::kind)
                ));
                continue;
            }
            Err(e) => {
                issues.push(format!("{label}: {e}"));
                continue;
            }
        };
        match (n == last, cursor) {
            (true, Some(_)) => issues.push(format!(
                "experiment items are incomplete: the last page ({label}) has meta.cursor, so more pages exist; \
                 fetch them with cursor=<meta.cursor> and pass every page"
            )),
            (false, None) => issues.push(format!(
                "{label}: no meta.cursor, yet more pages follow; pass the pages of one fetch, in order"
            )),
            (_, Some(c)) => {
                if let Some(first) = cursors.insert(c, label.clone()) {
                    issues.push(format!("{label}: meta.cursor repeats {first}'s (a page given twice?)"));
                }
            }
            (true, None) => {}
        }
    }
    out
}

/// An item's case id, whether it is an error, its boundary label
/// (`metadata["cloakpipe.expect"]`) and its scores; `None` (with an issue)
/// if it cannot be read.
type Item<'a> = (String, bool, Option<Expect>, &'a [J]);

fn read_item<'a>(label: &str, item: &'a J, experiment_id: &str, issues: &mut Vec<String>) -> Option<Item<'a>> {
    let read = || -> Result<Item<'a>, String> {
        if !matches!(item, J::Obj(_)) {
            return Err(format!("expected an experiment item object, found {}", item.kind()));
        }
        let case_id = non_empty(item, "experimentItemId")?;
        if case_id.trim() != case_id {
            return Err(format!("experimentItemId: case id {case_id:?} has leading or trailing whitespace"));
        }
        non_empty(item, "traceId")?;
        let exp = non_empty(item, "experimentId")?;
        if exp != experiment_id {
            return Err(format!(
                "experimentId {exp:?} is not the experiment's id {experiment_id:?}; the files are from different \
                 experiments"
            ));
        }
        let error = match item.get("level")? {
            None => false,
            Some(J::Str(level)) => level == "ERROR",
            Some(other) => return Err(format!("level: expected a string, found {}", other.kind())),
        };
        let scores: &[J] = match item.get("scores")? {
            None => &[],
            Some(J::Arr(scores)) => scores,
            Some(other) => return Err(format!("scores: expected an array or null, found {}", other.kind())),
        };
        let expect = metadata_expect(item.get("metadata")?)?;
        Ok((case_id, error, expect, scores))
    };
    read().map_err(|e| issues.push(format!("{label}: {e}"))).ok()
}

/// Record one `ScoreV3` on `case`; `Err` describes a problem with it.
fn read_score(score: &J, case: &mut CaseScores, issues: &mut Vec<String>) -> Result<(), String> {
    if !matches!(score, J::Obj(_)) {
        return Err(format!("expected a score object, found {}", score.kind()));
    }
    let data_type = match score.get("dataType")? {
        Some(J::Str(t)) => t.as_str(),
        other => return Err(format!("dataType: expected a string, found {}", other.map_or("null", J::kind))),
    };
    // Not numeric: categorical labels, free text, corrections.
    if matches!(data_type, "CATEGORICAL" | "TEXT" | "CORRECTION") {
        return Ok(());
    }
    let name = match score.get("name")? {
        Some(J::Str(name)) if !name.is_empty() => name,
        other => return Err(format!("name: expected a non-empty string, found {}", other.map_or("null", describe))),
    };
    if !case.counts(name) {
        return Ok(());
    }
    let value = match (data_type, score.get("value")?) {
        ("NUMERIC", Some(J::Num(v))) => *v,
        ("BOOLEAN", Some(J::Bool(b))) => f64::from(u8::from(*b)),
        ("NUMERIC", other) => {
            return Err(format!("score {name:?}: value: expected a number, found {}", other.map_or("null", J::kind)))
        }
        ("BOOLEAN", other) => {
            return Err(format!("score {name:?}: value: expected a bool, found {}", other.map_or("null", J::kind)))
        }
        (other, _) => return Err(format!("score {name:?}: unsupported dataType {other:?}")),
    };
    if case.name(name, issues) {
        case.value(name, value, issues);
    }
    Ok(())
}
