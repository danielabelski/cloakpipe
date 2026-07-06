//! Nemotron-v2 PII detector — 1.4B param MoE token classifier, 55 fine-grained
//! PII categories, BIOES tagging. q8-quantized ONNX, ~2GB, CPU-runnable.
//!
//! Base: openai/privacy-filter, fine-tuned as OpenMed/privacy-filter-nemotron-v2,
//! ONNX conversion by nisten/privacy-filter-nemotron-v2-ONNX.
//!
//! Benchmarked (2026-07-06, real-world multi-domain sentences) vs cloakpipe's
//! regex layer and the openai/privacy-filter base: F1 0.92 (regex-only: 0.65;
//! openai base: 0.91), ~60ms/sentence on a 2-core CPU. It's complementary to
//! regex, not a replacement: it catches names/addresses/medical/financial PII
//! regex is blind to, but missed an API key and mis-split an IP address in
//! testing — cloakpipe's `PatternDetector` (confidence 1.0, always wins
//! overlap dedup — see `Detector::deduplicate_spans`) covers that gap.
//!
//! Model path: models/nemotron-pii/model_quantized.onnx
//! Tokenizer:  models/nemotron-pii/tokenizer.json
//! Labels:     models/nemotron-pii/config.json ("id2label", BIOES, 221 labels)

use crate::config::NerConfig;
use crate::{DetectedEntity, DetectionSource, EntityCategory};
use anyhow::Result;
use ort::session::Session;
use ort::value::Value;
use std::collections::HashMap;
use std::sync::Mutex;
use tokenizers::Tokenizer;
use tracing::{debug, info};

/// Map a BIOES base category (e.g. "first_name", "ssn") to a CloakPipe
/// EntityCategory. Unrecognized categories fall back to `Custom(UPPERCASE)`
/// so nothing is silently dropped even if the model's label set changes.
fn label_to_category(base: &str) -> EntityCategory {
    match base {
        "first_name" | "last_name" => EntityCategory::Person,
        "company_name" => EntityCategory::Organization,
        "city" | "state" | "county" | "country" | "postcode" | "street_address"
        | "coordinate" => EntityCategory::Location,
        "date" | "date_of_birth" | "date_time" | "time" => EntityCategory::Date,
        "email" => EntityCategory::Email,
        "phone_number" | "fax_number" => EntityCategory::PhoneNumber,
        "ipv4" | "ipv6" => EntityCategory::IpAddress,
        "url" => EntityCategory::Url,
        "password" | "pin" | "api_key" | "http_cookie" => EntityCategory::Secret,
        "ssn" => EntityCategory::Custom("SSN".into()),
        "credit_debit_card" | "cvv" => EntityCategory::Custom("CREDIT_CARD".into()),
        "account_number" | "bank_routing_number" | "swift_bic" => {
            EntityCategory::Custom("ACCOUNT_NUMBER".into())
        }
        "national_id" | "tax_id" | "employee_id" | "customer_id" | "unique_id" => {
            EntityCategory::Custom("ID_NUMBER".into())
        }
        "certificate_license_number" | "license_plate" => {
            EntityCategory::Custom("LICENSE_NUMBER".into())
        }
        "device_identifier" | "mac_address" | "vehicle_identifier" => {
            EntityCategory::Custom("DEVICE_ID".into())
        }
        "medical_record_number" | "health_plan_beneficiary_number" => {
            EntityCategory::Custom("MEDICAL_RECORD".into())
        }
        other => EntityCategory::Custom(other.to_uppercase()),
    }
}

/// Whether two base categories should be treated as the same entity for span
/// merging (e.g. first_name + last_name both merge into one Person span).
fn same_entity_group(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    matches!((a, b), ("first_name", "last_name") | ("last_name", "first_name"))
}

pub struct NemotronPiiDetector {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    id2label: HashMap<usize, String>,
    confidence_threshold: f64,
}

impl NemotronPiiDetector {
    pub fn new(config: &NerConfig) -> Result<Self> {
        let model_path = config
            .model
            .as_deref()
            .unwrap_or("models/nemotron-pii/model_quantized.onnx");

        info!("Loading Nemotron-v2 PII model from: {}", model_path);

        let session = Session::builder()
            .map_err(|e| anyhow::anyhow!("Failed to create session builder: {e}"))?
            .with_intra_threads(2)
            .map_err(|e| anyhow::anyhow!("Failed to set threads: {e}"))?
            .commit_from_file(model_path)
            .map_err(|e| anyhow::anyhow!("Failed to load Nemotron-v2 PII model '{model_path}': {e}"))?;

        let model_dir = std::path::Path::new(model_path)
            .parent()
            .unwrap_or(std::path::Path::new("."));
        let find_sibling = |name: &str| -> std::path::PathBuf {
            let here = model_dir.join(name);
            if here.exists() {
                here
            } else {
                model_dir
                    .parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(name)
            }
        };

        let tokenizer_path = find_sibling("tokenizer.json");
        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer from {tokenizer_path:?}: {e}"))?;

        let config_path = find_sibling("config.json");
        let id2label = load_id2label(&config_path)?;

        info!(
            "Nemotron-v2 PII loaded: {} labels, threshold={:.2}",
            id2label.len(),
            config.confidence_threshold
        );

        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            id2label,
            confidence_threshold: config.confidence_threshold,
        })
    }

    pub fn detect(&self, text: &str) -> Result<Vec<DetectedEntity>> {
        if text.is_empty() {
            return Ok(Vec::new());
        }

        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenization failed: {e}"))?;

        let input_ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let seq_len = input_ids.len();
        let ones = vec![1i64; seq_len];
        let zeros = vec![0i64; seq_len];

        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("Nemotron-v2 PII session lock poisoned"))?;

        // Feed every declared input by name — the exact input set (input_ids /
        // attention_mask / token_type_ids) varies by export; matching on
        // substrings keeps this robust to that instead of hardcoding 2 or 3.
        let input_names: Vec<String> = session.inputs().iter().map(|o| o.name().to_string()).collect();
        let mut inputs: Vec<(std::borrow::Cow<'static, str>, Value)> = Vec::with_capacity(input_names.len());
        for name in &input_names {
            let data = if name.contains("attention") {
                ones.clone()
            } else if name.contains("token_type") {
                zeros.clone()
            } else {
                input_ids.clone()
            };
            let tensor = Value::from_array(([1i64, seq_len as i64], data))
                .map_err(|e| anyhow::anyhow!("{name} tensor: {e}"))?;
            inputs.push((name.clone().into(), tensor.into_dyn()));
        }

        let outputs = session
            .run(inputs)
            .map_err(|e| anyhow::anyhow!("Nemotron-v2 PII inference failed: {e}"))?;

        let (_shape, logits_data) = outputs[0]
            .try_extract_tensor::<f32>()
            .map_err(|e| anyhow::anyhow!("Failed to extract logits: {e}"))?;

        let num_labels = self.id2label.len();
        let offsets = encoding.get_offsets();

        let mut entities = Vec::new();
        let mut current: Option<(String, usize, usize, f64, String)> = None; // (text, start, end, conf, base_category)

        for (i, &(off_start, off_end)) in offsets.iter().enumerate() {
            // Special tokens (CLS/SEP/BOS/EOS-equivalents) carry a (0,0) offset
            // regardless of tokenizer family — more robust than matching token
            // strings, since Nemotron's o200k tokenizer isn't BERT-style.
            if off_start == 0 && off_end == 0 {
                current = flush(current, &mut entities, text);
                continue;
            }

            let logit_off = i * num_labels;
            if logit_off + num_labels > logits_data.len() {
                break;
            }
            let (pred_idx, confidence) = softmax_argmax(&logits_data[logit_off..logit_off + num_labels]);
            let label = self.id2label.get(&pred_idx).map(String::as_str).unwrap_or("O");

            if (confidence as f64) < self.confidence_threshold || label == "O" {
                current = flush(current, &mut entities, text);
                continue;
            }

            let (prefix, base) = match label.split_once('-') {
                Some((p, b)) => (p, b),
                None => {
                    current = flush(current, &mut entities, text);
                    continue;
                }
            };

            match prefix {
                "S" => {
                    flush(current, &mut entities, text);
                    let span = Some((text[off_start..off_end].to_string(), off_start, off_end, confidence as f64, base.to_string()));
                    current = flush(span, &mut entities, text);
                }
                "B" => {
                    flush(current, &mut entities, text);
                    current = Some((text[off_start..off_end].to_string(), off_start, off_end, confidence as f64, base.to_string()));
                }
                "I" | "E" => {
                    let extend = match &current {
                        Some((_, _, _, _, cur_base)) => same_entity_group(cur_base, base),
                        None => false,
                    };
                    if extend {
                        if let Some((ref mut val, _s, ref mut end, ref mut conf, _)) = current {
                            let piece = &text[*end..off_end];
                            val.push_str(piece);
                            *end = off_end;
                            *conf = (*conf + confidence as f64) / 2.0;
                        }
                    } else {
                        flush(current, &mut entities, text);
                        current = Some((text[off_start..off_end].to_string(), off_start, off_end, confidence as f64, base.to_string()));
                    }
                    if prefix == "E" {
                        current = flush(current, &mut entities, text);
                    }
                }
                _ => {
                    current = flush(current, &mut entities, text);
                }
            }
        }
        flush(current, &mut entities, text);

        entities = merge_person_entities(entities);

        debug!("Nemotron-v2 PII detected {} entities", entities.len());
        Ok(entities)
    }
}

fn flush(
    current: Option<(String, usize, usize, f64, String)>,
    entities: &mut Vec<DetectedEntity>,
    _text: &str,
) -> Option<(String, usize, usize, f64, String)> {
    if let Some((val, start, end, confidence, base)) = current {
        let trimmed = val.trim();
        if !trimmed.is_empty() && start < end {
            entities.push(DetectedEntity {
                original: trimmed.to_string(),
                start,
                end,
                category: label_to_category(&base),
                confidence,
                source: DetectionSource::Ner,
            });
        }
    }
    None
}

/// Merge adjacent Person entities (first_name + last_name) into full names,
/// mirroring cloakpipe's DistilBERT-PII behavior for the same case.
fn merge_person_entities(entities: Vec<DetectedEntity>) -> Vec<DetectedEntity> {
    let mut merged: Vec<DetectedEntity> = Vec::with_capacity(entities.len());
    for entity in entities {
        if entity.category == EntityCategory::Person {
            if let Some(last) = merged.last_mut() {
                if last.category == EntityCategory::Person {
                    let gap = entity.start.saturating_sub(last.end);
                    if gap <= 2 {
                        last.original = format!("{} {}", last.original.trim(), entity.original.trim());
                        last.end = entity.end;
                        last.confidence = (last.confidence + entity.confidence) / 2.0;
                        continue;
                    }
                }
            }
        }
        merged.push(entity);
    }
    merged
}

fn load_id2label(config_path: &std::path::Path) -> Result<HashMap<usize, String>> {
    let raw = std::fs::read_to_string(config_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {config_path:?}: {e}"))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("Failed to parse {config_path:?}: {e}"))?;
    let map = json
        .get("id2label")
        .and_then(|v| v.as_object())
        .ok_or_else(|| anyhow::anyhow!("{config_path:?} has no \"id2label\" object"))?;
    let mut out = HashMap::with_capacity(map.len());
    for (k, v) in map {
        let id: usize = k
            .parse()
            .map_err(|_| anyhow::anyhow!("non-numeric id2label key {k:?} in {config_path:?}"))?;
        let label = v
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("non-string id2label value for {k:?} in {config_path:?}"))?
            .to_string();
        out.insert(id, label);
    }
    Ok(out)
}

fn softmax_argmax(logits: &[f32]) -> (usize, f32) {
    let max_val = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let exp_sum: f32 = logits.iter().map(|&x| (x - max_val).exp()).sum();

    let mut best_idx = 0;
    let mut best_prob = 0.0f32;
    for (i, &logit) in logits.iter().enumerate() {
        let prob = (logit - max_val).exp() / exp_sum;
        if prob > best_prob {
            best_prob = prob;
            best_idx = i;
        }
    }
    (best_idx, best_prob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_to_category() {
        assert_eq!(label_to_category("first_name"), EntityCategory::Person);
        assert_eq!(label_to_category("last_name"), EntityCategory::Person);
        assert_eq!(label_to_category("email"), EntityCategory::Email);
        assert_eq!(label_to_category("ssn"), EntityCategory::Custom("SSN".into()));
        assert_eq!(label_to_category("credit_debit_card"), EntityCategory::Custom("CREDIT_CARD".into()));
        assert_eq!(label_to_category("city"), EntityCategory::Location);
        assert_eq!(label_to_category("phone_number"), EntityCategory::PhoneNumber);
        assert_eq!(label_to_category("company_name"), EntityCategory::Organization);
        assert_eq!(label_to_category("api_key"), EntityCategory::Secret);
        // Unmapped category still gets through as Custom, never silently dropped.
        assert_eq!(label_to_category("political_view"), EntityCategory::Custom("POLITICAL_VIEW".into()));
    }

    #[test]
    fn test_same_entity_group() {
        assert!(same_entity_group("first_name", "last_name"));
        assert!(same_entity_group("email", "email"));
        assert!(!same_entity_group("email", "ssn"));
    }

    #[test]
    fn test_load_id2label() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"id2label": {"0": "O", "1": "B-email", "2": "I-email"}}"#).unwrap();
        let map = load_id2label(&path).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&1).unwrap(), "B-email");
    }
}
