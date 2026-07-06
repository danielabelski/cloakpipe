//! Manual smoke test for the Nemotron-v2 PII backend against REAL downloaded
//! weights (not run in CI — the model is ~2GB and not vendored).
//!
//! Fetch the model first (q8 ONNX + tokenizer + config), then:
//!   cargo run --manifest-path crates/cloakpipe-core/Cargo.toml \
//!     --features ner --example nemotron_smoke -- /path/to/nemotron-dir
//!
//! Verifies the full wired path (DetectionConfig -> Detector::from_config ->
//! nemotron_pii -> regex-first dedup in Detector::detect), not just the
//! isolated module — proving the model actually loads and infers correctly
//! through cloakpipe's real detection pipeline.

use cloakpipe_core::config::{DetectionConfig, NerBackend};
use cloakpipe_core::detector::Detector;

fn main() -> anyhow::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: nemotron_smoke <path-to-nemotron-model-dir>");
    let model_path = format!("{dir}/model_quantized.onnx");

    let mut config: DetectionConfig = serde_json::from_str("{}")?;
    config.ner.enabled = true;
    config.ner.backend = NerBackend::NemotronPii;
    config.ner.model = Some(model_path.clone());
    config.ner.confidence_threshold = 0.5;

    println!("Loading Nemotron-v2 PII from {model_path} ...");
    let t0 = std::time::Instant::now();
    let detector = Detector::from_config(&config)?;
    println!("Loaded in {:.1}s\n", t0.elapsed().as_secs_f64());

    let samples = [
        "Patient Maria Gonzalez (DOB 03/14/1972, MRN 88213904) was admitted; SSN 501-22-8847.",
        "Wire $18,500 to Daniel Foster, card 4539 1488 0343 6467, routing 021000021.",
        "Set OPENAI_API_KEY=sk-proj-abc123DEF456ghi789 from host 10.4.22.19 by devops@acme.io.",
        "Customer Priya Nair called from +44 7911 123456 about a double charge.",
    ];

    for text in samples {
        let t0 = std::time::Instant::now();
        let entities = detector.detect(text)?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        println!("TEXT: {text}");
        println!("  ({ms:.1}ms, {} entities)", entities.len());
        for e in &entities {
            println!(
                "    {:?}\t{:?}\tconf={:.2}\tsrc={:?}",
                e.category, e.original, e.confidence, e.source
            );
        }
        println!();
    }

    Ok(())
}
