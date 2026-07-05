//! Shared application state for the proxy server.

use cloakpipe_audit::AuditLogger;
use cloakpipe_core::{
    config::{CloakPipeConfig, CloudConfig},
    detector::Detector,
    session::SessionManager,
    vault::Vault,
};
use std::sync::Arc;
use tokio::sync::Mutex;

/// A single request's telemetry, buffered for periodic flush to CloakPipe Cloud.
/// No raw prompt/PII — only counts, timing and the upstream model/provider.
#[derive(Clone)]
pub struct TelemetryEvent {
    pub request_id: String,
    pub timestamp: String,
    pub entities_masked: i64,
    pub latency_ms: f64,
    pub upstream_provider: String,
    pub upstream_model: String,
    pub status: String,
}

/// Shared state accessible from all request handlers.
pub struct AppState {
    pub config: CloakPipeConfig,
    pub detector: Detector,
    pub vault: Arc<Mutex<Vault>>,
    pub audit: AuditLogger,
    pub http_client: reqwest::Client,
    pub api_key: String,
    pub sessions: Arc<SessionManager>,
    /// Resolved CloakPipe Cloud config (`None` → cloud reporting off).
    pub cloud: Option<CloudConfig>,
    /// Buffer of per-request telemetry, drained by the flush loop (see CLI).
    pub telemetry: Arc<Mutex<Vec<TelemetryEvent>>>,
}

impl AppState {
    pub fn new(
        config: CloakPipeConfig,
        detector: Detector,
        vault: Vault,
        audit: AuditLogger,
        api_key: String,
    ) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.proxy.timeout_seconds))
            .build()
            .expect("Failed to build HTTP client");

        let sessions = Arc::new(SessionManager::new(config.session.clone()));
        let cloud = CloudConfig::resolve(&config.cloud);

        Self {
            config,
            detector,
            vault: Arc::new(Mutex::new(vault)),
            audit,
            http_client,
            api_key,
            sessions,
            cloud,
            telemetry: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
