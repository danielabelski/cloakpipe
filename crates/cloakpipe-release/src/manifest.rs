//! Manifest types and parsing.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The `apiVersion` writers emit; readers also accept
/// [`crate::namespace::LEGACY_API_VERSION`].
pub const API_VERSION: &str = crate::namespace::API_VERSION;
pub const KIND: &str = "AgentRelease";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("invalid JSON manifest: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid YAML manifest: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRelease {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}

/// `version` and `labels` are human bookkeeping and are excluded from the
/// manifest hash; `agent` is part of the identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Metadata {
    pub agent: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// `code`, `prompts`, `model` and `runtime` pin the release for
/// certification ([`AgentRelease::validate`]). The tool gate does not need
/// them ([`AgentRelease::gate_issues`]), so they may be left out; an omitted
/// field reads as empty, which `validate` reports.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Spec {
    #[serde(default)]
    pub code: Code,
    /// Ordered: prompt composition order is semantic.
    #[serde(default)]
    pub prompts: Vec<ArtifactRef>,
    #[serde(default)]
    pub model: ArtifactRef,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
    #[serde(default)]
    pub tools: Vec<ArtifactRef>,
    #[serde(default)]
    pub mcp_servers: Vec<ArtifactRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval: Option<ArtifactRef>,
    #[serde(default)]
    pub policies: Vec<ArtifactRef>,
    #[serde(default)]
    pub runtime: Runtime,
    #[serde(default)]
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub feature_flags: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub repository: String,
    pub commit: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub image: String,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dependency {
    pub name: String,
    pub version: String,
}

pub fn parse_str(src: &str, format: Format) -> Result<AgentRelease, ParseError> {
    Ok(match format {
        Format::Json => serde_json::from_str(src)?,
        Format::Yaml => serde_yaml::from_str(src)?,
    })
}

/// Parse a manifest file; `.json` is JSON, anything else is YAML (a superset).
pub fn parse_path(path: &Path) -> Result<AgentRelease, ParseError> {
    let src = std::fs::read_to_string(path)
        .map_err(|e| ParseError::Io(path.display().to_string(), e))?;
    let format = match path.extension().and_then(|e| e.to_str()) {
        Some("json") => Format::Json,
        _ => Format::Yaml,
    };
    parse_str(&src, format)
}
