//! Agent Release manifests.
//!
//! An Agent Release is the complete, immutable set of behaviour-affecting
//! components deployed as one unit: code, prompts, model, parameters, tools,
//! MCP servers, retrieval, policies, runtime and dependencies. This crate
//! parses and validates manifests, computes their canonical hash, and diffs two
//! releases to decide which assurance suites a change requires.

pub mod action;
mod canonical;
pub mod contract;
mod diff;
mod manifest;
pub mod namespace;
mod reference;
mod statement;
mod validate;

pub use canonical::{ReleaseHash, ReleaseHashParseError, HASH_DOMAIN};
pub use diff::{diff, Change, ChangeKind, Component, ReleaseDiff, Suite};
pub use manifest::{
    parse_path, parse_str, AgentRelease, ArtifactRef, Code, Dependency, Format, Metadata,
    ParseError, Runtime, Spec, API_VERSION, KIND,
};
pub use reference::{RefError, RefKind, Reference};
pub use statement::{PREDICATE_TYPE, STATEMENT_TYPE};
pub use validate::{Issue, IssueCode};
