//! Shared test fixtures. Each integration test compiles this module and
//! uses only part of it.
//!
//! - `anchoring`: deterministic bundles for the external-anchoring tests.
//! - `pack`: release audit pack fixtures built with the producer crates.
#![allow(dead_code, unused_imports)]

pub mod anchoring;
#[cfg(feature = "release-pack")]
pub mod pack;

pub use anchoring::*;
#[cfg(feature = "release-pack")]
pub use pack::*;
