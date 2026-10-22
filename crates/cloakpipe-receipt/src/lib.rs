//! Signed receipts for AI-agent tool calls.
//!
//! - [`dsse`]: DSSE envelopes over in-toto Statements (Ed25519 over the PAE
//!   of the RFC 8785 statement bytes), checked offline against trusted keys.
//! - [`approval`]: approval receipts, a trusted approver's signature over
//!   one exact tool call (its fingerprint), verified offline by the gate.
//!
//! This crate has no dependency on release certification: the gate's
//! runtime path needs only these primitives.

pub mod approval;
pub mod dsse;
