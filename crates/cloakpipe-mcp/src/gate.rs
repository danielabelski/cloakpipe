//! Runtime tool gate (Phase C): may this Agent Release call this tool now?
//!
//! The MCP interceptor asks [`ToolGate::check`] before forwarding each
//! `tools/call`. A call is allowed only when
//!
//! 1. the tool is declared in the release manifest (`spec.tools`, by name:
//!    `tool:refund@4` declares `refund`), and
//! 2. the release holds a certification that verifies offline *now*
//!    ([`cloakpipe_cert::statement::verify`]: trusted signer, not revoked,
//!    inside its validity window, about this release, `certified` decision)
//!    for the gate's environment.
//!
//! Without a certification every call is refused: the gate fails closed.
//! `warn` mode reports the same verdicts but lets calls through.
//!
//! A release can also bind tool contracts (`policy:tool-contract/...` in
//! `spec.policies`, see [`cloakpipe_release::contract`]). The gate is then
//! given the contracts and the trusted task context with
//! [`ToolGate::with_contracts`], which refuses a contract the release does
//! not bind and a bound contract that was not supplied. For a tool a
//! contract covers, [`ToolGate::check`] also validates the call's raw
//! (pre-masking) arguments. Declared tools no contract covers keep the
//! behaviour above.

use cloakpipe_cert::statement::{verify, Envelope, Status, VerifyContext};
use cloakpipe_release::contract::{self, ToolContract, ViolationCode};
use cloakpipe_release::{AgentRelease, Reference};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Refuse calls that fail the gate.
    Enforce,
    /// Forward them, but report the violation.
    Warn,
}

/// Why a call fails the gate. `code()` is stable and safe to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The manifest does not declare this tool.
    UndeclaredTool,
    /// No certification was supplied.
    Uncertified,
    /// The certification does not certify the release now; carries the
    /// verification status (`expired`, `revoked`, `invalid`, ...) or
    /// `blocked` for a verified BLOCKED decision.
    NotCertified(String),
    /// Certified, but for another environment.
    WrongEnvironment(String),
    /// A required argument is absent (`path`: its contract path).
    ArgumentMissing { path: Option<String> },
    /// An argument the contract does not list. Its name is never reported;
    /// `path` is the object holding it (`None` at the top level).
    ArgumentNotAllowed { path: Option<String> },
    /// A value breaks its constraint (`path`: the contract path, never the value).
    ArgumentInvalid { path: Option<String> },
    /// A `bindTo` argument differs from the trusted task context.
    ScopeMismatch { path: Option<String> },
    /// A `bindTo` argument needs a task context (key) the gate does not have.
    TaskContextMissing { path: Option<String> },
    /// The contract requires an approval receipt for this call.
    ApprovalRequired,
    /// The release binds a tool contract the gate was not given.
    ContractMissing,
}

impl Denial {
    pub fn code(&self) -> String {
        match self {
            Denial::UndeclaredTool => "undeclared_tool".into(),
            Denial::Uncertified => "uncertified".into(),
            Denial::NotCertified(status) => status.clone(),
            Denial::WrongEnvironment(_) => "wrong_environment".into(),
            Denial::ArgumentMissing { .. } => ViolationCode::ArgumentMissing.code().into(),
            Denial::ArgumentNotAllowed { .. } => ViolationCode::ArgumentNotAllowed.code().into(),
            Denial::ArgumentInvalid { .. } => ViolationCode::ArgumentInvalid.code().into(),
            Denial::ScopeMismatch { .. } => ViolationCode::ScopeMismatch.code().into(),
            Denial::TaskContextMissing { .. } => ViolationCode::TaskContextMissing.code().into(),
            Denial::ApprovalRequired => "approval_required".into(),
            Denial::ContractMissing => "contract_missing".into(),
        }
    }

    /// The contract path of an argument denial: built from contract names,
    /// so safe to record (as `gate_path`).
    pub fn path(&self) -> Option<&str> {
        match self {
            Denial::ArgumentMissing { path }
            | Denial::ArgumentNotAllowed { path }
            | Denial::ArgumentInvalid { path }
            | Denial::ScopeMismatch { path }
            | Denial::TaskContextMissing { path } => path.as_deref(),
            _ => None,
        }
    }
}

impl From<contract::Violation> for Denial {
    fn from(v: contract::Violation) -> Self {
        let path = v.path;
        match v.code {
            ViolationCode::ArgumentMissing => Denial::ArgumentMissing { path },
            ViolationCode::ArgumentNotAllowed => Denial::ArgumentNotAllowed { path },
            ViolationCode::ArgumentInvalid => Denial::ArgumentInvalid { path },
            ViolationCode::ScopeMismatch => Denial::ScopeMismatch { path },
            ViolationCode::TaskContextMissing => Denial::TaskContextMissing { path },
        }
    }
}

/// Why a gate cannot start with the given contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateConfigError {
    /// A supplied contract whose reference is not in `spec.policies`.
    NotInRelease { policy_ref: String },
    /// A contract the release binds that was not supplied.
    NotSupplied { policy_ref: String },
    /// Two supplied contracts cover the same tool.
    AmbiguousTool { tool: String },
    /// A contract tool with `sideEffect: true`: its operation outcomes must
    /// be tracked, which this gate cannot do.
    SideEffectUnsupported { tool: String },
    /// The task context is not a JSON object.
    TaskContextNotObject,
}

impl std::fmt::Display for GateConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateConfigError::NotInRelease { policy_ref } => write!(
                f,
                "tool contract {policy_ref} is not bound by the release: add it to spec.policies (and re-certify) or supply the contract the release binds"
            ),
            GateConfigError::NotSupplied { policy_ref } => {
                write!(f, "the release binds tool contract {policy_ref}, which was not supplied (--tool-contract)")
            }
            GateConfigError::AmbiguousTool { tool } => write!(f, "more than one tool contract covers tool {tool:?}"),
            GateConfigError::SideEffectUnsupported { tool } => write!(
                f,
                "tool {tool:?} has sideEffect: true, which needs operation tracking this gate does not provide"
            ),
            GateConfigError::TaskContextNotObject => write!(f, "the task context must be a JSON object"),
        }
    }
}

impl std::error::Error for GateConfigError {}

pub struct ToolGate {
    pub mode: GateMode,
    release: String,
    environment: String,
    tools: BTreeSet<String>,
    certification: Option<Envelope>,
    verify: VerifyContext,
    /// `spec.policies` entries that bind tool contracts.
    contract_refs: BTreeSet<String>,
    /// Whether [`Self::with_contracts`] accepted the contracts the release binds.
    contracts_loaded: bool,
    /// Tool name -> its contract.
    contracts: BTreeMap<String, ToolContract>,
    /// The trusted task context (never from MCP messages).
    task: Option<Value>,
}

impl ToolGate {
    /// `verify` carries the trusted keys and revocations; its `now` and
    /// `expected_release` are set per check.
    pub fn new(
        mode: GateMode,
        manifest: &AgentRelease,
        environment: &str,
        certification: Option<Envelope>,
        verify: VerifyContext,
    ) -> Self {
        let tools = manifest
            .spec
            .tools
            .iter()
            .filter_map(|t| Reference::parse(&t.reference).ok())
            .map(|r| r.name)
            .collect();
        let contract_refs: BTreeSet<String> = manifest
            .spec
            .policies
            .iter()
            .map(|p| p.reference.clone())
            .filter(|r| contract::is_tool_contract_ref(r))
            .collect();
        Self {
            mode,
            release: manifest.manifest_hash().to_string(),
            environment: environment.to_string(),
            tools,
            certification,
            verify,
            contracts_loaded: contract_refs.is_empty(),
            contract_refs,
            contracts: BTreeMap::new(),
            task: None,
        }
    }

    /// Give the gate the release's tool contracts and the trusted task
    /// context. Every supplied contract must be bound by the release
    /// (`spec.policies`), and every contract the release binds must be
    /// supplied; otherwise the gate must not start.
    pub fn with_contracts(mut self, contracts: Vec<ToolContract>, task: Option<Value>) -> Result<Self, GateConfigError> {
        if task.as_ref().is_some_and(|t| !t.is_object()) {
            return Err(GateConfigError::TaskContextNotObject);
        }
        let mut supplied = BTreeSet::new();
        let mut by_tool = BTreeMap::new();
        for c in contracts {
            let policy_ref = c.policy_ref();
            if !self.contract_refs.contains(&policy_ref) {
                return Err(GateConfigError::NotInRelease { policy_ref });
            }
            for (tool, rule) in &c.spec.tools {
                if rule.side_effect {
                    return Err(GateConfigError::SideEffectUnsupported { tool: tool.clone() });
                }
                if by_tool.insert(tool.clone(), c.clone()).is_some() {
                    return Err(GateConfigError::AmbiguousTool { tool: tool.clone() });
                }
            }
            supplied.insert(policy_ref);
        }
        if let Some(missing) = self.contract_refs.difference(&supplied).next() {
            return Err(GateConfigError::NotSupplied { policy_ref: missing.clone() });
        }
        self.contracts = by_tool;
        self.task = task;
        self.contracts_loaded = true;
        Ok(self)
    }

    /// The release's manifest hash (`sha256:<hex>`).
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The release's manifest hash as bytes, for ledger binding.
    pub fn release_bytes(&self) -> [u8; 32] {
        self.release.parse::<cloakpipe_release::ReleaseHash>().map(|h| h.0).unwrap_or_default()
    }

    /// Check one call to `tool` with its raw (pre-masking) `arguments` at
    /// RFC 3339 time `now`.
    pub fn check(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<(), Denial> {
        if !self.tools.contains(tool) {
            return Err(Denial::UndeclaredTool);
        }
        let Some(envelope) = &self.certification else { return Err(Denial::Uncertified) };
        let ctx = VerifyContext {
            now: now.to_string(),
            expected_release: Some(self.release.clone()),
            ..self.verify.clone()
        };
        let report = verify(envelope, &ctx);
        if !report.certified {
            let status = match report.status {
                // Verified, but the decision it attests is a block.
                Status::Valid | Status::ValidWithLimitations => "blocked".to_string(),
                other => serde_json::to_value(other)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                    .unwrap_or_else(|| "invalid".into()),
            };
            return Err(Denial::NotCertified(status));
        }
        // Signed and verified: its scope can be trusted.
        match certified_environment(envelope) {
            Some(env) if env == self.environment => {}
            Some(env) => return Err(Denial::WrongEnvironment(env)),
            None => return Err(Denial::NotCertified("invalid".into())),
        }
        if !self.contracts_loaded {
            return Err(Denial::ContractMissing);
        }
        let Some(rule) = self.contracts.get(tool).and_then(|c| c.rule(tool)) else { return Ok(()) };
        rule.check(arguments, self.task.as_ref())?;
        if rule.requires_approval {
            // No approval receipts yet: an approval-gated call is refused.
            return Err(Denial::ApprovalRequired);
        }
        Ok(())
    }
}

/// `predicate.certification.environment` of a (verified) envelope.
fn certified_environment(envelope: &Envelope) -> Option<String> {
    use base64::prelude::*;
    let payload = BASE64_STANDARD.decode(&envelope.payload).ok()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    statement.pointer("/predicate/certification/environment")?.as_str().map(str::to_string)
}
