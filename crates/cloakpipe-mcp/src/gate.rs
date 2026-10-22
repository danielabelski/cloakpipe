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
//!
//! A contract tool with `requiresApproval: true` also needs a signed
//! approval receipt for this exact call ([`cloakpipe_receipt::approval`]): the
//! gate computes the call's fingerprint
//! ([`cloakpipe_release::action::fingerprint`] over the raw arguments),
//! reads `<fingerprint hex>.approval.json` from the directory given to
//! [`ToolGate::with_approvals`] and verifies it against the release, the
//! tool, the task context's `taskId` and the trusted approver keys.
//! [`ToolGate::authorize`] returns the receipt's digest and operation id so
//! the call can be recorded against it.
//!
//! A contract tool with `sideEffect: true` is an *operation*
//! ([`crate::operations`]): [`ToolGate::authorize`] names it (the receipt's
//! `operationId`, else [`derive_operation_id`], keyed by the store, from the task context's
//! `taskId` and the call fingerprint) and the interceptor runs it through
//! the operations store given to [`ToolGate::with_operations`], so a call
//! whose outcome is unknown is never silently re-executed. A gate with such
//! a tool and no store is not [`ToolGate::ready`].

use cloakpipe_cert::statement::{verify, Status, VerifyContext};
use cloakpipe_receipt::approval::{verify_approval, ApprovalCheck, ApprovalError};
use cloakpipe_receipt::dsse::{Envelope, TrustedKey};
use cloakpipe_release::action::{derive_operation_id, fingerprint, ToolCallFingerprint};
use cloakpipe_release::contract::{self, ToolContract, ViolationCode};
use cloakpipe_release::{AgentRelease, Reference, ReleaseHash};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::operations::OperationStore;

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
    /// The contract requires an approval receipt for this call and there is
    /// none (any change to the arguments is a different call).
    ApprovalRequired,
    /// The receipt for this call is malformed, not signed by a trusted
    /// approver, or for another release, tool, task or call.
    ApprovalInvalid,
    /// The receipt for this call has passed its `notAfter`.
    ApprovalExpired,
    /// The release binds a tool contract the gate was not given.
    ContractMissing,
    /// The operation id names a different call (operations store).
    OperationConflict { operation_id: String },
    /// The operation is in flight or its outcome is unknown: an operator
    /// must reconcile it (`cloakpipe operations reconcile`) before a retry.
    ReconcileBeforeRetry { operation_id: String },
    /// The operations store could not be read or written.
    OperationsUnavailable,
    /// A side-effecting call sent as a notification (no JSON-RPC id): its
    /// outcome could never be settled.
    RequestIdMissing,
    /// A side-effecting call reusing the JSON-RPC id of a call still in
    /// flight: the replies could not be told apart.
    RequestIdInUse,
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
            Denial::ApprovalInvalid => "approval_invalid".into(),
            Denial::ApprovalExpired => "approval_expired".into(),
            Denial::ContractMissing => "contract_missing".into(),
            Denial::OperationConflict { .. } => "operation_conflict".into(),
            Denial::ReconcileBeforeRetry { .. } => "reconcile_before_retry".into(),
            Denial::OperationsUnavailable => "operations_unavailable".into(),
            Denial::RequestIdMissing => "request_id_missing".into(),
            Denial::RequestIdInUse => "request_id_in_use".into(),
        }
    }

    /// The operation an operations-store denial is about.
    pub fn operation_id(&self) -> Option<&str> {
        match self {
            Denial::OperationConflict { operation_id } | Denial::ReconcileBeforeRetry { operation_id } => Some(operation_id),
            _ => None,
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

/// A call the gate let through on the strength of an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCall {
    /// SHA-256 of the receipt file's bytes: what the ledger records
    /// (`approval`), so an auditor holding the receipt can match it.
    pub receipt_digest: [u8; 32],
    /// The receipt's `operationId`.
    pub operation_id: String,
    /// The call's fingerprint (operator state; never recorded in the ledger).
    pub fingerprint: ToolCallFingerprint,
}

/// The operation a side-effecting call is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationKey {
    /// The approval receipt's `operationId`, else the derived id.
    pub operation_id: String,
    /// The call's fingerprint: the store's `call_digest` (never ledger content).
    pub fingerprint: ToolCallFingerprint,
}

/// What the gate establishes about an allowed call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authorization {
    /// Set when the call needed, and has, a valid approval receipt.
    pub approval: Option<ApprovedCall>,
    /// Set when the contract marks the tool `sideEffect: true`.
    pub operation: Option<OperationKey>,
}

/// Where approval receipts come from and who may sign them.
struct Approvals {
    dir: PathBuf,
    approvers: Vec<TrustedKey>,
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
    /// A contract tool with `sideEffect: true` and no operations store.
    OperationsRequired { tool: String },
    /// The operations store could not be prepared.
    OperationsStore(String),
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
            GateConfigError::OperationsRequired { tool } => write!(
                f,
                "tool {tool:?} has sideEffect: true: its operations must be tracked in an operations store (--operations-db or CLOAKPIPE_OPERATIONS_DB)"
            ),
            GateConfigError::OperationsStore(e) => write!(f, "operations store: {e}"),
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
    /// Approval receipts; `None`: every approval-gated call is refused.
    approvals: Option<Approvals>,
    /// The operations store for `sideEffect` tools.
    operations: Option<Arc<Mutex<OperationStore>>>,
    /// Operations the start-up sweep found left in flight (now `unknown`).
    recovered: Vec<String>,
    /// The operations store's key for derived operation ids.
    operation_id_key: Option<[u8; 32]>,
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
            approvals: None,
            operations: None,
            recovered: Vec::new(),
            operation_id_key: None,
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
            for tool in c.spec.tools.keys() {
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

    /// Read approval receipts from `dir` (`<fingerprint hex>.approval.json`)
    /// and accept those signed by one of `approvers`. Without this, every
    /// call to a tool whose contract requires approval is refused.
    pub fn with_approvals(mut self, dir: impl Into<PathBuf>, approvers: Vec<TrustedKey>) -> Self {
        self.approvals = Some(Approvals { dir: dir.into(), approvers });
        self
    }

    /// Track `sideEffect` operations in `store`. The gate takes the database
    /// for as long as it lives (an error if another gate holds it), and
    /// every operation a previous process left `in_flight` becomes `unknown`
    /// now (see [`Self::recovered_operations`]): one gate per operations
    /// database.
    pub fn with_operations(mut self, mut store: OperationStore) -> Result<Self, GateConfigError> {
        self.recovered = store.recover().map_err(|e| GateConfigError::OperationsStore(e.0))?;
        self.operation_id_key = Some(store.operation_id_key().map_err(|e| GateConfigError::OperationsStore(e.0))?);
        self.operations = Some(Arc::new(Mutex::new(store)));
        Ok(self)
    }

    /// Whether an operations store is configured.
    pub fn has_operations(&self) -> bool {
        self.operations.is_some()
    }

    /// The operations store, shared with the interceptor's reply thread.
    pub fn operations(&self) -> Option<Arc<Mutex<OperationStore>>> {
        self.operations.clone()
    }

    /// Operations the start-up sweep marked `unknown`.
    pub fn recovered_operations(&self) -> &[String] {
        &self.recovered
    }

    /// Can the gate run? A contract tool with `sideEffect: true` needs an
    /// operations store.
    pub fn ready(&self) -> Result<(), GateConfigError> {
        if self.operations.is_none() {
            let side_effect = self.contracts.iter().find(|(tool, c)| c.rule(tool).is_some_and(|r| r.side_effect));
            if let Some((tool, _)) = side_effect {
                return Err(GateConfigError::OperationsRequired { tool: tool.clone() });
            }
        }
        Ok(())
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
        self.authorize(tool, arguments, now).map(|_| ())
    }

    /// [`Self::check`], also returning what the call was allowed on (its
    /// approval receipt, when the contract requires one).
    pub fn authorize(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<Authorization, Denial> {
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
        let Some(rule) = self.contracts.get(tool).and_then(|c| c.rule(tool)) else { return Ok(Authorization::default()) };
        rule.check(arguments, self.task.as_ref())?;
        let arguments = arguments.unwrap_or(&Value::Null);
        let approval = if rule.requires_approval { Some(self.approve(tool, arguments, now)?) } else { None };
        let operation = if rule.side_effect { Some(self.operation_key(tool, arguments, approval.as_ref())?) } else { None };
        Ok(Authorization { approval, operation })
    }

    /// The operation a call to `tool` is, whether or not it passes the gate:
    /// `--gate warn` forwards a call that fails it, and tracking a
    /// side-effecting call is not a release rule. `None` when the contract
    /// does not mark the tool `sideEffect: true`. The id is the approval
    /// receipt's `operationId` when a receipt for this call verifies, else the
    /// derived id.
    pub fn operation(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<Option<OperationKey>, Denial> {
        let Some(rule) = self.contracts.get(tool).and_then(|c| c.rule(tool)) else { return Ok(None) };
        if !rule.side_effect {
            return Ok(None);
        }
        let arguments = arguments.unwrap_or(&Value::Null);
        let approval = if rule.requires_approval { self.approve(tool, arguments, now).ok() } else { None };
        self.operation_key(tool, arguments, approval.as_ref()).map(Some)
    }

    /// The operation of a side-effecting call: the receipt's `operationId`,
    /// else derived from the task and the call.
    fn operation_key(&self, tool: &str, arguments: &Value, approval: Option<&ApprovedCall>) -> Result<OperationKey, Denial> {
        if let Some(a) = approval {
            return Ok(OperationKey { operation_id: a.operation_id.clone(), fingerprint: a.fingerprint });
        }
        let release: ReleaseHash = self.release.parse().map_err(|_| Denial::OperationsUnavailable)?;
        let fp = fingerprint(&release, tool, arguments);
        let task_id = self.task_id().ok_or(Denial::TaskContextMissing { path: None })?;
        // Without an operations store there is no key (and `ready` refuses).
        let key = self.operation_id_key.as_ref().ok_or(Denial::OperationsUnavailable)?;
        Ok(OperationKey { operation_id: derive_operation_id(key, task_id, &fp), fingerprint: fp })
    }

    /// The trusted task context's `taskId`.
    fn task_id(&self) -> Option<&str> {
        self.task.as_ref().and_then(|t| t.get("taskId")).and_then(Value::as_str)
    }

    /// Find and verify the approval receipt for this exact call.
    fn approve(&self, tool: &str, arguments: &Value, now: &str) -> Result<ApprovedCall, Denial> {
        let Some(approvals) = &self.approvals else { return Err(Denial::ApprovalRequired) };
        let release: ReleaseHash = self.release.parse().map_err(|_| Denial::ApprovalInvalid)?;
        let fp = fingerprint(&release, tool, arguments);
        // The file name is hex: nothing from the call reaches the path.
        let path = approvals.dir.join(format!("{}.approval.json", fp.hex()));
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Denial::ApprovalRequired),
            Err(e) => {
                tracing::warn!(error = %e, "approval receipt unreadable");
                return Err(Denial::ApprovalInvalid);
            }
        };
        let Some(task_id) = self.task_id() else {
            return Err(Denial::TaskContextMissing { path: None });
        };
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| Denial::ApprovalInvalid)?;
        let check = ApprovalCheck {
            fingerprint: fp,
            release: &self.release,
            tool,
            task_id,
            approvers: &approvals.approvers,
            now,
        };
        match verify_approval(&envelope, &check) {
            Ok(a) => Ok(ApprovedCall {
                receipt_digest: Sha256::digest(&bytes).into(),
                operation_id: a.operation_id,
                fingerprint: fp,
            }),
            Err(ApprovalError::Expired) => Err(Denial::ApprovalExpired),
            Err(e @ ApprovalError::Invalid(_)) => {
                // Receipt diagnostics only: never argument values.
                tracing::warn!(reason = %e, "approval receipt rejected");
                Err(Denial::ApprovalInvalid)
            }
        }
    }
}

/// `predicate.certification.environment` of a (verified) envelope.
fn certified_environment(envelope: &Envelope) -> Option<String> {
    use base64::prelude::*;
    let payload = BASE64_STANDARD.decode(&envelope.payload).ok()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    statement.pointer("/predicate/certification/environment")?.as_str().map(str::to_string)
}
