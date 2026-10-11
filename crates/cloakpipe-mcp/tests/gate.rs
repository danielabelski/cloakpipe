//! Contract tests for `cloakpipe_mcp::gate` (see the module doc comment).

use cloakpipe_cert::statement::{sign, statement, Certification, Envelope, TrustedKey, VerifyContext};
use cloakpipe_mcp::{Denial, GateMode, ToolGate};
use cloakpipe_release::AgentRelease;
use ed25519_dalek::SigningKey;
use serde_json::json;

const NOW: &str = "2026-10-06T12:00:00Z";

fn manifest() -> AgentRelease {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn release() -> String {
    manifest().manifest_hash().to_string()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn cert_for(release: &str, outcome: &str, environment: &str) -> Certification {
    serde_json::from_value(json!({
        "id": "cert-0001",
        "release": release,
        "agent": "support-agent",
        "environment": environment,
        "decision": {
            "outcome": outcome,
            "release": release,
            "policy": {"name": "support-prod", "version": "11", "hash": format!("sha256:{}", "cd".repeat(32))},
            "requiredSuites": [],
            "runs": [{"runId": "run-1", "suite": "support-critical", "hash": format!("sha256:{}", "11".repeat(32))}],
            "baselineRuns": [],
            "summaries": [],
            "reasons": if outcome == "blocked" {
                json!([{"code": "pass_rate_below_minimum", "message": "pass rate 0.8 < 0.95"}])
            } else { json!([]) }
        },
        "issuedAt": "2026-10-01T00:00:00Z",
        "validUntil": "2026-10-31T00:00:00Z",
        "issuer": "ci:acme/support"
    }))
    .unwrap()
}

fn envelope(c: &Certification) -> Envelope {
    sign(&statement(c), &key(), "k1")
}

fn trust() -> VerifyContext {
    VerifyContext {
        trusted: vec![TrustedKey { keyid: "k1".into(), public_key: key().verifying_key().to_bytes() }],
        ..Default::default()
    }
}

fn gate(cert: Option<Envelope>) -> ToolGate {
    ToolGate::new(GateMode::Enforce, &manifest(), "production", cert, trust())
}

fn certified() -> ToolGate {
    gate(Some(envelope(&cert_for(&release(), "certified", "production"))))
}

#[test]
fn a_certified_release_may_call_its_declared_tools() {
    let g = certified();
    assert_eq!(g.release(), release());
    assert_eq!(g.check("refund", None, NOW), Ok(()));
    assert_eq!(g.check("lookup-customer", None, NOW), Ok(()));
}

#[test]
fn undeclared_tools_are_refused() {
    let g = certified();
    for tool in ["delete_customer", "refund@4", "tool:refund", "", "REFUND"] {
        assert_eq!(g.check(tool, None, NOW), Err(Denial::UndeclaredTool), "{tool:?}");
    }
}

#[test]
fn without_a_certification_every_call_is_refused() {
    assert_eq!(gate(None).check("refund", None, NOW), Err(Denial::Uncertified));
}

#[test]
fn the_certification_must_verify_now() {
    let g = certified();
    assert_eq!(g.check("refund", None, "2026-10-31T00:00:00Z"), Err(Denial::NotCertified("expired".into())));
    assert_eq!(g.check("refund", None, "2026-09-30T00:00:00Z"), Err(Denial::NotCertified("invalid".into())), "not yet valid is INVALID in the verify contract");
    assert_eq!(g.check("refund", None, "not a time"), Err(Denial::NotCertified("invalid".into())));
}

#[test]
fn revoked_untrusted_and_foreign_certifications_are_refused() {
    let c = cert_for(&release(), "certified", "production");
    let env = envelope(&c);

    let mut revoked = trust();
    let digest = {
        use base64::prelude::*;
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(BASE64_STANDARD.decode(&env.payload).unwrap()))
    };
    revoked.revoked_statements.insert(digest);
    let g = ToolGate::new(GateMode::Enforce, &manifest(), "production", Some(env.clone()), revoked);
    assert_eq!(g.check("refund", None, NOW), Err(Denial::NotCertified("revoked".into())));

    let untrusted = ToolGate::new(GateMode::Enforce, &manifest(), "production", Some(env), VerifyContext::default());
    assert_eq!(untrusted.check("refund", None, NOW), Err(Denial::NotCertified("invalid".into())));

    // A valid certification of another release.
    let other = format!("sha256:{}", "ab".repeat(32));
    let g = gate(Some(envelope(&cert_for(&other, "certified", "production"))));
    assert_eq!(g.check("refund", None, NOW), Err(Denial::NotCertified("invalid".into())));
}

#[test]
fn a_blocked_decision_does_not_certify() {
    let g = gate(Some(envelope(&cert_for(&release(), "blocked", "production"))));
    assert_eq!(g.check("refund", None, NOW), Err(Denial::NotCertified("blocked".into())));
}

#[test]
fn the_certification_must_cover_the_environment() {
    let g = gate(Some(envelope(&cert_for(&release(), "certified", "staging"))));
    assert_eq!(g.check("refund", None, NOW), Err(Denial::WrongEnvironment("staging".into())));
}

#[test]
fn undeclared_is_checked_before_certification() {
    // An undeclared tool is refused for that reason even without a certification.
    assert_eq!(gate(None).check("delete_customer", None, NOW), Err(Denial::UndeclaredTool));
}

#[test]
fn denial_codes_are_stable() {
    assert_eq!(Denial::UndeclaredTool.code(), "undeclared_tool");
    assert_eq!(Denial::Uncertified.code(), "uncertified");
    assert_eq!(Denial::NotCertified("revoked".into()).code(), "revoked");
    assert_eq!(Denial::WrongEnvironment("staging".into()).code(), "wrong_environment");
}

// ── tool contracts: argument-level rules ────────────────────────────────

mod contracts {
    use super::*;
    use cloakpipe_mcp::GateConfigError;
    use cloakpipe_release::contract::ToolContract;
    use cloakpipe_release::{parse_path, ArtifactRef, Format};
    use serde_json::Value;

    fn example(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
    }

    /// The example contract with item-2/3 features switched as given.
    fn contract(side_effect: bool, approval: bool) -> ToolContract {
        let src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
            .unwrap()
            .replace("sideEffect: true", &format!("sideEffect: {side_effect}"))
            .replace("requiresApproval: true", &format!("requiresApproval: {approval}"));
        ToolContract::parse_str(&src, Format::Yaml).unwrap()
    }

    /// The example release, binding exactly `contracts`.
    fn release_binding(contracts: &[&ToolContract]) -> AgentRelease {
        let mut m = parse_path(&example("release.yaml")).unwrap();
        m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
        m.spec.policies.extend(contracts.iter().map(|c| ArtifactRef { reference: c.policy_ref() }));
        m
    }

    fn task() -> Value {
        serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap()
    }

    fn certified_for(m: &AgentRelease) -> ToolGate {
        let cert = envelope(&cert_for(&m.manifest_hash().to_string(), "certified", "production"));
        ToolGate::new(GateMode::Enforce, m, "production", Some(cert), trust())
    }

    fn gate_with(task: Option<Value>) -> ToolGate {
        let c = contract(false, false);
        certified_for(&release_binding(&[&c])).with_contracts(vec![c], task).unwrap()
    }

    fn args() -> Value {
        json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified"}})
    }

    fn with(f: impl Fn(&mut Value)) -> Value {
        let mut a = args();
        f(&mut a);
        a
    }

    #[test]
    fn the_example_release_binds_the_example_contract() {
        let m = parse_path(&example("release.yaml")).unwrap();
        let c = ToolContract::parse_path(&example("crm-tools.contract.yaml")).unwrap();
        assert!(m.spec.policies.iter().any(|p| p.reference == c.policy_ref()));
    }

    #[test]
    fn a_conforming_call_is_allowed() {
        assert_eq!(gate_with(Some(task())).check("crm.patch", Some(&args()), NOW), Ok(()));
    }

    #[test]
    fn calls_that_break_the_contract_are_refused_with_the_contract_path() {
        let g = gate_with(Some(task()));
        let cases = [
            (with(|a| a["tenant"] = json!("other-co")), Denial::ScopeMismatch { path: Some("/tenant".into()) }),
            (with(|a| a["tenant_override"] = json!("x")), Denial::ArgumentNotAllowed { path: None }),
            (with(|a| a["patch"]["owner"] = json!("x")), Denial::ArgumentNotAllowed { path: Some("/patch".into()) }),
            (with(|a| a["patch"]["stage"] = json!("closed-won")), Denial::ArgumentInvalid { path: Some("/patch/stage".into()) }),
            (with(|a| {
                a.as_object_mut().unwrap().remove("record");
            }), Denial::ArgumentMissing { path: Some("/record".into()) }),
            (json!("tenant=demo-co"), Denial::ArgumentInvalid { path: None }),
        ];
        for (a, denial) in cases {
            assert_eq!(g.check("crm.patch", Some(&a), NOW), Err(denial), "{a}");
        }
        assert_eq!(g.check("crm.patch", None, NOW), Err(Denial::ArgumentMissing { path: Some("/patch".into()) }));
    }

    #[test]
    fn without_a_task_context_bound_arguments_are_refused() {
        let g = gate_with(None);
        assert_eq!(g.check("crm.patch", Some(&args()), NOW), Err(Denial::TaskContextMissing { path: Some("/record".into()) }));
    }

    #[test]
    fn release_checks_come_before_argument_checks() {
        let c = contract(false, false);
        let m = release_binding(&[&c]);
        let uncertified = ToolGate::new(GateMode::Enforce, &m, "production", None, trust()).with_contracts(vec![c], None).unwrap();
        assert_eq!(uncertified.check("crm.patch", Some(&json!({"x": 1})), NOW), Err(Denial::Uncertified));
        assert_eq!(gate_with(None).check("crm.delete", Some(&args()), NOW), Err(Denial::UndeclaredTool));
    }

    #[test]
    fn declared_tools_outside_every_contract_keep_todays_behaviour() {
        assert_eq!(gate_with(None).check("crm.lookup", Some(&json!({"anything": [1, 2]})), NOW), Ok(()));
    }

    #[test]
    fn a_tool_that_requires_approval_is_refused_without_a_receipt() {
        let c = contract(false, true);
        let g = certified_for(&release_binding(&[&c])).with_contracts(vec![c], Some(task())).unwrap();
        assert_eq!(g.check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalRequired));
        // Arguments are checked first.
        assert_eq!(
            g.check("crm.patch", Some(&with(|a| a["tenant"] = json!("x"))), NOW),
            Err(Denial::ScopeMismatch { path: Some("/tenant".into()) })
        );
    }

    #[test]
    fn a_contract_the_release_does_not_bind_refuses_to_start() {
        let bound = contract(false, false);
        let other = ToolContract::parse_str(
            &std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap().replace("maxLength: 280", "maxLength: 9000").replace("sideEffect: true", "sideEffect: false").replace("requiresApproval: true", "requiresApproval: false"),
            Format::Yaml,
        )
        .unwrap();
        let m = release_binding(&[&bound]);
        let err = certified_for(&m).with_contracts(vec![other.clone()], Some(task())).err().expect("refused");
        assert!(matches!(&err, GateConfigError::NotInRelease { policy_ref } if *policy_ref == other.policy_ref()), "{err}");
        assert!(err.to_string().contains(&other.policy_ref()), "the message names the digest to bind: {err}");
    }

    #[test]
    fn a_contract_the_release_binds_but_was_not_supplied_refuses_to_start() {
        let c = contract(false, false);
        let m = release_binding(&[&c]);
        let err = certified_for(&m).with_contracts(vec![], Some(task())).err().expect("refused");
        assert!(matches!(&err, GateConfigError::NotSupplied { policy_ref } if *policy_ref == c.policy_ref()), "{err}");
        // A library caller that never supplies contracts gets every call refused.
        assert_eq!(certified_for(&m).check("crm.lookup", None, NOW), Err(Denial::ContractMissing));
    }

    #[test]
    fn two_contracts_for_one_tool_refuse_to_start() {
        let a = contract(false, false);
        let b = ToolContract::parse_str(
            &std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap().replace("name: crm-tools", "name: crm-tools-2").replace("sideEffect: true", "sideEffect: false").replace("requiresApproval: true", "requiresApproval: false"),
            Format::Yaml,
        )
        .unwrap();
        let m = release_binding(&[&a, &b]);
        let err = certified_for(&m).with_contracts(vec![a, b], None).err().expect("refused");
        assert!(matches!(&err, GateConfigError::AmbiguousTool { tool } if tool == "crm.patch"), "{err}");
    }

    #[test]
    fn side_effect_tools_need_an_operations_store() {
        let c = contract(true, false);
        let m = release_binding(&[&c]);
        let g = certified_for(&m).with_contracts(vec![c.clone()], Some(task())).unwrap();
        assert!(!g.has_operations());
        let err = g.ready().expect_err("not ready without an operations store");
        assert!(matches!(&err, GateConfigError::OperationsRequired { tool } if tool == "crm.patch"), "{err}");
        assert!(err.to_string().contains("--operations-db"), "{err}");

        let dir = tempfile::tempdir().unwrap();
        let store = cloakpipe_mcp::operations::OperationStore::open(dir.path().join("ops.db")).unwrap();
        let g = certified_for(&m).with_contracts(vec![c], Some(task())).unwrap().with_operations(store).unwrap();
        assert!(g.has_operations());
        assert!(g.ready().is_ok());
        // A gate with no side-effect tool needs no store.
        assert!(gate_with(Some(task())).ready().is_ok());
    }

    #[test]
    fn a_side_effect_call_gets_an_operation_derived_from_the_task_and_the_call() {
        use cloakpipe_release::action::{derive_operation_id, fingerprint};
        let c = contract(true, false);
        let m = release_binding(&[&c]);
        let g = certified_for(&m).with_contracts(vec![c], Some(task())).unwrap();
        let auth = g.authorize("crm.patch", Some(&args()), NOW).unwrap();
        let op = auth.operation.expect("a side-effect call is an operation");
        let fp = fingerprint(&m.manifest_hash(), "crm.patch", &args());
        assert_eq!(op.fingerprint, fp);
        assert_eq!(op.operation_id, derive_operation_id("t-981", &fp));
        assert!(auth.approval.is_none());
        // Same call, same operation; another call, another operation.
        assert_eq!(g.authorize("crm.patch", Some(&args()), NOW).unwrap().operation.unwrap().operation_id, op.operation_id);
        let other = with(|a| a["patch"]["stage"] = json!("review"));
        assert_ne!(g.authorize("crm.patch", Some(&other), NOW).unwrap().operation.unwrap().operation_id, op.operation_id);
        // Tools without sideEffect are not operations.
        assert!(gate_with(Some(task())).authorize("crm.patch", Some(&args()), NOW).unwrap().operation.is_none());
    }

    #[test]
    fn a_side_effect_call_without_a_task_id_is_refused() {
        let c = contract(true, false);
        let m = release_binding(&[&c]);
        let mut t = task();
        t.as_object_mut().unwrap().remove("taskId");
        let g = certified_for(&m).with_contracts(vec![c], Some(t)).unwrap();
        assert_eq!(g.check("crm.patch", Some(&args()), NOW), Err(Denial::TaskContextMissing { path: None }));
    }

    #[test]
    fn operation_denials_have_stable_codes() {
        let op = Some("op-1".to_string());
        assert_eq!(Denial::OperationConflict { operation_id: "op-1".into() }.code(), "operation_conflict");
        assert_eq!(Denial::ReconcileBeforeRetry { operation_id: "op-1".into() }.code(), "reconcile_before_retry");
        assert_eq!(Denial::OperationConflict { operation_id: "op-1".into() }.operation_id(), op.as_deref());
        assert_eq!(Denial::OperationsUnavailable.code(), "operations_unavailable");
        assert_eq!(Denial::RequestIdMissing.code(), "request_id_missing");
        assert_eq!(Denial::RequestIdInUse.code(), "request_id_in_use");
        assert_eq!(Denial::ApprovalRequired.operation_id(), None);
    }

    #[test]
    fn the_task_context_must_be_an_object() {
        let c = contract(false, false);
        let m = release_binding(&[&c]);
        let err = certified_for(&m).with_contracts(vec![c], Some(json!(["demo-co"]))).err().expect("refused");
        assert!(matches!(err, GateConfigError::TaskContextNotObject), "{err}");
    }

    #[test]
    fn a_release_without_contracts_is_unchanged() {
        let g = certified().with_contracts(vec![], None).unwrap();
        assert_eq!(g.check("refund", Some(&json!({"anything": 1})), NOW), Ok(()));
        assert_eq!(certified().check("refund", Some(&json!({"anything": 1})), NOW), Ok(()));
    }

    #[test]
    fn contract_denial_codes_are_stable() {
        let p = || Some("/patch/stage".to_string());
        assert_eq!(Denial::ArgumentMissing { path: p() }.code(), "argument_missing");
        assert_eq!(Denial::ArgumentNotAllowed { path: None }.code(), "argument_not_allowed");
        assert_eq!(Denial::ArgumentInvalid { path: p() }.code(), "argument_invalid");
        assert_eq!(Denial::ScopeMismatch { path: p() }.code(), "scope_mismatch");
        assert_eq!(Denial::TaskContextMissing { path: p() }.code(), "task_context_missing");
        assert_eq!(Denial::ApprovalRequired.code(), "approval_required");
        assert_eq!(Denial::ContractMissing.code(), "contract_missing");
        assert_eq!(Denial::ArgumentInvalid { path: p() }.path(), Some("/patch/stage"));
        assert_eq!(Denial::UndeclaredTool.path(), None);
    }
}

// ── signed approval receipts ────────────────────────────────────────────

mod approvals {
    use super::*;
    use cloakpipe_cert::approval::{sign_approval, Approval};
    use cloakpipe_mcp::ApprovedCall;
    use cloakpipe_release::action::{fingerprint, ToolCallFingerprint};
    use cloakpipe_release::contract::ToolContract;
    use cloakpipe_release::{parse_path, ArtifactRef, Format, ReleaseHash};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};

    fn example(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
    }

    /// The example contract: approval on, operation tracking (item 3) off.
    fn contract() -> ToolContract {
        let src = std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap().replace("sideEffect: true", "sideEffect: false");
        ToolContract::parse_str(&src, Format::Yaml).unwrap()
    }

    fn manifest() -> AgentRelease {
        let mut m = parse_path(&example("release.yaml")).unwrap();
        m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
        m.spec.policies.push(ArtifactRef { reference: contract().policy_ref() });
        m
    }

    fn release() -> ReleaseHash {
        manifest().manifest_hash()
    }

    fn task() -> Value {
        serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap()
    }

    fn approver() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn approvers() -> Vec<TrustedKey> {
        vec![TrustedKey { keyid: "approver-1".into(), public_key: approver().verifying_key().to_bytes() }]
    }

    /// A certified gate for the example release with approvals read from `dir`.
    fn gate_in(dir: &Path, task: Option<Value>) -> ToolGate {
        let m = manifest();
        let cert = envelope(&cert_for(&m.manifest_hash().to_string(), "certified", "production"));
        ToolGate::new(GateMode::Enforce, &m, "production", Some(cert), trust())
            .with_contracts(vec![contract()], task)
            .unwrap()
            .with_approvals(dir, approvers())
    }

    fn args() -> Value {
        json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "review", "note": "called back"}})
    }

    fn approval() -> Approval {
        Approval {
            release: release().to_string(),
            tool: "crm.patch".into(),
            task_id: "t-981".into(),
            operation_id: "op-7f3a".into(),
            approver: "approver-1".into(),
            approved_at: "2026-10-06T11:58:00Z".into(),
            not_after: "2026-10-06T12:15:00Z".into(),
        }
    }

    fn fp(a: &Value) -> ToolCallFingerprint {
        fingerprint(&release(), "crm.patch", a)
    }

    /// Sign `approval` for the call with `signed_args` and file it under the
    /// fingerprint of `filed_args`. Returns the receipt file's bytes.
    fn file_receipt(dir: &Path, approval: &Approval, key: &SigningKey, signed: &ToolCallFingerprint, filed: &ToolCallFingerprint) -> Vec<u8> {
        let env = sign_approval(signed, approval, key, "approver-1");
        let bytes = serde_json::to_vec_pretty(&env).unwrap();
        std::fs::write(dir.join(format!("{}.approval.json", filed.hex())), &bytes).unwrap();
        bytes
    }

    fn approve(dir: &Path, a: &Approval) -> Vec<u8> {
        file_receipt(dir, a, &approver(), &fp(&args()), &fp(&args()))
    }

    #[test]
    fn an_approved_call_passes_and_names_its_receipt_and_operation() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = approve(dir.path(), &approval());
        let g = gate_in(dir.path(), Some(task()));
        let auth = g.authorize("crm.patch", Some(&args()), NOW).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        assert_eq!(
            auth.approval,
            Some(ApprovedCall { receipt_digest: expected, operation_id: "op-7f3a".into(), fingerprint: fp(&args()) })
        );
        assert_eq!(g.check("crm.patch", Some(&args()), NOW), Ok(()));
    }

    #[test]
    fn an_approved_side_effect_call_is_the_receipts_operation() {
        // The full example contract: sideEffect and requiresApproval both on.
        let full = ToolContract::parse_path(&example("crm-tools.contract.yaml")).unwrap();
        let mut m = parse_path(&example("release.yaml")).unwrap();
        m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
        m.spec.policies.push(ArtifactRef { reference: full.policy_ref() });
        let dir = tempfile::tempdir().unwrap();
        let fp = fingerprint(&m.manifest_hash(), "crm.patch", &args());
        let a = Approval { release: m.manifest_hash().to_string(), ..approval() };
        file_receipt(dir.path(), &a, &approver(), &fp, &fp);
        let cert = envelope(&cert_for(&m.manifest_hash().to_string(), "certified", "production"));
        let g = ToolGate::new(GateMode::Enforce, &m, "production", Some(cert), trust())
            .with_contracts(vec![full], Some(task()))
            .unwrap()
            .with_approvals(dir.path(), approvers());
        let auth = g.authorize("crm.patch", Some(&args()), NOW).unwrap();
        let op = auth.operation.expect("an operation");
        assert_eq!(op.operation_id, "op-7f3a", "the receipt's operationId, not a derived one");
        assert_eq!(op.fingerprint, fp);
    }

    #[test]
    fn a_changed_argument_needs_its_own_approval() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &approval());
        let g = gate_in(dir.path(), Some(task()));
        let mut changed = args();
        changed["patch"]["stage"] = json!("qualified");
        assert_eq!(g.check("crm.patch", Some(&changed), NOW), Err(Denial::ApprovalRequired));
        let mut changed = args();
        changed["patch"]["note"] = json!("called back!");
        assert_eq!(g.check("crm.patch", Some(&changed), NOW), Err(Denial::ApprovalRequired));
    }

    #[test]
    fn a_receipt_filed_under_another_calls_name_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let mut changed = args();
        changed["patch"]["stage"] = json!("qualified");
        // Approved for `args`, copied to the file name of `changed`.
        file_receipt(dir.path(), &approval(), &approver(), &fp(&args()), &fp(&changed));
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&changed), NOW), Err(Denial::ApprovalInvalid));
    }

    #[test]
    fn an_expired_receipt_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &approval());
        let g = gate_in(dir.path(), Some(task()));
        assert_eq!(g.check("crm.patch", Some(&args()), "2026-10-06T12:15:00Z"), Err(Denial::ApprovalExpired));
    }

    #[test]
    fn a_receipt_from_an_untrusted_signer_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let mallory = SigningKey::from_bytes(&[66u8; 32]);
        file_receipt(dir.path(), &approval(), &mallory, &fp(&args()), &fp(&args()));
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalInvalid));
    }

    #[test]
    fn a_receipt_for_another_task_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &Approval { task_id: "t-982".into(), ..approval() });
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalInvalid));
    }

    #[test]
    fn a_receipt_for_another_release_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let other: ReleaseHash = format!("sha256:{}", "ee".repeat(32)).parse().unwrap();
        // Signed for the same call under another release, filed where this
        // release looks: the subject is another fingerprint.
        let other_fp = fingerprint(&other, "crm.patch", &args());
        let a = Approval { release: other.to_string(), ..approval() };
        file_receipt(dir.path(), &a, &approver(), &other_fp, &fp(&args()));
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalInvalid));
        // This call's fingerprint, but the signed release is another one.
        approve(dir.path(), &a);
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalInvalid));
    }

    #[test]
    fn an_unreadable_receipt_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(format!("{}.approval.json", fp(&args()).hex())), "{not json").unwrap();
        assert_eq!(gate_in(dir.path(), Some(task())).check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalInvalid));
    }

    #[test]
    fn without_approvals_configured_every_approval_gated_call_is_refused() {
        let m = manifest();
        let cert = envelope(&cert_for(&m.manifest_hash().to_string(), "certified", "production"));
        let g = ToolGate::new(GateMode::Enforce, &m, "production", Some(cert), trust())
            .with_contracts(vec![contract()], Some(task()))
            .unwrap();
        assert_eq!(g.check("crm.patch", Some(&args()), NOW), Err(Denial::ApprovalRequired));
    }

    #[test]
    fn a_task_context_without_a_task_id_cannot_match_a_receipt() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &approval());
        let mut t = task();
        t.as_object_mut().unwrap().remove("taskId");
        assert_eq!(
            gate_in(dir.path(), Some(t)).check("crm.patch", Some(&args()), NOW),
            Err(Denial::TaskContextMissing { path: None })
        );
    }

    #[test]
    fn arguments_are_checked_before_approval() {
        let dir = tempfile::tempdir().unwrap();
        let mut bad = args();
        bad["tenant"] = json!("rival-co");
        file_receipt(dir.path(), &approval(), &approver(), &fp(&bad), &fp(&bad));
        assert_eq!(
            gate_in(dir.path(), Some(task())).check("crm.patch", Some(&bad), NOW),
            Err(Denial::ScopeMismatch { path: Some("/tenant".into()) }),
            "an approval never widens the contract"
        );
    }

    #[test]
    fn tools_without_requires_approval_carry_no_approval() {
        let dir = tempfile::tempdir().unwrap();
        let g = gate_in(dir.path(), Some(task()));
        assert_eq!(g.authorize("crm.lookup", None, NOW).unwrap().approval, None);
    }

    #[test]
    fn approval_denial_codes_are_stable() {
        assert_eq!(Denial::ApprovalRequired.code(), "approval_required");
        assert_eq!(Denial::ApprovalInvalid.code(), "approval_invalid");
        assert_eq!(Denial::ApprovalExpired.code(), "approval_expired");
    }
}
