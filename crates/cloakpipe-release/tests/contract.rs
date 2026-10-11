//! Tool contracts: argument-level rules for the tools a release may call
//! (docs/ACTION_BOUNDARY.md). The examples under `examples/action-boundary/`
//! are loaded here, so the docs cannot drift from the code.

use cloakpipe_release::contract::{self, ContractError, ToolContract, ViolationCode};
use cloakpipe_release::{namespace, parse_path, Format};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
}

fn crm() -> ToolContract {
    ToolContract::parse_path(&example("crm-tools.contract.yaml")).unwrap()
}

fn task() -> Value {
    serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap()
}

fn good_args() -> Value {
    json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified", "note": "called back"}})
}

fn check(c: &ToolContract, args: &Value) -> Result<(), (ViolationCode, Option<String>)> {
    c.check("crm.patch", Some(args), Some(&task())).map_err(|v| (v.code, v.path))
}

fn contract_from(v: Value) -> Result<ToolContract, ContractError> {
    ToolContract::parse_str(&v.to_string(), Format::Json)
}

fn minimal(arguments: Value, required: Value) -> Value {
    json!({
        "apiVersion": "cloakpipe.co/v1alpha1",
        "kind": "ToolContract",
        "metadata": {"name": "t"},
        "spec": {"tools": {"x": {"arguments": arguments, "required": required}}}
    })
}

// ── the example ─────────────────────────────────────────────────────────

#[test]
fn the_example_contract_parses() {
    let c = crm();
    assert_eq!(c.metadata.name, "crm-tools");
    let rule = c.rule("crm.patch").expect("covers crm.patch");
    assert!(rule.side_effect);
    assert!(rule.requires_approval);
    assert!(c.rule("crm.lookup").is_none());
}

#[test]
fn the_example_release_binds_the_example_contract() {
    let release = parse_path(&example("release.yaml")).unwrap();
    assert!(release.validate().is_empty(), "{:?}", release.validate());
    let refs: Vec<_> = release.spec.policies.iter().map(|p| p.reference.as_str()).collect();
    assert!(refs.contains(&crm().policy_ref().as_str()), "release.yaml must carry {} (has {refs:?})", crm().policy_ref());
}

#[test]
fn the_digest_is_domain_separated_jcs_of_the_contract() {
    let c = crm();
    let raw: Value = serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap();
    let mut h = Sha256::new();
    h.update(b"cloakpipe.co/tool-contract/v1\n");
    h.update(serde_json_canonicalizer::to_vec(&raw).unwrap());
    assert_eq!(c.digest().to_string(), format!("sha256:{}", hex::encode(h.finalize())));
    assert_eq!(namespace::TOOL_CONTRACT_HASH_DOMAIN, "cloakpipe.co/tool-contract/v1");
    assert_eq!(c.policy_ref(), format!("policy:tool-contract/crm-tools@{}", c.digest()));
}

#[test]
fn json_and_yaml_spellings_of_one_contract_share_a_digest() {
    let raw: Value = serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap();
    let from_json = ToolContract::parse_str(&serde_json::to_string_pretty(&raw).unwrap(), Format::Json).unwrap();
    assert_eq!(from_json.digest(), crm().digest());
}

#[test]
fn any_change_changes_the_digest() {
    let mut raw: Value = serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap();
    raw["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["properties"]["note"]["maxLength"] = json!(281);
    assert_ne!(contract_from(raw).unwrap().digest(), crm().digest());
}

#[test]
fn only_tool_contract_policies_are_recognised() {
    assert!(contract::is_tool_contract_ref(&crm().policy_ref()));
    assert!(!contract::is_tool_contract_ref("policy:crm-prod@4"));
    assert!(!contract::is_tool_contract_ref("tool:tool-contract/x@1"));
    assert!(!contract::is_tool_contract_ref("policy:tool-contract/x"));
}

// ── argument rules ──────────────────────────────────────────────────────

#[test]
fn a_conforming_call_passes() {
    assert_eq!(check(&crm(), &good_args()), Ok(()));
    assert_eq!(check(&crm(), &json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "review"}})), Ok(()));
}

#[test]
fn a_tool_the_contract_does_not_cover_passes() {
    assert_eq!(crm().check("crm.lookup", Some(&json!({"anything": 1})), None), Ok(()));
}

#[test]
fn bind_to_pins_arguments_to_the_task() {
    let mut a = good_args();
    a["tenant"] = json!("other-co");
    assert_eq!(check(&crm(), &a), Err((ViolationCode::ScopeMismatch, Some("/tenant".into()))));
    let mut a = good_args();
    a["record"] = json!(42);
    assert_eq!(check(&crm(), &a), Err((ViolationCode::ScopeMismatch, Some("/record".into()))));
}

#[test]
fn a_missing_task_context_or_key_is_a_denial() {
    let v = crm().check("crm.patch", Some(&good_args()), None).unwrap_err();
    assert_eq!((v.code, v.path.as_deref()), (ViolationCode::TaskContextMissing, Some("/record")));
    let v = crm().check("crm.patch", Some(&good_args()), Some(&json!({"taskId": "t-981", "record": "lead-42"}))).unwrap_err();
    assert_eq!((v.code, v.path.as_deref()), (ViolationCode::TaskContextMissing, Some("/tenant")));
}

#[test]
fn unknown_arguments_are_refused_without_naming_them() {
    let mut a = good_args();
    a["tenant_override"] = json!("other-co");
    assert_eq!(check(&crm(), &a), Err((ViolationCode::ArgumentNotAllowed, None)));
    let mut a = good_args();
    a["patch"]["owner"] = json!("mallory");
    assert_eq!(check(&crm(), &a), Err((ViolationCode::ArgumentNotAllowed, Some("/patch".into()))));
}

#[test]
fn missing_arguments_are_refused() {
    let mut a = good_args();
    a.as_object_mut().unwrap().remove("patch");
    assert_eq!(check(&crm(), &a), Err((ViolationCode::ArgumentMissing, Some("/patch".into()))));
    assert_eq!(
        crm().check("crm.patch", None, Some(&task())).map_err(|v| v.code),
        Err(ViolationCode::ArgumentMissing),
        "no arguments at all"
    );
}

#[test]
fn invalid_values_carry_the_contract_path_not_the_value() {
    let cases = [
        (json!({"stage": "closed-won"}), "/patch/stage"),
        (json!({"stage": 1}), "/patch/stage"),
        (json!({"note": "x".repeat(281)}), "/patch/note"),
        (json!({"note": 5}), "/patch/note"),
        (json!({}), "/patch"),
        (json!("stage=qualified"), "/patch"),
    ];
    for (patch, path) in cases {
        let mut a = good_args();
        a["patch"] = patch.clone();
        let err = check(&crm(), &a).unwrap_err();
        assert_eq!(err, (ViolationCode::ArgumentInvalid, Some(path.to_string())), "{patch}");
    }
    // Lengths count Unicode scalars, not bytes.
    let mut a = good_args();
    a["patch"]["note"] = json!("é".repeat(280));
    assert_eq!(check(&crm(), &a), Ok(()));
}

#[test]
fn arguments_that_are_not_an_object_are_invalid() {
    let v = crm().check("crm.patch", Some(&json!(["demo-co"])), Some(&task())).unwrap_err();
    assert_eq!(v.code, ViolationCode::ArgumentInvalid);
}

#[test]
fn the_constraint_language() {
    let c = contract_from(minimal(
        json!({
            "s": {"type": "string", "minLength": 2, "pattern": "[a-z]+"},
            "i": {"type": "integer", "minimum": -1, "maximum": 10},
            "n": {"type": "number", "maximum": 1.5},
            "b": {"type": "boolean"},
            "z": {"type": "null"},
            "k": {"const": {"a": [1, 2]}},
            "l": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"enum": ["a", "b"]}},
            "o": {"type": "object", "maxProperties": 1, "additionalProperties": true}
        }),
        json!([]),
    ))
    .unwrap();
    let ok = |args: Value| c.check("x", Some(&args), None).map_err(|v| (v.code, v.path));
    let bad = |path: &str| Err((ViolationCode::ArgumentInvalid, Some(path.to_string())));
    assert_eq!(ok(json!({})), Ok(()), "nothing required");
    assert_eq!(ok(json!({"s": "ab", "i": 10, "n": 1.5, "b": true, "z": null, "k": {"a": [1, 2]}, "l": ["a", "b"], "o": {"any": 1}})), Ok(()));
    assert_eq!(ok(json!({"i": 3.0})), Ok(()), "3.0 is an integer");
    assert_eq!(ok(json!({"s": "a"})), bad("/s"));
    assert_eq!(ok(json!({"s": "ab1"})), bad("/s"), "pattern is anchored");
    assert_eq!(ok(json!({"s": "1ab"})), bad("/s"), "pattern is anchored");
    assert_eq!(ok(json!({"i": 11})), bad("/i"));
    assert_eq!(ok(json!({"i": -2})), bad("/i"));
    assert_eq!(ok(json!({"i": 1.5})), bad("/i"));
    assert_eq!(ok(json!({"i": "1"})), bad("/i"));
    assert_eq!(ok(json!({"i": u64::MAX})), bad("/i"));
    assert_eq!(ok(json!({"n": 1.6})), bad("/n"));
    assert_eq!(ok(json!({"b": "true"})), bad("/b"));
    assert_eq!(ok(json!({"z": 0})), bad("/z"));
    assert_eq!(ok(json!({"k": {"a": [2, 1]}})), bad("/k"));
    assert_eq!(ok(json!({"l": []})), bad("/l"));
    assert_eq!(ok(json!({"l": ["a", "b", "a"]})), bad("/l"));
    assert_eq!(ok(json!({"l": ["c"]})), bad("/l/items"));
    assert_eq!(ok(json!({"o": {"a": 1, "b": 2}})), bad("/o"));
}

#[test]
fn a_const_null_is_a_constraint_not_an_absence() {
    let c = contract_from(minimal(json!({"z": {"const": null}}), json!(["z"]))).unwrap();
    assert!(c.check("x", Some(&json!({"z": null})), None).is_ok());
    assert_eq!(c.check("x", Some(&json!({"z": 0})), None).unwrap_err().code, ViolationCode::ArgumentInvalid);
}

#[test]
fn nested_task_keys_bind() {
    let c = contract_from(minimal(json!({"org": {"bindTo": "task.org.id"}}), json!(["org"]))).unwrap();
    let task = json!({"org": {"id": "o-1"}});
    assert!(c.check("x", Some(&json!({"org": "o-1"})), Some(&task)).is_ok());
    assert_eq!(c.check("x", Some(&json!({"org": "o-2"})), Some(&task)).unwrap_err().code, ViolationCode::ScopeMismatch);
}

#[test]
fn paths_escape_property_names() {
    let c = contract_from(minimal(json!({"a/b": {"type": "string"}, "c~d": {"type": "string"}}), json!([]))).unwrap();
    assert_eq!(c.check("x", Some(&json!({"a/b": 1})), None).unwrap_err().path.as_deref(), Some("/a~1b"));
    assert_eq!(c.check("x", Some(&json!({"c~d": 1})), None).unwrap_err().path.as_deref(), Some("/c~0d"));
}

#[test]
fn checks_are_deterministic_whatever_the_argument_order() {
    // Two problems: an unknown argument is always reported first.
    let a: Value = serde_json::from_str(r#"{"zzz": 1, "tenant": "x", "record": "lead-42", "patch": {}}"#).unwrap();
    let b: Value = serde_json::from_str(r#"{"patch": {}, "record": "lead-42", "tenant": "x", "zzz": 1}"#).unwrap();
    assert_eq!(check(&crm(), &a), check(&crm(), &b));
    assert_eq!(check(&crm(), &a).unwrap_err().0, ViolationCode::ArgumentNotAllowed);
}

#[test]
fn violation_codes_are_stable() {
    assert_eq!(ViolationCode::ArgumentMissing.code(), "argument_missing");
    assert_eq!(ViolationCode::ArgumentNotAllowed.code(), "argument_not_allowed");
    assert_eq!(ViolationCode::ArgumentInvalid.code(), "argument_invalid");
    assert_eq!(ViolationCode::ScopeMismatch.code(), "scope_mismatch");
    assert_eq!(ViolationCode::TaskContextMissing.code(), "task_context_missing");
}

// ── parsing fails closed ────────────────────────────────────────────────

#[test]
fn malformed_contracts_are_rejected() {
    let base = || -> Value { serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap() };
    let patch = |f: &dyn Fn(&mut Value)| {
        let mut v = base();
        f(&mut v);
        v
    };
    let cases: Vec<(&str, Value)> = vec![
        ("unknown keyword", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["format"] = json!("email"))),
        ("unknown keyword (nested)", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["properties"]["note"]["maxlength"] = json!(1))),
        ("unknown tool field", patch(&|v| v["spec"]["tools"]["crm.patch"]["approval"] = json!(true))),
        ("unknown type", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["type"] = json!("map"))),
        ("type list", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["type"] = json!(["object"]))),
        ("schema-valued additionalProperties", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["additionalProperties"] = json!({"type": "string"}))),
        ("bindTo outside task", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["tenant"]["bindTo"] = json!("env.tenant"))),
        ("bindTo with an empty key", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["tenant"]["bindTo"] = json!("task."))),
        ("bad pattern", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["properties"]["note"]["pattern"] = json!("("))),
        ("required not declared", patch(&|v| v["spec"]["tools"]["crm.patch"]["required"] = json!(["tenant", "owner"]))),
        ("empty constraint", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["record"] = json!({}))),
        ("keywords of another type", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["properties"]["note"]["minItems"] = json!(1))),
        ("empty enum", patch(&|v| v["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["properties"]["stage"]["enum"] = json!([]))),
        ("no tools", patch(&|v| v["spec"]["tools"] = json!({}))),
        ("wrong kind", patch(&|v| v["kind"] = json!("AgentRelease"))),
        ("unknown apiVersion", patch(&|v| v["apiVersion"] = json!("cloakpipe.co/v9"))),
        ("bad name", patch(&|v| v["metadata"]["name"] = json!("CRM Tools"))),
    ];
    for (what, v) in cases {
        assert!(contract_from(v).is_err(), "{what} must be rejected");
    }
}

#[test]
fn duplicate_keys_are_rejected_in_json_too() {
    let src = r#"{"apiVersion":"cloakpipe.co/v1alpha1","kind":"ToolContract","metadata":{"name":"t"},
        "spec":{"tools":{"x":{"arguments":{"a":{"const":1},"a":{"type":"string"}}}}}}"#;
    assert!(ToolContract::parse_str(src, Format::Json).is_err());
}

#[test]
fn legacy_namespace_contracts_are_read_with_the_legacy_domain() {
    let mut raw: Value = serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap();
    raw["apiVersion"] = json!("cloakpipe.dev/v1alpha1");
    let c = contract_from(raw.clone()).unwrap();
    let mut h = Sha256::new();
    h.update(b"cloakpipe.dev/tool-contract/v1\n");
    h.update(serde_json_canonicalizer::to_vec(&raw).unwrap());
    assert_eq!(c.digest().to_string(), format!("sha256:{}", hex::encode(h.finalize())));
}

// ── the JSON schema agrees ──────────────────────────────────────────────

fn schema() -> jsonschema::Validator {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schemas/tool-contract.schema.json");
    let s: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(s["$id"], namespace::TOOL_CONTRACT_SCHEMA_ID);
    jsonschema::validator_for(&s).expect("schema compiles")
}

#[test]
fn the_schema_accepts_the_example_and_rejects_unknown_keywords() {
    let v = schema();
    let raw: Value = serde_yaml::from_str(&std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap()).unwrap();
    assert!(v.is_valid(&raw));
    let mut bad = raw.clone();
    bad["spec"]["tools"]["crm.patch"]["arguments"]["patch"]["format"] = json!("email");
    assert!(!v.is_valid(&bad));
    let mut bad = raw.clone();
    bad["kind"] = json!("AgentRelease");
    assert!(!v.is_valid(&bad));
    let mut bad = raw;
    bad["spec"]["tools"]["crm.patch"]["arguments"]["tenant"]["bindTo"] = json!("env.tenant");
    assert!(!v.is_valid(&bad));
}
