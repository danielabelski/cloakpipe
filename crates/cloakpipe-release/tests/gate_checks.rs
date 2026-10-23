//! What the tool gate needs from a release (`AgentRelease::gate_issues`):
//! its identity, the tools it declares and the policies it binds. Code,
//! prompt, model and runtime pins matter for certification only, so a release
//! without them is a valid gate input.

use cloakpipe_release::{parse_path, parse_str, Format, IssueCode};
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const MINIMAL: &str = r#"
apiVersion: cloakpipe.co/v1alpha1
kind: AgentRelease
metadata:
  agent: support-agent
  version: "1"
spec:
  tools:
    - ref: tool:lookup_ticket@1
    - ref: tool:send_email@1
"#;

#[test]
fn a_release_without_runtime_pins_parses() {
    let m = parse_str(MINIMAL, Format::Yaml).expect("code, prompts, model and runtime are optional");
    assert_eq!(m.spec.tools.len(), 2);
    assert!(m.spec.prompts.is_empty());
}

#[test]
fn a_release_without_runtime_pins_passes_gate_checks_but_is_not_certifiable() {
    let m = parse_str(MINIMAL, Format::Yaml).unwrap();
    assert_eq!(m.gate_issues(), vec![]);
    let codes: Vec<IssueCode> = m.validate().iter().map(|i| i.code).collect();
    for code in [IssueCode::InvalidCommit, IssueCode::UnpinnedImage, IssueCode::EmptyField] {
        assert!(codes.contains(&code), "{code:?} missing from {codes:?}");
    }
}

#[test]
fn the_support_agent_example_is_a_valid_gate_input() {
    let m = parse_path(&root().join("examples/support-agent/release.yaml")).unwrap();
    assert_eq!(m.gate_issues(), vec![]);
}

#[test]
fn a_certifiable_release_passes_gate_checks() {
    let m = parse_path(&root().join("crates/cloakpipe-release/testdata/support-agent-184.yaml")).unwrap();
    assert_eq!(m.validate(), vec![]);
    assert_eq!(m.gate_issues(), vec![]);
}

#[test]
fn gate_checks_report_what_the_gate_cannot_read() {
    let cases = [
        // A tool reference the gate cannot name.
        ("tool:send_email@1", "tool:send_email", "spec.tools[1].ref", IssueCode::MutableReference),
        ("tool:send_email@1", "send_email", "spec.tools[1].ref", IssueCode::MalformedReference),
        ("tool:send_email@1", "prompt:send_email@1", "spec.tools[1].ref", IssueCode::WrongReferenceKind),
        ("tool:send_email@1", "tool:lookup_ticket@2", "spec.tools[1].ref", IssueCode::DuplicateEntry),
        ("kind: AgentRelease", "kind: ToolContract", "kind", IssueCode::UnsupportedKind),
        ("apiVersion: cloakpipe.co/v1alpha1", "apiVersion: cloakpipe.co/v9", "apiVersion", IssueCode::UnsupportedApiVersion),
        ("agent: support-agent", "agent: Support Agent", "metadata.agent", IssueCode::InvalidName),
    ];
    for (from, to, path, code) in cases {
        let m = parse_str(&MINIMAL.replace(from, to), Format::Yaml).unwrap();
        let issues = m.gate_issues();
        assert!(issues.iter().any(|i| i.path == path && i.code == code), "{to:?}: {issues:?}");
    }
}

#[test]
fn gate_checks_cover_bound_policies() {
    let with_policy = |r: &str| format!("{MINIMAL}  policies:\n    - ref: {r}\n");
    let ok = format!("policy:tool-contract/support-tools@sha256:{}", "ab".repeat(32));
    assert_eq!(parse_str(&with_policy(&ok), Format::Yaml).unwrap().gate_issues(), vec![]);
    for bad in ["policy:tool-contract/support-tools", "tool-contract/support-tools@sha256:ab", "tool:support-tools@1"] {
        let issues = parse_str(&with_policy(bad), Format::Yaml).unwrap().gate_issues();
        assert!(issues.iter().any(|i| i.path == "spec.policies[0].ref"), "{bad:?}: {issues:?}");
    }
}
