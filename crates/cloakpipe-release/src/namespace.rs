//! Every CloakPipe format identifier, in one place.
//!
//! Identifiers live in the `cloakpipe.co` namespace. CloakPipe up to 0.10
//! wrote them under `cloakpipe.dev`; those objects are still read and
//! verified. Writers always emit [`Namespace::Current`]. Readers accept
//! both namespaces for a supported version and nothing else: an unknown
//! version in either namespace, or any other domain, fails closed.
//!
//! Hashes and signatures cover the identifier bytes an object was issued
//! with, so a legacy object is never rewritten on read, and its hash or
//! signing domain is the legacy one ([`Namespace::for_hashing`]). This keeps
//! every hash and signature issued before the rename valid.

/// The namespace current writers emit.
pub const NAMESPACE: &str = "cloakpipe.co";
/// The namespace of objects written by CloakPipe up to 0.10.
pub const LEGACY_NAMESPACE: &str = "cloakpipe.dev";

/// `apiVersion` of manifests, evaluation runs, certification policies and
/// release audit packs.
pub const API_VERSION: &str = "cloakpipe.co/v1alpha1";
pub const LEGACY_API_VERSION: &str = "cloakpipe.dev/v1alpha1";

/// Domain separator of the Agent Release manifest hash.
pub const AGENT_RELEASE_HASH_DOMAIN: &str = "cloakpipe.co/agent-release/v1";
pub const LEGACY_AGENT_RELEASE_HASH_DOMAIN: &str = "cloakpipe.dev/agent-release/v1";

/// Domain separator of the evaluation run hash.
pub const EVALUATION_RUN_HASH_DOMAIN: &str = "cloakpipe.co/evaluation-run/v1";
pub const LEGACY_EVALUATION_RUN_HASH_DOMAIN: &str = "cloakpipe.dev/evaluation-run/v1";

/// Domain separator of the certification policy hash.
pub const CERTIFICATION_POLICY_HASH_DOMAIN: &str = "cloakpipe.co/certification-policy/v1";
pub const LEGACY_CERTIFICATION_POLICY_HASH_DOMAIN: &str = "cloakpipe.dev/certification-policy/v1";

/// Domain separator of the tool contract digest.
pub const TOOL_CONTRACT_HASH_DOMAIN: &str = "cloakpipe.co/tool-contract/v1";
pub const LEGACY_TOOL_CONTRACT_HASH_DOMAIN: &str = "cloakpipe.dev/tool-contract/v1";

/// Domain separator of a release audit pack's signing input.
pub const RELEASE_AUDIT_PACK_SIGNING_DOMAIN: &str = "cloakpipe.co/release-audit-pack/v1alpha1";
pub const LEGACY_RELEASE_AUDIT_PACK_SIGNING_DOMAIN: &str = "cloakpipe.dev/release-audit-pack/v1alpha1";

/// in-toto `predicateType` of an Agent Release statement.
pub const AGENT_RELEASE_PREDICATE_TYPE: &str = "https://cloakpipe.co/attestations/agent-release/v1alpha1";
pub const LEGACY_AGENT_RELEASE_PREDICATE_TYPE: &str = "https://cloakpipe.dev/attestations/agent-release/v1alpha1";

/// in-toto `predicateType` of a certification attestation.
pub const CERTIFICATION_PREDICATE_TYPE: &str = "https://cloakpipe.co/attestations/certification/v1alpha1";
pub const LEGACY_CERTIFICATION_PREDICATE_TYPE: &str = "https://cloakpipe.dev/attestations/certification/v1alpha1";

/// `$id` of `schemas/agent-release.schema.json`.
pub const AGENT_RELEASE_SCHEMA_ID: &str = "https://cloakpipe.co/schemas/agent-release/v1alpha1.json";
pub const LEGACY_AGENT_RELEASE_SCHEMA_ID: &str = "https://cloakpipe.dev/schemas/agent-release/v1alpha1.json";

/// `$id` of `schemas/tool-contract.schema.json`.
pub const TOOL_CONTRACT_SCHEMA_ID: &str = "https://cloakpipe.co/schemas/tool-contract/v1alpha1.json";

/// Which namespace an identifier belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// `cloakpipe.co`: what writers emit.
    Current,
    /// `cloakpipe.dev`: accepted when reading.
    Legacy,
}

impl Namespace {
    /// Both namespaces, current first.
    pub const ALL: [Namespace; 2] = [Namespace::Current, Namespace::Legacy];

    fn pick(self, current: &'static str, legacy: &'static str) -> &'static str {
        match self {
            Namespace::Current => current,
            Namespace::Legacy => legacy,
        }
    }

    pub fn domain(self) -> &'static str {
        self.pick(NAMESPACE, LEGACY_NAMESPACE)
    }

    pub fn api_version(self) -> &'static str {
        self.pick(API_VERSION, LEGACY_API_VERSION)
    }

    pub fn agent_release_hash_domain(self) -> &'static str {
        self.pick(AGENT_RELEASE_HASH_DOMAIN, LEGACY_AGENT_RELEASE_HASH_DOMAIN)
    }

    pub fn evaluation_run_hash_domain(self) -> &'static str {
        self.pick(EVALUATION_RUN_HASH_DOMAIN, LEGACY_EVALUATION_RUN_HASH_DOMAIN)
    }

    pub fn certification_policy_hash_domain(self) -> &'static str {
        self.pick(CERTIFICATION_POLICY_HASH_DOMAIN, LEGACY_CERTIFICATION_POLICY_HASH_DOMAIN)
    }

    pub fn tool_contract_hash_domain(self) -> &'static str {
        self.pick(TOOL_CONTRACT_HASH_DOMAIN, LEGACY_TOOL_CONTRACT_HASH_DOMAIN)
    }

    pub fn release_audit_pack_signing_domain(self) -> &'static str {
        self.pick(RELEASE_AUDIT_PACK_SIGNING_DOMAIN, LEGACY_RELEASE_AUDIT_PACK_SIGNING_DOMAIN)
    }

    pub fn agent_release_predicate_type(self) -> &'static str {
        self.pick(AGENT_RELEASE_PREDICATE_TYPE, LEGACY_AGENT_RELEASE_PREDICATE_TYPE)
    }

    pub fn certification_predicate_type(self) -> &'static str {
        self.pick(CERTIFICATION_PREDICATE_TYPE, LEGACY_CERTIFICATION_PREDICATE_TYPE)
    }

    pub fn agent_release_schema_id(self) -> &'static str {
        self.pick(AGENT_RELEASE_SCHEMA_ID, LEGACY_AGENT_RELEASE_SCHEMA_ID)
    }

    /// The namespace of a supported `apiVersion`; `None` for anything else.
    pub fn of_api_version(api_version: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|ns| ns.api_version() == api_version)
    }

    /// The namespace whose hash or signing domain covers an object with this
    /// `apiVersion`: legacy objects keep the domain they were issued under,
    /// everything else (including versions that validation rejects) uses the
    /// current one.
    pub fn for_hashing(api_version: &str) -> Self {
        Self::of_api_version(api_version).unwrap_or(Namespace::Current)
    }
}

/// `apiVersion` is a supported version in either namespace.
pub fn is_known_api_version(api_version: &str) -> bool {
    Namespace::of_api_version(api_version).is_some()
}

/// `predicateType` of an Agent Release statement, in either namespace.
pub fn is_known_agent_release_predicate_type(predicate_type: &str) -> bool {
    Namespace::ALL.into_iter().any(|ns| ns.agent_release_predicate_type() == predicate_type)
}

/// `predicateType` of a certification attestation, in either namespace.
pub fn is_known_certification_predicate_type(predicate_type: &str) -> bool {
    Namespace::ALL.into_iter().any(|ns| ns.certification_predicate_type() == predicate_type)
}
