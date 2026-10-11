//! Tool contracts: argument-level rules for the tools a release may call.
//!
//! A `ToolContract` (`apiVersion: cloakpipe.co/v1alpha1`) says, per tool,
//! which arguments a call may carry and what each may hold. It is bound into
//! an Agent Release through `spec.policies` as
//! `policy:tool-contract/<name>@sha256:<digest>` ([`ToolContract::policy_ref`]),
//! so the contract is covered by the certified release hash without a
//! manifest schema change. The `tool-contract/` name prefix is what lets a
//! gate tell a contract reference from any other policy.
//!
//! The digest is `SHA-256(domain || "\n" || jcs_bytes)` over the contract
//! document exactly as written (RFC 8785, no Unicode normalisation: two
//! contracts that behave differently never share a digest), with `domain`
//! [`namespace::TOOL_CONTRACT_HASH_DOMAIN`] (the legacy `cloakpipe.dev`
//! domain for a legacy `apiVersion`).
//!
//! The constraint language is a small, deterministic subset of JSON Schema,
//! implemented here: `type`, `enum`, `const`, `minLength`/`maxLength`
//! (Unicode scalars), `pattern` (anchored full match), `minimum`/`maximum`,
//! `properties`, `required`, `additionalProperties` (a boolean, default
//! false), `minProperties`/`maxProperties`, `items`, `minItems`/`maxItems`,
//! plus `bindTo: task.<key>`: the value must equal the trusted task context's
//! value for that key. Everything fails closed: unknown keywords, duplicate
//! keys and constraints that restrict nothing are parse errors, and a keyword
//! only applies to values of its own type (a `maxLength` rejects a number).
//!
//! A violation carries a stable code and, where one applies, the contract
//! path (`/patch/stage`): never the offending value or an unknown key's name.

use crate::canonical::ReleaseHash;
use crate::manifest::Format;
use crate::namespace::{self, Namespace};
use crate::reference::{is_valid_name, RefKind, Reference};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::Path;

/// `kind` of a tool contract.
pub const KIND: &str = "ToolContract";
/// Name prefix of the `spec.policies` entry that binds a contract.
pub const POLICY_NAME_PREFIX: &str = "tool-contract/";

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("invalid tool contract: {0}")]
    Syntax(String),
    #[error("invalid tool contract: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolContract {
    pub api_version: String,
    pub kind: String,
    pub metadata: ContractMetadata,
    pub spec: ContractSpec,
    /// The document as written: what the digest covers.
    #[serde(skip)]
    raw: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractMetadata {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSpec {
    pub tools: BTreeMap<String, ToolRule>,
}

/// The rules for one tool. Arguments are closed: a call may carry only the
/// arguments listed here.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolRule {
    /// The call changes state outside the agent (operation tracking).
    #[serde(default)]
    pub side_effect: bool,
    /// The call needs a signed approval receipt.
    #[serde(default)]
    pub requires_approval: bool,
    #[serde(default)]
    pub arguments: BTreeMap<String, Constraint>,
    #[serde(default)]
    pub required: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonType {
    String,
    Integer,
    Number,
    Boolean,
    Object,
    Array,
    Null,
}

impl JsonType {
    fn matches(self, v: &Value) -> bool {
        match (self, v) {
            (JsonType::String, Value::String(_))
            | (JsonType::Number, Value::Number(_))
            | (JsonType::Boolean, Value::Bool(_))
            | (JsonType::Object, Value::Object(_))
            | (JsonType::Array, Value::Array(_))
            | (JsonType::Null, Value::Null) => true,
            (JsonType::Integer, Value::Number(n)) => {
                n.is_i64() || n.is_u64() || n.as_f64().is_some_and(|f| f.is_finite() && f.fract() == 0.0)
            }
            _ => false,
        }
    }
}

/// One value's constraint (see the module docs for the keywords).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Constraint {
    #[serde(rename = "type")]
    pub ty: Option<JsonType>,
    #[serde(rename = "enum")]
    pub one_of: Option<Vec<Value>>,
    /// `const: null` is a constraint, so presence is tracked separately from
    /// the value.
    #[serde(rename = "const", default, deserialize_with = "present")]
    pub constant: Option<Value>,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    pub pattern: Option<String>,
    pub minimum: Option<Number>,
    pub maximum: Option<Number>,
    pub properties: Option<BTreeMap<String, Constraint>>,
    pub required: Option<Vec<String>>,
    pub additional_properties: Option<bool>,
    pub min_properties: Option<u64>,
    pub max_properties: Option<u64>,
    pub items: Option<Box<Constraint>>,
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
    /// `task.<key>[.<key>...]`.
    pub bind_to: Option<String>,
    #[serde(skip)]
    regex: Option<regex::Regex>,
}

fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(d).map(Some)
}

/// Why a call breaks its contract. `code()` is stable and safe to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationCode {
    /// A required argument is absent.
    ArgumentMissing,
    /// An argument the contract does not list (its name is not reported).
    ArgumentNotAllowed,
    /// A value breaks its constraint.
    ArgumentInvalid,
    /// A `bindTo` value differs from the task context.
    ScopeMismatch,
    /// A `bindTo` needs a task context key that is not there.
    TaskContextMissing,
}

impl ViolationCode {
    pub fn code(self) -> &'static str {
        match self {
            ViolationCode::ArgumentMissing => "argument_missing",
            ViolationCode::ArgumentNotAllowed => "argument_not_allowed",
            ViolationCode::ArgumentInvalid => "argument_invalid",
            ViolationCode::ScopeMismatch => "scope_mismatch",
            ViolationCode::TaskContextMissing => "task_context_missing",
        }
    }
}

/// A contract violation: a code and, where one applies, the contract path
/// (a JSON pointer built from contract names; for an unknown argument, the
/// path of the object that holds it, `None` at the top level).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub code: ViolationCode,
    pub path: Option<String>,
}

impl Violation {
    fn at(code: ViolationCode, path: &str) -> Self {
        Violation { code, path: (!path.is_empty()).then(|| path.to_string()) }
    }
}

/// `spec.policies` entry naming a tool contract (any version).
pub fn is_tool_contract_ref(reference: &str) -> bool {
    Reference::parse(reference)
        .is_ok_and(|r| r.kind == RefKind::Policy && r.name.starts_with(POLICY_NAME_PREFIX))
}

impl ToolContract {
    pub fn parse_str(src: &str, format: Format) -> Result<Self, ContractError> {
        let syntax = |e: &dyn std::fmt::Display| ContractError::Syntax(e.to_string());
        let Strict(raw) = match format {
            Format::Json => {
                let mut d = serde_json::Deserializer::from_str(src);
                let v = Strict::deserialize(&mut d).map_err(|e| syntax(&e))?;
                d.end().map_err(|e| syntax(&e))?;
                v
            }
            Format::Yaml => serde_yaml::from_str(src).map_err(|e| syntax(&e))?,
        };
        Self::from_value(raw)
    }

    /// Parse a contract file; `.json` is JSON, anything else is YAML.
    pub fn parse_path(path: &Path) -> Result<Self, ContractError> {
        let src = std::fs::read_to_string(path).map_err(|e| ContractError::Io(path.display().to_string(), e))?;
        let format = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => Format::Json,
            _ => Format::Yaml,
        };
        Self::parse_str(&src, format)
    }

    fn from_value(raw: Value) -> Result<Self, ContractError> {
        let mut c: ToolContract =
            serde_json::from_value(raw.clone()).map_err(|e| ContractError::Syntax(e.to_string()))?;
        c.raw = raw;
        c.validate().map_err(ContractError::Invalid)?;
        Ok(c)
    }

    fn validate(&mut self) -> Result<(), String> {
        if !namespace::is_known_api_version(&self.api_version) {
            return Err(format!("unsupported apiVersion {:?}", self.api_version));
        }
        if self.kind != KIND {
            return Err(format!("kind must be {KIND:?}, got {:?}", self.kind));
        }
        if !is_valid_name(&self.metadata.name) || Reference::parse(&self.policy_ref()).is_err() {
            return Err(format!("metadata.name {:?} must match [a-z0-9][a-z0-9._/-]*", self.metadata.name));
        }
        if self.spec.tools.is_empty() {
            return Err("spec.tools is empty".into());
        }
        for (tool, rule) in &mut self.spec.tools {
            if tool.is_empty() {
                return Err("spec.tools has an empty tool name".into());
            }
            for r in &rule.required {
                if !rule.arguments.contains_key(r) {
                    return Err(format!("{tool}: required argument {r:?} is not declared"));
                }
            }
            for (name, c) in &mut rule.arguments {
                c.validate(&child("", name)).map_err(|e| format!("{tool}: {e}"))?;
            }
        }
        Ok(())
    }

    /// The contract digest (`sha256:<hex>`).
    pub fn digest(&self) -> ReleaseHash {
        let mut h = Sha256::new();
        h.update(Namespace::for_hashing(&self.api_version).tool_contract_hash_domain().as_bytes());
        h.update(b"\n");
        h.update(serde_json_canonicalizer::to_vec(&self.raw).expect("a parsed JSON value encodes"));
        ReleaseHash(h.finalize().into())
    }

    /// The `spec.policies` reference that binds this contract.
    pub fn policy_ref(&self) -> String {
        format!("policy:{POLICY_NAME_PREFIX}{}@{}", self.metadata.name, self.digest())
    }

    /// The rules for `tool`, if this contract covers it.
    pub fn rule(&self, tool: &str) -> Option<&ToolRule> {
        self.spec.tools.get(tool)
    }

    /// Check one call's raw arguments against the rules for `tool`; a tool
    /// the contract does not cover passes. `task` is the trusted task context.
    pub fn check(&self, tool: &str, arguments: Option<&Value>, task: Option<&Value>) -> Result<(), Violation> {
        match self.rule(tool) {
            Some(rule) => rule.check(arguments, task),
            None => Ok(()),
        }
    }
}

impl ToolRule {
    /// Check a call's raw arguments (absent arguments are an empty object).
    pub fn check(&self, arguments: Option<&Value>, task: Option<&Value>) -> Result<(), Violation> {
        let empty = Map::new();
        let args = match arguments {
            None => &empty,
            Some(Value::Object(o)) => o,
            Some(_) => return Err(Violation::at(ViolationCode::ArgumentInvalid, "")),
        };
        check_object(Some(&self.arguments), &self.required, false, None, None, args, "", task)
    }
}

impl Constraint {
    fn has_string_keywords(&self) -> bool {
        self.min_length.is_some() || self.max_length.is_some() || self.pattern.is_some()
    }

    fn has_number_keywords(&self) -> bool {
        self.minimum.is_some() || self.maximum.is_some()
    }

    fn has_object_keywords(&self) -> bool {
        self.properties.is_some()
            || self.required.is_some()
            || self.additional_properties.is_some()
            || self.min_properties.is_some()
            || self.max_properties.is_some()
    }

    fn has_array_keywords(&self) -> bool {
        self.items.is_some() || self.min_items.is_some() || self.max_items.is_some()
    }

    fn validate(&mut self, path: &str) -> Result<(), String> {
        let families = [
            (self.has_string_keywords(), &[JsonType::String][..]),
            (self.has_number_keywords(), &[JsonType::Number, JsonType::Integer][..]),
            (self.has_object_keywords(), &[JsonType::Object][..]),
            (self.has_array_keywords(), &[JsonType::Array][..]),
        ];
        let used: Vec<_> = families.iter().filter(|(on, _)| *on).map(|(_, types)| *types).collect();
        if used.len() > 1 {
            return Err(format!("{path}: keywords for more than one type"));
        }
        if let (Some(ty), Some(types)) = (self.ty, used.first()) {
            if !types.contains(&ty) {
                return Err(format!("{path}: keywords that do not apply to type {ty:?}"));
            }
        }
        let restricts = self.ty.is_some()
            || self.one_of.is_some()
            || self.constant.is_some()
            || self.bind_to.is_some()
            || !used.is_empty();
        if !restricts {
            return Err(format!("{path}: the constraint does not restrict the value"));
        }
        if self.one_of.as_ref().is_some_and(Vec::is_empty) {
            return Err(format!("{path}: enum is empty"));
        }
        if let Some(key) = &self.bind_to {
            let ok = key.strip_prefix("task.").is_some_and(|k| k.split('.').all(|s| !s.is_empty()));
            if !ok {
                return Err(format!("{path}: bindTo must be task.<key>, got {key:?}"));
            }
        }
        if let Some(p) = &self.pattern {
            let re = regex::Regex::new(&format!("^(?:{p})$")).map_err(|e| format!("{path}: bad pattern: {e}"))?;
            self.regex = Some(re);
        }
        if let Some(required) = &self.required {
            for r in required {
                if !self.properties.as_ref().is_some_and(|p| p.contains_key(r)) {
                    return Err(format!("{path}: required property {r:?} is not declared"));
                }
            }
        }
        if let Some(props) = &mut self.properties {
            for (name, c) in props {
                c.validate(&child(path, name))?;
            }
        }
        if let Some(items) = &mut self.items {
            items.validate(&format!("{path}/items"))?;
        }
        Ok(())
    }

    fn check(&self, v: &Value, path: &str, task: Option<&Value>) -> Result<(), Violation> {
        let invalid = || Violation::at(ViolationCode::ArgumentInvalid, path);
        if let Some(key) = &self.bind_to {
            let expected =
                task_value(task, key).ok_or_else(|| Violation::at(ViolationCode::TaskContextMissing, path))?;
            if v != expected {
                return Err(Violation::at(ViolationCode::ScopeMismatch, path));
            }
        }
        if self.ty.is_some_and(|ty| !ty.matches(v)) {
            return Err(invalid());
        }
        if self.constant.as_ref().is_some_and(|k| k != v) {
            return Err(invalid());
        }
        if self.one_of.as_ref().is_some_and(|e| !e.contains(v)) {
            return Err(invalid());
        }
        if self.has_string_keywords() {
            let Value::String(s) = v else { return Err(invalid()) };
            let n = s.chars().count() as u64;
            if self.min_length.is_some_and(|m| n < m)
                || self.max_length.is_some_and(|m| n > m)
                || self.regex.as_ref().is_some_and(|re| !re.is_match(s))
            {
                return Err(invalid());
            }
        }
        if self.has_number_keywords() {
            let Value::Number(n) = v else { return Err(invalid()) };
            // Incomparable counts as out of range.
            let below = self
                .minimum
                .as_ref()
                .is_some_and(|m| !matches!(cmp_number(n, m), Some(Ordering::Greater | Ordering::Equal)));
            let above = self
                .maximum
                .as_ref()
                .is_some_and(|m| !matches!(cmp_number(n, m), Some(Ordering::Less | Ordering::Equal)));
            if below || above {
                return Err(invalid());
            }
        }
        if self.has_object_keywords() || self.ty == Some(JsonType::Object) {
            let Value::Object(o) = v else { return Err(invalid()) };
            check_object(
                self.properties.as_ref(),
                self.required.as_deref().unwrap_or_default(),
                self.additional_properties.unwrap_or(false),
                self.min_properties,
                self.max_properties,
                o,
                path,
                task,
            )?;
        }
        if self.has_array_keywords() {
            let Value::Array(a) = v else { return Err(invalid()) };
            let n = a.len() as u64;
            if self.min_items.is_some_and(|m| n < m) || self.max_items.is_some_and(|m| n > m) {
                return Err(invalid());
            }
            if let Some(items) = &self.items {
                let items_path = format!("{path}/items");
                for x in a {
                    items.check(x, &items_path, task)?;
                }
            }
        }
        Ok(())
    }
}

/// Check an object in a fixed order, whatever the order of its keys: unknown
/// keys, then missing required ones, then counts, then each declared value in
/// name order.
#[allow(clippy::too_many_arguments)]
fn check_object(
    properties: Option<&BTreeMap<String, Constraint>>,
    required: &[String],
    additional: bool,
    min: Option<u64>,
    max: Option<u64>,
    o: &Map<String, Value>,
    path: &str,
    task: Option<&Value>,
) -> Result<(), Violation> {
    if !additional && o.keys().any(|k| !properties.is_some_and(|p| p.contains_key(k))) {
        return Err(Violation::at(ViolationCode::ArgumentNotAllowed, path));
    }
    let mut missing: Vec<&String> = required.iter().filter(|r| !o.contains_key(r.as_str())).collect();
    missing.sort();
    if let Some(r) = missing.first() {
        return Err(Violation::at(ViolationCode::ArgumentMissing, &child(path, r)));
    }
    let n = o.len() as u64;
    if min.is_some_and(|m| n < m) || max.is_some_and(|m| n > m) {
        return Err(Violation::at(ViolationCode::ArgumentInvalid, path));
    }
    for (name, c) in properties.into_iter().flatten() {
        if let Some(v) = o.get(name) {
            c.check(v, &child(path, name), task)?;
        }
    }
    Ok(())
}

/// `path` + `/name`, escaped as a JSON pointer (RFC 6901).
fn child(path: &str, name: &str) -> String {
    format!("{path}/{}", name.replace('~', "~0").replace('/', "~1"))
}

/// The task context value at `task.<a>.<b>...`.
fn task_value<'a>(task: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    let mut v = task?;
    for part in key.strip_prefix("task.")?.split('.') {
        v = v.as_object()?.get(part)?;
    }
    Some(v)
}

/// Exact for integers (any mix of signed and unsigned); IEEE otherwise.
fn cmp_number(a: &Number, b: &Number) -> Option<Ordering> {
    let int = |n: &Number| n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from));
    match (int(a), int(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

/// A JSON value read without serde_json's last-wins duplicate keys: a
/// contract with a duplicate key could mean different things to different
/// readers, so it is refused.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
        Ok(Value::Number(n.into()))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        Number::from_f64(n).map(Value::Number).ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_string()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        Strict::deserialize(d).map(|s| s.0)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some(k) = map.next_key::<String>()? {
            if out.contains_key(&k) {
                return Err(de::Error::custom(format_args!("duplicate key {k:?}")));
            }
            let Strict(v) = map.next_value()?;
            out.insert(k, v);
        }
        Ok(Value::Object(out))
    }
}
