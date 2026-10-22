//! Certification commands: `cloakpipe release keygen | certify | verify-cert`
//! and `cloakpipe eval import`.
//!
//! The decision and attestation logic lives in `cloakpipe-cert`
//! (docs/CERTIFICATION.md); this module only loads inputs, calls it and
//! reports. Exit codes follow `release`: 0 ok / certified, 1 invalid input,
//! blocked or not certified, 2 usage or I/O error.

use crate::release::{load, load_valid, EXIT_INVALID, EXIT_IO, EXIT_OK};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, Subcommand};
use cloakpipe_cert::import::{
    from_braintrust, from_junit, from_langfuse, from_langfuse_experiment, ImportError, ImportMeta, ScoreRules,
};
use cloakpipe_cert::policy::{decide, DecisionInput};
use cloakpipe_cert::statement::{self, Certification, Envelope, TrustedKey, VerifyContext};
use cloakpipe_cert::{CertificationPolicy, EvaluationRun, Outcome, SuiteRef};
use cloakpipe_release::{diff, ReleaseHash, Suite};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Exit early with a code.
pub(crate) type Res<T> = Result<T, i32>;

pub(crate) fn usage(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_IO
}

pub(crate) fn invalid(msg: impl std::fmt::Display) -> i32 {
    eprintln!("error: {msg}");
    EXIT_INVALID
}

pub(crate) fn read(path: &Path) -> Res<String> {
    std::fs::read_to_string(path).map_err(|e| usage(format_args!("cannot read {}: {e}", path.display())))
}

fn write(path: &Path, content: &str) -> Res<()> {
    std::fs::write(path, content).map_err(|e| usage(format_args!("cannot write {}: {e}", path.display())))
}

fn pretty(v: &impl Serialize) -> String {
    format!("{}\n", serde_json::to_string_pretty(v).expect("serialisable"))
}

pub(crate) fn finish(code: Res<i32>) -> i32 {
    code.unwrap_or_else(|c| c)
}

/// `--release`: a `sha256:<hex>` manifest hash, or a manifest path that must
/// be certifiable and is hashed.
fn release_target(arg: &str) -> Res<String> {
    if arg.starts_with("sha256:") {
        return arg
            .parse::<ReleaseHash>()
            .map(|h| h.to_string())
            .map_err(|e| usage(format_args!("--release: {e}")));
    }
    Ok(load_valid(Path::new(arg))?.manifest_hash().to_string())
}

/// `--now`: RFC 3339, normalised to UTC with second precision; defaults to
/// the current time.
pub(crate) fn now_arg(now: Option<&str>) -> Res<DateTime<Utc>> {
    match now {
        None => Ok(Utc::now()),
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|e| usage(format_args!("--now {s:?} is not RFC 3339: {e}"))),
    }
}

pub(crate) fn rfc3339(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn snake(v: &impl Serialize) -> String {
    serde_json::to_value(v).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

// ── Keys ────────────────────────────────────────────────────────────────

/// `ed25519:` + first 16 hex chars of SHA-256(public key).
pub fn keyid(public: &[u8; 32]) -> String {
    format!("ed25519:{}", &hex::encode(Sha256::digest(public))[..16])
}

/// The `keygen` file format. Trust files may omit `privateKey`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keyid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.trim(), &mut out).ok()?;
    Some(out)
}

fn read_key_file(path: &Path) -> Res<KeyFile> {
    let src = read(path)?;
    serde_json::from_str(&src).map_err(|e| invalid(format_args!("{}: not a key file: {e}", path.display())))
}

/// Check that the file's declared `keyid` / `publicKey` match `public`.
fn check_declared(path: &Path, file: &KeyFile, public: &[u8; 32]) -> Res<String> {
    let id = keyid(public);
    if file.public_key.as_deref().is_some_and(|p| hex32(p) != Some(*public)) {
        return Err(invalid(format_args!("{}: publicKey does not match privateKey", path.display())));
    }
    if file.keyid.as_deref().is_some_and(|k| k != id) {
        return Err(invalid(format_args!("{}: keyid does not match the key (expected {id})", path.display())));
    }
    Ok(id)
}

pub(crate) fn signing_key(path: &Path) -> Res<(SigningKey, String)> {
    let file = read_key_file(path)?;
    let Some(seed) = file.private_key.as_deref().and_then(hex32) else {
        return Err(invalid(format_args!("{}: privateKey must be a 32-byte hex Ed25519 seed", path.display())));
    };
    let key = SigningKey::from_bytes(&seed);
    let id = check_declared(path, &file, &key.verifying_key().to_bytes())?;
    Ok((key, id))
}

/// A trust file: only the public part is used (derived from `privateKey`
/// when `publicKey` is absent).
pub(crate) fn trusted_key(path: &Path) -> Res<TrustedKey> {
    let file = read_key_file(path)?;
    let public = match (&file.public_key, &file.private_key) {
        (Some(p), _) => hex32(p),
        (None, Some(s)) => hex32(s).map(|s| SigningKey::from_bytes(&s).verifying_key().to_bytes()),
        (None, None) => None,
    };
    let Some(public) = public else {
        return Err(invalid(format_args!("{}: publicKey must be a 32-byte hex Ed25519 key", path.display())));
    };
    let id = check_declared(path, &KeyFile { private_key: None, ..file }, &public)?;
    Ok(TrustedKey { keyid: id, public_key: public })
}

pub(crate) fn inline_key(arg: &str) -> Res<TrustedKey> {
    let (id, public) = arg.split_once('=').ok_or_else(|| usage("--trust-key expects KEYID=PUBHEX"))?;
    let public = hex32(public).ok_or_else(|| usage(format_args!("--trust-key {id}: public key must be 64 hex chars")))?;
    Ok(TrustedKey { keyid: id.to_string(), public_key: public })
}

pub fn keygen(out: Option<&Path>) -> i32 {
    let key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let public = key.verifying_key().to_bytes();
    let mut file = KeyFile {
        keyid: Some(keyid(&public)),
        public_key: Some(hex::encode(public)),
        private_key: Some(hex::encode(key.to_bytes())),
    };
    let Some(out) = out else {
        print!("{}", pretty(&file));
        return EXIT_OK;
    };
    if let Err(e) = write_private(out, &pretty(&file)) {
        return usage(format_args!("cannot write {}: {e}", out.display()));
    }
    file.private_key = None;
    print!("{}", pretty(&file));
    EXIT_OK
}

/// Create `path` (never overwriting) readable only by the owner.
fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(content.as_bytes())
}

// ── eval import ─────────────────────────────────────────────────────────

#[derive(Subcommand)]
pub enum EvalCommands {
    /// Import JUnit XML, a Braintrust experiment or a Langfuse experiment as a native EvaluationRun
    Import(ImportArgs),
}

#[derive(Args)]
#[command(group = clap::ArgGroup::new("source").required(true).args(["junit", "braintrust", "langfuse_experiment", "langfuse_run"]))]
pub struct ImportArgs {
    /// JUnit XML report
    #[arg(long, value_name = "FILE")]
    junit: Option<PathBuf>,
    /// Braintrust experiment events: /v1/experiment/{id}/fetch output, an array of events or JSONL
    #[arg(long, value_name = "FILE")]
    braintrust: Option<PathBuf>,
    /// Langfuse experiment: GET /api/public/experiments?id=<id> output (one experiment)
    #[arg(long, value_name = "FILE", requires = "langfuse_experiment_items")]
    langfuse_experiment: Option<PathBuf>,
    /// Langfuse experiment items with scores: every page of
    /// GET /api/public/experiment-items?experimentId=<id>&fields=core,dataset,scores (a page, or an array of pages)
    #[arg(
        long,
        value_name = "FILE",
        requires = "langfuse_experiment",
        conflicts_with_all = ["junit", "braintrust", "langfuse_run", "langfuse_scores"]
    )]
    langfuse_experiment_items: Option<PathBuf>,
    /// Deprecated: Langfuse dataset run, /api/public/datasets/{dataset}/runs/{run} output (removed on
    /// Langfuse Cloud on 2026-11-16 and in self-hosted v4; use --langfuse-experiment)
    #[arg(long, value_name = "FILE", requires = "langfuse_scores")]
    langfuse_run: Option<PathBuf>,
    /// Deprecated: Langfuse scores for --langfuse-run, GET /api/public/v2/scores output (a page, or an
    /// array of every page)
    #[arg(long, value_name = "FILE", requires = "langfuse_run", conflicts_with_all = ["junit", "braintrust"])]
    langfuse_scores: Option<PathBuf>,
    /// Score-based sources: a case passes iff every score is >= this, 0..=1 [default: 0.5]
    #[arg(long, value_name = "T", value_parser = unit_interval, allow_negative_numbers = true, conflicts_with = "junit")]
    pass_threshold: Option<f64>,
    /// Score-based sources: count only this score name (repeatable); other scores are ignored and a
    /// case missing a named score is an error [default: every score counts]
    #[arg(long = "score", value_name = "NAME", conflicts_with = "junit")]
    score_names: Vec<String>,
    /// Evaluated release: a manifest path (must be certifiable) or sha256:<hex>
    #[arg(long)]
    release: String,
    /// Evaluation suite as NAME@VERSION
    #[arg(long, value_name = "NAME@VERSION")]
    suite: String,
    /// Assurance suites this run is evidence for, comma-separated
    #[arg(long, required = true, value_delimiter = ',')]
    covers: Vec<String>,
    /// Case-id pattern marking cases critical (`prefix*` or exact); repeatable
    #[arg(long, value_name = "PATTERN")]
    critical: Vec<String>,
    /// Run id (default: NAME@VERSION)
    #[arg(long)]
    run_id: Option<String>,
    /// Producing tool, e.g. pytest
    #[arg(long)]
    tool: Option<String>,
    /// Dataset reference (Langfuse default: the experiment's datasetId, or the dataset run's datasetName)
    #[arg(long)]
    dataset: Option<String>,
    /// Write the run here instead of stdout
    #[arg(long)]
    out: Option<PathBuf>,
}

/// `--pass-threshold`: a finite number within 0..=1.
fn unit_interval(s: &str) -> Result<f64, String> {
    match s.parse::<f64>() {
        Ok(t) if t.is_finite() && (0.0..=1.0).contains(&t) => Ok(t),
        _ => Err("must be a number within 0..=1".into()),
    }
}

pub fn eval(cmd: EvalCommands) -> i32 {
    match cmd {
        EvalCommands::Import(a) => finish(import(a)),
    }
}

fn import(a: ImportArgs) -> Res<i32> {
    let (name, version) = a
        .suite
        .rsplit_once('@')
        .filter(|(n, v)| !n.trim().is_empty() && !v.trim().is_empty())
        .ok_or_else(|| usage(format_args!("--suite {:?}: expected NAME@VERSION", a.suite)))?;
    let rules = ScoreRules {
        pass_threshold: a.pass_threshold.unwrap_or(ScoreRules::default().pass_threshold),
        score_names: a.score_names.clone(),
    };
    // Read every input before resolving the release: I/O errors come first.
    let source = match (&a.junit, &a.braintrust, &a.langfuse_experiment, &a.langfuse_experiment_items) {
        (Some(junit), ..) => Source::Junit(junit, read(junit)?),
        (_, Some(bt), ..) => Source::Braintrust(bt, read(bt)?),
        (_, _, Some(exp), Some(items)) => Source::LangfuseExperiment(items, read(exp)?, read(items)?),
        _ => match (&a.langfuse_run, &a.langfuse_scores) {
            (Some(run), Some(scores)) => Source::Langfuse(run, read(run)?, read(scores)?),
            _ => return Err(usage("one of --junit, --braintrust, --langfuse-experiment or --langfuse-run is required")),
        },
    };
    let release = release_target(&a.release)?;
    let meta = ImportMeta {
        run_id: a.run_id.clone().unwrap_or_else(|| a.suite.clone()),
        release,
        suite: SuiteRef { name: name.into(), version: version.into() },
        covers: a.covers,
        dataset: a.dataset,
        evaluators: Vec::new(),
        tool: a.tool,
        critical: a.critical,
    };
    let (path, result) = match &source {
        Source::Junit(path, xml) => (path, from_junit(xml, &meta)),
        Source::Braintrust(path, json) => (path, from_braintrust(json, &meta, &rules)),
        Source::LangfuseExperiment(path, exp, items) => (path, from_langfuse_experiment(exp, items, &meta, &rules)),
        Source::Langfuse(path, run, scores) => (path, from_langfuse(run, scores, &meta, &rules)),
    };
    let run = match result {
        Ok(run) => run,
        Err(ImportError::Invalid(issues)) => {
            eprintln!("error: {}: invalid evaluation run", path.display());
            for i in issues {
                eprintln!("  {i}");
            }
            return Err(EXIT_INVALID);
        }
        Err(e) => return Err(invalid(format_args!("{}: {e}", path.display()))),
    };
    match a.out {
        Some(out) => write(&out, &pretty(&run))?,
        None => print!("{}", pretty(&run)),
    }
    Ok(EXIT_OK)
}

/// The import source: its (main) file and contents.
enum Source<'a> {
    Junit(&'a PathBuf, String),
    Braintrust(&'a PathBuf, String),
    /// The items file, the experiment's contents, and the items' contents.
    LangfuseExperiment(&'a PathBuf, String, String),
    /// The run file, its contents, and the scores' contents (deprecated upstream).
    Langfuse(&'a PathBuf, String, String),
}

// ── certify ─────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct CertifyArgs {
    /// Candidate release manifest (must be certifiable)
    manifest: PathBuf,
    /// Certification policy (YAML or JSON)
    #[arg(long, value_name = "FILE")]
    policy: PathBuf,
    /// Candidate evaluation runs (native JSON, e.g. from `cloakpipe eval import`)
    #[arg(long = "run", value_name = "FILE", required = true, num_args = 1..)]
    runs: Vec<PathBuf>,
    /// Baseline release manifest; its diff to the candidate sets the required suites
    #[arg(long, value_name = "MANIFEST")]
    baseline: Option<PathBuf>,
    /// Evaluation runs of the baseline release
    #[arg(long = "baseline-run", value_name = "FILE", num_args = 1.., requires = "baseline")]
    baseline_runs: Vec<PathBuf>,
    /// Additional required assurance suites, comma-separated
    #[arg(long, value_delimiter = ',')]
    require: Vec<String>,
    /// Scope of the certification, e.g. production
    #[arg(long)]
    environment: String,
    /// Issuer identity, e.g. a CI workload
    #[arg(long)]
    issuer: String,
    /// Signing key file from `cloakpipe release keygen --out`; signs a DSSE envelope
    #[arg(long, value_name = "KEYFILE")]
    key: Option<PathBuf>,
    /// Issue time, RFC 3339 (default: now)
    #[arg(long)]
    now: Option<String>,
    /// Declared limitation of the certification; repeatable
    #[arg(long = "limitation", value_name = "TEXT")]
    limitations: Vec<String>,
    /// Certification id (unique per issuance; default: random). Pin it only
    /// for reproducible output: two issuances must never share an id.
    #[arg(long)]
    id: Option<String>,
    /// Envelope output (default: <manifest stem>.cert.dsse.json)
    #[arg(long)]
    out: Option<PathBuf>,
    /// Print {decision, envelope} as JSON
    #[arg(long)]
    json: bool,
}

fn read_policy(path: &Path) -> Res<CertificationPolicy> {
    let src = read(path)?;
    let is_json = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json"));
    let parsed = if is_json {
        serde_json::from_str(&src).map_err(|e| e.to_string())
    } else {
        serde_yaml::from_str(&src).map_err(|e| e.to_string())
    };
    parsed.map_err(|e| invalid(format_args!("{}: invalid policy: {e}", path.display())))
}

fn read_runs(paths: &[PathBuf]) -> Res<Vec<EvaluationRun>> {
    paths
        .iter()
        .map(|p| {
            let src = read(p)?;
            // Structural validation is left to `decide` (InvalidInput reasons).
            serde_json::from_str(&src).map_err(|e| invalid(format_args!("{}: invalid evaluation run: {e}", p.display())))
        })
        .collect()
}

pub fn certify(a: CertifyArgs) -> i32 {
    finish(certify_inner(a))
}

fn certify_inner(a: CertifyArgs) -> Res<i32> {
    // Usage first, so nothing is read for a malformed invocation.
    let issued = now_arg(a.now.as_deref())?;
    let mut required = BTreeSet::new();
    for s in &a.require {
        let suite: Suite = s.parse().map_err(|e| usage(format_args!("--require: {e}")))?;
        required.insert(suite.as_str().to_string());
    }

    let candidate = load_valid(&a.manifest)?;
    let release = candidate.manifest_hash().to_string();
    let policy = read_policy(&a.policy)?;
    let key = a.key.as_deref().map(signing_key).transpose()?;
    let runs = read_runs(&a.runs)?;
    let baseline_runs = read_runs(&a.baseline_runs)?;
    if let Some(b) = &a.baseline {
        let baseline = load(b)?;
        required.extend(diff(&baseline, &candidate).required_suites.iter().map(|s| s.as_str().to_string()));
    }
    if required.is_empty() {
        eprintln!(
            "warning: no required assurance suites (no --baseline diff, no --require); only the policy rules apply"
        );
    }

    let decision = decide(&DecisionInput {
        release: &release,
        required_suites: &required,
        runs: &runs,
        baseline_runs: &baseline_runs,
        policy: &policy,
    });

    let mut signed: Option<(Envelope, PathBuf)> = None;
    if let Some((key, id)) = key {
        let valid_until = chrono::Duration::try_days(i64::from(policy.validity_days))
            .and_then(|d| issued.checked_add_signed(d))
            .ok_or_else(|| {
                invalid(format_args!(
                    "{}: validityDays {} puts the certification's expiry out of range",
                    a.policy.display(),
                    policy.validity_days
                ))
            })?;
        let cert = Certification {
            id: a.id.clone().unwrap_or_else(|| format!("cert_{}", hex::encode(rand::random::<[u8; 16]>()))),
            release: release.clone(),
            agent: Some(candidate.metadata.agent.clone()),
            environment: a.environment.clone(),
            decision: decision.clone(),
            issued_at: rfc3339(issued),
            valid_until: rfc3339(valid_until),
            issuer: a.issuer.clone(),
            limitations: a.limitations.clone(),
        };
        let envelope = statement::sign(&statement::statement(&cert), &key, &id);
        let out = a.out.clone().unwrap_or_else(|| {
            let stem = a.manifest.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or("release".into());
            PathBuf::from(format!("{stem}.cert.dsse.json"))
        });
        write(&out, &pretty(&envelope))?;
        signed = Some((envelope, out));
    }

    if a.json {
        let mut v = json!({ "decision": decision });
        if let Some((env, out)) = &signed {
            v["envelope"] = serde_json::to_value(env).expect("serialisable");
            v["envelopePath"] = out.to_string_lossy().into_owned().into();
        }
        print!("{}", pretty(&v));
    } else {
        let certified = decision.outcome == Outcome::Certified;
        println!("{}", if certified { "CERTIFIED" } else { "BLOCKED" });
        println!("release   {release}  {}@{}", candidate.metadata.agent, candidate.metadata.version);
        println!("policy    {}@{}  {}", decision.policy.name, decision.policy.version, decision.policy.hash);
        let suites = &decision.required_suites;
        println!("required  {}", if suites.is_empty() { "-".into() } else { suites.join(", ") });
        println!("runs      {}", decision.runs.len());
        for r in &decision.reasons {
            let mut scope = String::new();
            if let Some(s) = &r.suite {
                scope.push_str(&format!(" [{s}]"));
            }
            if let Some(c) = &r.case {
                scope.push_str(&format!(" {c}"));
            }
            println!("  - {}{scope}: {}", snake(&r.code), r.message);
        }
        if let Some((_, out)) = &signed {
            println!("envelope  {}", out.display());
        }
    }
    Ok(if decision.outcome == Outcome::Certified { EXIT_OK } else { EXIT_INVALID })
}

// ── verify-cert ─────────────────────────────────────────────────────────

#[derive(Args)]
pub struct VerifyCertArgs {
    /// DSSE envelope from `cloakpipe release certify`
    envelope: PathBuf,
    /// Trusted key file (keygen output; only the public part is used); repeatable
    #[arg(long = "trust", value_name = "KEYFILE")]
    trust: Vec<PathBuf>,
    /// Trusted key inline as KEYID=PUBHEX; repeatable
    #[arg(long = "trust-key", value_name = "KEYID=PUBHEX")]
    trust_keys: Vec<String>,
    /// Release the certification must be about: a manifest path or sha256:<hex>
    #[arg(long)]
    release: Option<String>,
    /// Run hash the decision must cite; repeatable
    #[arg(long = "require-run", value_name = "HASH")]
    require_runs: Vec<String>,
    /// Revoked statement digest (sha256 hex of the payload); repeatable
    #[arg(long = "revoked-statement", value_name = "HEX")]
    revoked_statements: Vec<String>,
    /// Revoked signing keyid; repeatable
    #[arg(long = "revoked-key", value_name = "KEYID")]
    revoked_keys: Vec<String>,
    /// Verification time, RFC 3339 (default: now)
    #[arg(long)]
    now: Option<String>,
    /// Print the verification report as JSON
    #[arg(long)]
    json: bool,
}

pub fn verify_cert(a: VerifyCertArgs) -> i32 {
    finish(verify_inner(a))
}

fn verify_inner(a: VerifyCertArgs) -> Res<i32> {
    let now = now_arg(a.now.as_deref())?;
    let mut trusted = a.trust_keys.iter().map(|k| inline_key(k)).collect::<Res<Vec<_>>>()?;
    for p in &a.trust {
        trusted.push(trusted_key(p)?);
    }
    if trusted.is_empty() {
        eprintln!("warning: no trusted keys (--trust / --trust-key); no signature can verify");
    }
    let src = read(&a.envelope)?;
    let envelope: Envelope = serde_json::from_str(&src)
        .map_err(|e| invalid(format_args!("{}: not a DSSE envelope: {e}", a.envelope.display())))?;
    let ctx = VerifyContext {
        trusted,
        revoked_statements: a
            .revoked_statements
            .iter()
            .map(|d| d.trim().trim_start_matches("sha256:").to_ascii_lowercase())
            .collect(),
        revoked_keys: a.revoked_keys.into_iter().collect(),
        now: rfc3339(now),
        expected_release: a.release.as_deref().map(release_target).transpose()?,
        required_runs: (!a.require_runs.is_empty()).then_some(a.require_runs),
    };
    let report = statement::verify(&envelope, &ctx);

    if a.json {
        print!("{}", pretty(&report));
    } else {
        println!("{}", snake(&report.status));
        println!("outcome    {}", report.outcome.as_ref().map(snake).unwrap_or_else(|| "-".into()));
        println!("release    {}", report.release.as_deref().unwrap_or("-"));
        println!("statement  {}", report.statement_digest.as_deref().unwrap_or("-"));
        println!("certified  {}", if report.certified { "yes" } else { "no" });
        for r in &report.reasons {
            println!("  - {r}");
        }
    }
    Ok(if report.certified { EXIT_OK } else { EXIT_INVALID })
}
