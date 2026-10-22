//! `cloakpipe-verify` — standalone auditor CLI for CloakPipe bundles.
//!
//! ## Commands
//!
//! ```text
//! cloakpipe-verify chain   <bundle.json>   # hash chain unbroken, no seq gaps
//! cloakpipe-verify sigs    <bundle.json>   # Ed25519 batch-head signatures valid
//! cloakpipe-verify anchors <bundle.json> [--tsa-root PEM] [--rekor-key PEM]
//!                                          # anchor receipts valid offline
//! cloakpipe-verify all     <bundle.json> [--trust-key KEYID=HEX]...
//!                                          # everything; exit 0 / nonzero for CI
//! cloakpipe-verify release-pack <pack.json> --trust KEYFILE [--ledger-trust KEYFILE]
//!                                [--cert-trust KEYFILE] [--now RFC3339] [--json]
//!                                          # each trust flag takes one file; repeat it
//!                                          # a release audit pack (docs/AUDIT_PACK.md);
//!                                          # needs the `release-pack` cargo feature
//! ```
//!
//! `--trust-key` pins the signer: the manifest must be signed by one of the
//! given keys. Without it the bundle is checked against the key it carries,
//! which proves integrity but not who produced it.
//!
//! ## Why standalone
//!
//! Per the v2 plan: "If it needs internal crates, the format is
//! wrong." Evidence bundles are verified with this crate's own code — no
//! `cloakpipe-ledger`. A hostile third party can clone only this crate,
//! build it, and verify any bundle the producer emits. Release audit packs
//! (the optional `release-pack` cargo feature, off by default) additionally
//! use the two spec crates `cloakpipe-release` (manifest hash) and
//! `cloakpipe-cert` (DSSE certification verification); neither produces
//! evidence, and the release hash also has an independent Python reference
//! (`tools/release_hash_reference.py`).

use anyhow::{Context, Result};
use cloakpipe_verify::{anchor, bundle, verify};
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cloakpipe-verify: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    if cmd == "release-pack" {
        return release_pack(&args[2..]);
    }
    let path = args.get(2).cloned().unwrap_or_default();
    if path.is_empty() && cmd != "help" && cmd != "--help" && cmd != "-h" {
        anyhow::bail!("missing bundle path");
    }

    let opts = parse_opts(&args[3.min(args.len())..])?;
    if !matches!(cmd, "anchors" | "all") && (opts.tsa_root.is_some() || opts.rekor_key.is_some()) {
        anyhow::bail!("--tsa-root / --rekor-key apply only to `anchors` and `all`");
    }
    let trusted = opts.trust_keys;
    let anchor_trust = load_anchor_trust(opts.tsa_root.as_deref(), opts.rekor_key.as_deref())?;

    match cmd {
        "chain" => {
            let b = load_bundle(&path)?;
            match verify::verify_chain(&b) {
                Ok(tip) => {
                    println!(
                        "OK  {} record(s) verified; chain tip = {}",
                        b.records.len(),
                        tip
                    );
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "sigs" => {
            let b = load_bundle(&path)?;
            match verify::verify_sigs(&b) {
                Ok(n) => {
                    println!("OK  {n} batch-head signature(s) valid");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "all" => {
            let b = load_bundle(&path)?;
            // v2 bundles get full anchor + inclusion-proof checks. So does
            // any bundle once a trust input is given or receipts are present:
            // format_version is unsigned, so a lowered version must never
            // turn anchor checks off.
            let anchored = anchor_trust.tsa_roots.is_some()
                || anchor_trust.rekor_key.is_some()
                || !b.anchor_receipts.is_empty();
            if b.format_version >= 2 || anchored {
                match run_all_v2(&b, &anchor_trust).and_then(|s| {
                    let signer = signer_status(&b, &trusted)?;
                    Ok((s, signer))
                }) {
                    Ok((s, signer)) => {
                        println!(
                            "OK  records={} batch_signatures={} anchors={} inclusion_proofs={} chain_tip={} {signer}",
                            s.records, s.signatures, s.anchors, s.proofs, s.chain_tip
                        );
                        Ok(ExitCode::from(0))
                    }
                    Err(e) => {
                        println!("FAIL  {e}");
                        Ok(ExitCode::from(1))
                    }
                }
            } else {
                match verify::verify_all(&b) {
                    Ok(s) => {
                        println!(
                            "OK  records={} batch_signatures={} chain_tip={}",
                            s.records, s.signatures, s.chain_tip
                        );
                        Ok(ExitCode::from(0))
                    }
                    Err(e) => {
                        println!("FAIL  {e}");
                        Ok(ExitCode::from(1))
                    }
                }
            }
        }
        "anchors" => {
            let b = load_bundle(&path)?;
            match anchor::verify_anchors_with_trust(&b, &anchor_trust) {
                Ok(n) => {
                    println!("OK  {n} anchor receipt(s) verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "proofs" => {
            let b = load_bundle(&path)?;
            match anchor::verify_inclusion_proofs(&b) {
                Ok(n) => {
                    println!("OK  {n} inclusion proof(s) verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "manifest" => {
            let b = load_bundle(&path)?;
            match anchor::verify_manifest(&b) {
                Ok(()) => {
                    println!("OK  manifest verified");
                    Ok(ExitCode::from(0))
                }
                Err(e) => {
                    println!("FAIL  {e}");
                    Ok(ExitCode::from(1))
                }
            }
        }
        "help" | "--help" | "-h" => {
            println!("{}", USAGE);
            Ok(ExitCode::from(0))
        }
        other => anyhow::bail!("unknown command `{other}`; try `cloakpipe-verify help`"),
    }
}

/// `release-pack PACK --trust KEYFILE [--ledger-trust KEYFILE] [--cert-trust KEYFILE]
/// [--now T] [--json]`, each trust flag repeatable with one file per use.
/// Usage and I/O problems are errors (exit 2); everything about the pack's
/// content is a verification result (exit 0 or 1).
#[cfg(not(feature = "release-pack"))]
fn release_pack(_args: &[String]) -> Result<ExitCode> {
    anyhow::bail!(
        "release-pack: this cloakpipe-verify was built without the `release-pack` cargo feature \
         (rebuild with `--features release-pack`)"
    )
}

#[cfg(feature = "release-pack")]
fn release_pack(args: &[String]) -> Result<ExitCode> {
    use cloakpipe_verify::pack::{trusted_key_from_json, verify_pack_bytes, VerifyOptions, MAX_PACK_BYTES};
    use std::io::Read;
    let mut pack = None;
    let (mut trust, mut ledger_trust, mut cert_trust) = (Vec::new(), Vec::new(), Vec::new());
    let (mut now, mut json) = (None, false);
    let mut it = args.iter();
    let key_file = |path: &str| -> Result<cloakpipe_verify::pack::TrustedKey> {
        let src = std::fs::read_to_string(path).with_context(|| format!("reading key file {path}"))?;
        trusted_key_from_json(&src).map_err(|e| anyhow::anyhow!("{path}: {e}"))
    };
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--trust" => trust.push(key_file(it.next().context("--trust needs a KEYFILE")?)?),
            "--ledger-trust" => ledger_trust.push(key_file(it.next().context("--ledger-trust needs a KEYFILE")?)?),
            "--cert-trust" => cert_trust.push(key_file(it.next().context("--cert-trust needs a KEYFILE")?)?),
            "--now" => {
                let t = it.next().context("--now needs an RFC 3339 time")?;
                let ok = matches!(t.as_bytes().get(10), Some(b'T' | b't'));
                let parsed = chrono::DateTime::parse_from_rfc3339(t).ok().filter(|_| ok);
                now = Some(parsed.with_context(|| format!("--now {t:?} is not RFC 3339"))?.with_timezone(&chrono::Utc));
            }
            "--json" => json = true,
            flag if flag.starts_with("--") => anyhow::bail!("unexpected argument `{flag}`"),
            path if pack.is_none() => pack = Some(path.to_string()),
            extra => anyhow::bail!(
                "unexpected argument `{extra}` (one pack at a time; each trust flag takes one KEYFILE, repeat the flag)"
            ),
        }
    }
    let pack = pack.context("missing pack path; usage: cloakpipe-verify release-pack PACK --trust KEYFILE")?;
    if trust.is_empty() {
        anyhow::bail!("--trust KEYFILE is required: a pack proves nothing without a pinned exporter key");
    }
    let file = std::fs::File::open(&pack).with_context(|| format!("reading {pack}"))?;
    let len = file.metadata().with_context(|| format!("reading {pack}"))?.len();
    let mut bytes = Vec::new();
    file.take(MAX_PACK_BYTES + 1).read_to_end(&mut bytes).with_context(|| format!("reading {pack}"))?;
    if len > MAX_PACK_BYTES || bytes.len() as u64 > MAX_PACK_BYTES {
        anyhow::bail!("{pack} is larger than {MAX_PACK_BYTES} bytes; not read");
    }
    let opts = VerifyOptions {
        trusted: trust,
        ledger_trusted: ledger_trust,
        cert_trusted: cert_trust,
        now: now.unwrap_or_else(chrono::Utc::now),
    };
    let report = verify_pack_bytes(&bytes, &opts);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render_text());
    }
    Ok(ExitCode::from(if report.ok { 0 } else { 1 }))
}

struct Opts {
    trust_keys: std::collections::BTreeMap<String, [u8; 32]>,
    tsa_root: Option<String>,
    rekor_key: Option<String>,
}

/// `--trust-key KEYID=HEX` pairs (64 hex chars = Ed25519 public key),
/// `--tsa-root PEM` and `--rekor-key PEM` (each at most once).
fn parse_opts(rest: &[String]) -> Result<Opts> {
    let mut keys = std::collections::BTreeMap::new();
    let (mut tsa_root, mut rekor_key) = (None, None);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let slot = match arg.as_str() {
            "--trust-key" => None,
            "--tsa-root" => Some(&mut tsa_root),
            "--rekor-key" => Some(&mut rekor_key),
            _ => anyhow::bail!("unexpected argument `{arg}`"),
        };
        if let Some(slot) = slot {
            let v = it.next().with_context(|| format!("{arg} needs a PEM file"))?;
            if slot.replace(v.clone()).is_some() {
                anyhow::bail!("{arg} given twice");
            }
            continue;
        }
        let spec = it.next().context("--trust-key needs KEYID=HEX")?;
        let (id, hex_key) = spec.split_once('=').context("--trust-key needs KEYID=HEX")?;
        let bytes = hex::decode(hex_key).ok().filter(|b| b.len() == 32).context("--trust-key: HEX must be 64 hex chars")?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.insert(id.to_string(), key);
    }
    Ok(Opts { trust_keys: keys, tsa_root, rekor_key })
}

/// Trust inputs for external anchors. An unreadable or unparseable file is
/// a usage error (exit 2), never a silent skip.
fn load_anchor_trust(tsa_root: Option<&str>, rekor_key: Option<&str>) -> Result<anchor::AnchorTrust> {
    let read = |p: &str| std::fs::read(p).with_context(|| format!("reading {p}"));
    let tsa_roots = match tsa_root {
        Some(p) => Some(
            cloakpipe_verify::rfc3161::TrustedRoots::from_pem(&read(p)?).map_err(|e| anyhow::anyhow!("--tsa-root {p}: {e}"))?,
        ),
        None => None,
    };
    let rekor_key = match rekor_key {
        Some(p) => Some(
            cloakpipe_verify::rekor::RekorKey::from_pem(&read(p)?).map_err(|e| anyhow::anyhow!("--rekor-key {p}: {e}"))?,
        ),
        None => None,
    };
    Ok(anchor::AnchorTrust { tsa_roots, rekor_key })
}

/// "signer trusted" when pinned keys were given and match; an explicit
/// warning when none were given, so an unpinned pass is never mistaken for
/// proof of origin.
fn signer_status(b: &bundle::Bundle, trusted: &std::collections::BTreeMap<String, [u8; 32]>) -> Result<&'static str> {
    if b.manifest.is_none() {
        return Ok("signer=none");
    }
    if trusted.is_empty() {
        return Ok("WARNING signer not pinned (pass --trust-key to verify who signed)");
    }
    anchor::check_trusted_signer(b, trusted).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok("signer trusted")
}

fn load_bundle(path: &str) -> Result<bundle::Bundle> {
    let p = PathBuf::from(path);
    let bytes = std::fs::read(&p).with_context(|| format!("reading {path}"))?;
    let b: bundle::Bundle =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {path}"))?;
    Ok(b)
}

struct AllV2Summary {
    records: usize,
    signatures: usize,
    anchors: usize,
    proofs: usize,
    chain_tip: bundle::Hex32,
}

fn run_all_v2(b: &bundle::Bundle, trust: &anchor::AnchorTrust) -> Result<AllV2Summary, anyhow::Error> {
    let summary = verify::verify_all(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    let anchors = anchor::verify_anchors_with_trust(b, trust).map_err(|e| anyhow::anyhow!("{e}"))?;
    let proofs = anchor::verify_inclusion_proofs(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    // v3 bundles additionally require a manifest check.
    if b.format_version >= 3 {
        anchor::verify_manifest(b).map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(AllV2Summary {
        records: summary.records,
        signatures: summary.signatures,
        anchors,
        proofs,
        chain_tip: summary.chain_tip,
    })
}

const USAGE: &str = "\
cloakpipe-verify — standalone auditor for CloakPipe evidence bundles

USAGE:
  cloakpipe-verify chain    <bundle.json>
  cloakpipe-verify sigs     <bundle.json>
  cloakpipe-verify anchors  <bundle.json> [--tsa-root PEM] [--rekor-key PEM]
  cloakpipe-verify proofs   <bundle.json>
  cloakpipe-verify manifest <bundle.json>
  cloakpipe-verify all      <bundle.json> [--trust-key KEYID=HEX]... [--tsa-root PEM] [--rekor-key PEM]
  cloakpipe-verify release-pack <pack.json> --trust KEYFILE [--ledger-trust KEYFILE]
                                [--cert-trust KEYFILE] [--now RFC3339] [--json]
      Verify a release audit pack (docs/AUDIT_PACK.md). Each role has its
      own keys (release keygen files; the public part is enough): --trust
      the exporter that signed the pack, --ledger-trust the ledger signers,
      --cert-trust the certification issuers. Each flag takes one KEYFILE;
      repeat the flag for more. One key may not hold two roles. Offline;
      --now defaults to the current time; packs over 256 MiB are refused.
      Only in builds with the `release-pack` cargo feature.

TRUST INPUTS (external anchors; never read from the bundle):
  --tsa-root PEM   root certificate(s) an RFC 3161 TSA must chain to
  --rekor-key PEM  the Rekor log's public key (rekor.sigstore.dev: /api/v1/log/publicKey)
  A bundle with rfc3161/rekor receipts fails without the matching input;
  with an input, every batch head must carry that kind of anchor.

EXITS:
  0   bundle / pack verified
  1   verification failed (tamper / gap / bad signature / inconsistency)
  2   usage error / could not read bundle, pack or key file

NOTES:
  This binary has NO dependency on cloakpipe-ledger or any other
  evidence producer. Release packs (`release-pack` feature) use the spec
  crates cloakpipe-release and cloakpipe-cert for the manifest hash and
  certifications.
";