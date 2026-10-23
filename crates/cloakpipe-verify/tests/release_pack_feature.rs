//! Release audit packs are behind the `release-pack` cargo feature (off by
//! default), so the default verifier carries no certification code. Built
//! without it, `cloakpipe-verify release-pack` is a usage error that names
//! the feature.

use std::process::Command;

#[cfg(not(feature = "release-pack"))]
#[test]
fn release_pack_subcommand_names_the_missing_feature() {
    let out = Command::new(env!("CARGO_BIN_EXE_cloakpipe-verify"))
        .args(["release-pack", "pack.json", "--trust", "key.json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "usage error exit code");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("release-pack"), "{stderr}");
    assert!(stderr.contains("feature"), "{stderr}");
}

#[cfg(feature = "release-pack")]
#[test]
fn release_pack_subcommand_is_available_with_the_feature() {
    let out = Command::new(env!("CARGO_BIN_EXE_cloakpipe-verify")).args(["release-pack"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing pack path"), "{stderr}");
}
