#!/usr/bin/env bash
# The gate's runtime dependency tree must not contain the certification
# pipeline. Each crate below is checked with its default features, normal
# (non-dev, non-build) edges only: `cargo tree -p <crate> -e normal`.
#
# cloakpipe-mcp (the gate itself) verifies certifications only when built
# with its legacy `certification` feature, which is off by default.
set -euo pipefail

forbidden="cloakpipe-cert"
crates=(cloakpipe-mcp cloakpipe-receipt cloakpipe-verify cloakpipe-anchor cloakpipe-ledger)

status=0
for crate in "${crates[@]}"; do
  # A failing `cargo tree` (unknown crate, resolve error) fails the check.
  tree=$(cargo tree -q -p "$crate" -e normal --prefix none)
  if grep -q "^${forbidden} " <<<"$tree"; then
    echo "FAIL: $crate depends on $forbidden:"
    cargo tree -q -p "$crate" -e normal -i "$forbidden" || true
    status=1
  else
    echo "ok: $crate has no $forbidden in its normal dependency tree"
  fi
done
exit "$status"
