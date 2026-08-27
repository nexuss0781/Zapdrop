#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${ZAPDROP_SWARM_V2_DIRECT:-}" == "1" || "${ZAPDROP_SWARM_V2_DIRECT:-}" == "true" || "${ZAPDROP_SWARM_V2_DIRECT:-}" == "TRUE" ]]; then
  echo "Refusing security qualification with experimental v2 direct transfer enabled." >&2
  exit 2
fi

if ! command -v cargo >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v cargo-audit >/dev/null 2>&1 || { echo "cargo-audit is required; install cargo-audit before running this gate" >&2; exit 1; }

run_test() {
  local features="$1"
  local test_name="$2"
  if [[ -n "$features" ]]; then
    cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features "$features" --lib "$test_name"
  else
    cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --lib "$test_name"
  fi
}

# Deterministic regression checks for parser, trust, path, frame, and scheduler boundaries.
for test_name in \
  rejects_traversal \
  resolves_conflict_by_renaming \
  retries_only_transient_network_errors \
  local_three_recipient_parent_harness; do
  run_test "" "$test_name"
done
for test_name in \
  secure_v2_frame_rejects_oversized_length_before_allocation \
  secure_v2_offer_rejects_unsafe_metadata_and_snapshot_mismatch \
  secure_v2_offer_rejects_preapproval_key_envelope \
  channel_lifetime_limits_fail_closed_at_exact_boundaries; do
  run_test "swarm-v2" "$test_name"
done

mkdir -p target/security-audit
for crate in apps/zapdrop-desktop/src-tauri apps/zapdrop-companion; do
  name="$(basename "$crate")"
  output="target/security-audit/${name}.json"
  (cd "$crate" && cargo audit --json > "$repo_root/$output")
  grep -q '"vulnerabilities":{"found":false' "$output" || {
    echo "Known vulnerability found in $crate; inspect $output" >&2
    exit 3
  }
done

printf '%s\n' 'Security qualification passed: deterministic robustness tests passed and cargo-audit reported zero known vulnerabilities.'
printf '%s\n' 'Advisory warnings remain recorded in target/security-audit/*.json; they are not silently treated as release approval.'
