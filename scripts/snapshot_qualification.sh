#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v cargo >/dev/null 2>&1 && [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi
command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }

run_test() {
  local features="$1"
  local test_name="$2"
  if [[ -n "$features" ]]; then
    cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features "$features" --lib "$test_name"
  else
    cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --lib "$test_name"
  fi
}

for test_name in \
  qualifies_large_fixture_determinism_and_bounded_metadata \
  persists_sparse_resume_ranges_for_large_file_fixture \
  metadata_page_roundtrip_rejects_invalid_exchange_data; do
  run_test "" "$test_name"
done
for test_name in \
  qualifies_large_fixture_determinism_and_bounded_metadata \
  persists_sparse_resume_ranges_for_large_file_fixture \
  metadata_page_roundtrip_rejects_invalid_exchange_data \
  secure_v2_partial_state_mismatch_resets_stale_journal \
  secure_v2_direct_file_transfer_resumes_from_persisted_sparse_journal; do
  run_test "swarm-v2" "$test_name"
done

printf '%s\n' 'Snapshot qualification passed: deterministic 512-file indexing, serialized metadata bounds, subtree reuse, sparse journal persistence, metadata-page exchange validation, stale-state reset, and v2 sparse-resume loopback passed in default and swarm-v2 builds.'
printf '%s\n' 'This remains a controlled local fixture; it does not claim 4 GiB-plus physical-file or process-termination acceptance.'
