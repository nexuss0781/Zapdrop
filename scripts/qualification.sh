#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${ZAPDROP_SWARM_V2_DIRECT:-}" == "1" || "${ZAPDROP_SWARM_V2_DIRECT:-}" == "true" || "${ZAPDROP_SWARM_V2_DIRECT:-}" == "TRUE" ]]; then
  echo "Refusing qualification with experimental v2 direct transfer enabled in the environment." >&2
  exit 2
fi

if ! command -v cargo >/dev/null 2>&1; then
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
fi

cargo fmt --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --check
cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --lib
cargo test --manifest-path apps/zapdrop-desktop/src-tauri/Cargo.toml --features swarm-v2 --lib
cargo fmt --manifest-path apps/zapdrop-companion/Cargo.toml --check
cargo test --manifest-path apps/zapdrop-companion/Cargo.toml --quiet
pnpm --dir apps/zapdrop-desktop build

git diff --check
if git status --short | grep -E '(^| )\.env|id_rsa|\.pem$|\.key$'; then
  echo "Potential credential artifact detected in the working tree." >&2
  exit 3
fi

echo "Automated qualification passed. Physical-LAN, packet-capture, Windows runtime, and independent security gates remain manual."
