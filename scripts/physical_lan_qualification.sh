#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  physical_lan_qualification.sh --self-check
  physical_lan_qualification.sh --init <output-directory>
  physical_lan_qualification.sh --validate <evidence-file>

The runner never declares a physical test passed by itself. Use --init to create
an evidence form, fill each test status as PASS, FAIL, BLOCKED, or NOT_RUN, and
use --validate to check that the form is complete and uses only known statuses.
USAGE
}

fail() {
  echo "physical-LAN qualification: $*" >&2
  exit 1
}

self_check() {
  [[ -x "$0" ]] || fail "script must be executable"
  bash -n "$0"
  grep -q "status: NOT_RUN" "$0" || fail "template default must remain NOT_RUN"
  for required in "LAN-01" "LAN-02" "LAN-03" "SWARM-01" "SWARM-02" "SAFE-01"; do
    grep -q "$required" "$0" || fail "missing checklist identifier: $required"
  done
  echo "Physical-LAN qualification runner self-check passed; no hardware result was produced."
}

init_run() {
  local output_dir="$1"
  [[ -n "$output_dir" ]] || fail "an output directory is required"
  mkdir -p "$output_dir"
  local evidence="$output_dir/qualification-evidence.md"
  local run_id
  run_id="$(date -u +%Y%m%dT%H%M%SZ)"
  cat > "$evidence" <<EOF
# Zapdrop Physical-LAN Qualification Evidence

**Run ID:** $run_id
**Status:** NOT_RUN
**Product path:** v1 direct transfer by default
**Experimental path:** swarm-v2 only if explicitly enabled and recorded separately
**Internet:** must remain disconnected during these tests

> Do not change a row to PASS without recording the participating device names, operating systems, network topology, trusted fingerprints, test command or UI action, and an evidence path such as a log, screenshot, hash report, or packet-capture reference.

## Safety and setup record

| Field | Recorded value |
|---|---|
| Operator | NOT_RUN |
| Date and timezone | NOT_RUN |
| Sender device and OS | NOT_RUN |
| Receiver devices and OS versions | NOT_RUN |
| Router or hotspot topology | NOT_RUN |
| Private-network firewall profile | NOT_RUN |
| Internet disconnected | NOT_RUN |
| Trusted fingerprints verified out-of-band | NOT_RUN |
| Evidence directory | $output_dir |

## Required test matrix

| ID | Test | Status | Evidence or failure reason |
|---|---|---|---|
| LAN-01 | Two trusted PCs on a private home-router LAN discover or manually connect, approve a receive offer, and transfer a mixed file/folder fixture. | NOT_RUN | |
| LAN-02 | Two trusted PCs on a phone hotspot transfer the same fixture with no internet dependency. | NOT_RUN | |
| LAN-03 | A multicast-blocked or client-isolated network uses manual endpoint fallback; an untrusted discovered peer receives no manifest or payload. | NOT_RUN | |
| LAN-04 | Private-network firewall behavior is verified without globally disabling the firewall; only the documented private-network rule is used. | NOT_RUN | |
| SWARM-01 | Two, four, and eight trusted recipients complete mixed file/folder fan-out with bounded parallelism and correct parent/child history. | NOT_RUN | |
| SWARM-02 | A slow recipient, a rejected recipient, a transient failure, and a cancelled recipient do not corrupt or hide successful child results. | NOT_RUN | |
| SWARM-03 | Shared bandwidth cap and queue depth are recorded for a multi-recipient job; observed active count never exceeds the configured limit. | NOT_RUN | |
| SAFE-01 | Fingerprint mismatch, revoked trust, unsafe path, malformed metadata, and receiver rejection fail closed without writing outside the receive root. | NOT_RUN | |
| SAFE-02 | Sender and receiver hashes match for zero-byte, Unicode, nested-folder, duplicate-name, and large-fixture cases. | NOT_RUN | |
| OPS-01 | Sleep/wake, process interruption, cancellation, retry, and resume behavior are recorded on the supported Windows test matrix. | NOT_RUN | |
| OPS-02 | Optional swarm-v2 direct lane is tested only with its explicit feature switch; results are not combined with v1 results. | NOT_RUN | |

## Evidence rules

A **PASS** row requires reproducible evidence and no unexplained data loss. A **FAIL** row must include the first failing step and preserve the relevant logs. A **BLOCKED** row must identify the missing hardware, permission, or environment. **NOT_RUN** is the default and is not an acceptance result.

## Operator notes

Record the exact Zapdrop commit, installer or executable hash, configured scheduler values, sender/recipient names, source fixture hash, destination hash, and any firewall or VPN changes. Do not upload private files or private keys as evidence.
EOF
  echo "$evidence"
}

validate_run() {
  local evidence="$1"
  [[ -f "$evidence" ]] || fail "evidence file does not exist: $evidence"
  local required_count=0
  local id
  for id in LAN-01 LAN-02 LAN-03 LAN-04 SWARM-01 SWARM-02 SWARM-03 SAFE-01 SAFE-02 OPS-01 OPS-02; do
    grep -q "| $id |" "$evidence" || fail "missing checklist row: $id"
    required_count=$((required_count + 1))
  done
  local invalid
  invalid="$(awk -F'|' '/^\| (LAN|SWARM|SAFE|OPS)-[0-9]+ / { gsub(/[[:space:]]/, "", $4); if ($4 !~ /^(PASS|FAIL|BLOCKED|NOT_RUN)$/) print $2 ":" $4 }' "$evidence")"
  [[ -z "$invalid" ]] || fail "invalid status values: $invalid"
  local unresolved
  unresolved="$(awk -F'|' '/^\| (LAN|SWARM|SAFE|OPS)-[0-9]+ / { gsub(/[[:space:]]/, "", $4); if ($4 != "PASS") print $2 ":" $4 }' "$evidence")"
  if [[ -n "$unresolved" ]]; then
    echo "Evidence format valid for $required_count tests; unresolved rows remain:"
    printf '%s\n' "$unresolved"
    return 2
  fi
  echo "All $required_count physical-LAN checklist rows are marked PASS; review evidence manually before accepting the release."
}

case "${1:-}" in
  --self-check)
    [[ $# -eq 1 ]] || { usage; exit 2; }
    self_check
    ;;
  --init)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    init_run "$2"
    ;;
  --validate)
    [[ $# -eq 2 ]] || { usage; exit 2; }
    validate_run "$2"
    ;;
  *)
    usage
    exit 2
    ;;
esac
