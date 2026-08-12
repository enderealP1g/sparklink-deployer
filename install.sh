#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=""
ASSUME_YES=0
NON_INTERACTIVE=0
LOCAL_SNI_REPORT=""
CANDIDATES="$PROJECT_ROOT/config/reality-sni-candidates.txt"
EFFECTIVE_CONFIG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)
      [[ $# -ge 2 ]] || { echo "--config requires a path" >&2; exit 2; }
      CONFIG="$2"
      shift 2
      ;;
    --yes)
      ASSUME_YES=1
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --local-sni-report)
      [[ $# -ge 2 ]] || { echo "--local-sni-report requires a path" >&2; exit 2; }
      LOCAL_SNI_REPORT="$2"
      shift 2
      ;;
    --sni-candidates)
      [[ $# -ge 2 ]] || { echo "--sni-candidates requires a path" >&2; exit 2; }
      CANDIDATES="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
if [[ -z "$CONFIG" ]]; then
  if [[ -f "$PROJECT_ROOT/config/host.json" ]]; then
    CONFIG="$PROJECT_ROOT/config/host.json"
  else
    CONFIG="$PROJECT_ROOT/config/host.example.json"
  fi
fi
[[ -f "$CONFIG" ]] || { echo "configuration not found: $CONFIG" >&2; exit 2; }
[[ -f "$CANDIDATES" ]] || { echo "SNI candidate list not found: $CANDIDATES" >&2; exit 2; }
[[ -z "$LOCAL_SNI_REPORT" || -f "$LOCAL_SNI_REPORT" ]] || { echo "local SNI report not found: $LOCAL_SNI_REPORT" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

export PYTHONPATH="$PROJECT_ROOT/src"

if [[ $NON_INTERACTIVE -ne 1 && -t 0 ]]; then
  EFFECTIVE_CONFIG="$(mktemp /tmp/sparklink-host.XXXXXX.json)"
  trap '[[ -z "$EFFECTIVE_CONFIG" ]] || rm -f -- "$EFFECTIVE_CONFIG"' EXIT
  prepare_args=(
    prepare-install
    --config "$CONFIG"
    --output "$EFFECTIVE_CONFIG"
    --candidates "$CANDIDATES"
    --vps-report "$PROJECT_ROOT/build/sni/vps-install.json"
  )
  if [[ -n "$LOCAL_SNI_REPORT" ]]; then
    prepare_args+=(--local-report "$LOCAL_SNI_REPORT")
  fi
  python3 -m sparklink_deployer.cli "${prepare_args[@]}"
  CONFIG="$EFFECTIVE_CONFIG"
elif [[ $NON_INTERACTIVE -ne 1 ]]; then
  echo "No interactive terminal detected; using configuration values unchanged."
fi

python3 -m sparklink_deployer.cli plan --config "$CONFIG" --vps

if [[ $ASSUME_YES -ne 1 ]]; then
  echo
  read -r -p "Type INSTALL to apply this exact plan: " answer
  [[ "$answer" == "INSTALL" ]] || { echo "cancelled"; exit 1; }
fi

python3 -m sparklink_deployer.cli install --config "$CONFIG" --yes
