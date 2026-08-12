#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG=""
ASSUME_YES=0

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
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -n "$CONFIG" && -f "$CONFIG" ]] || { echo "usage: sudo ./install.sh --config config/host.json [--yes]" >&2; exit 2; }
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

export PYTHONPATH="$PROJECT_ROOT/src"
python3 -m sparklink_deployer.cli plan --config "$CONFIG" --vps

if [[ $ASSUME_YES -ne 1 ]]; then
  echo
  read -r -p "Type INSTALL to apply this exact plan: " answer
  [[ "$answer" == "INSTALL" ]] || { echo "cancelled"; exit 1; }
fi

exec python3 -m sparklink_deployer.cli install --config "$CONFIG" --yes
