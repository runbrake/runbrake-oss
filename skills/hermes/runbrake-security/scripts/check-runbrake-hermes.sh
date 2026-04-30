#!/usr/bin/env bash
set -euo pipefail

hermes_home="${HERMES_HOME:-$HOME/.hermes}"
plugin_dir="$hermes_home/plugins/runbrake-policy"
sidecar_url="${RUNBRAKE_SIDECAR_URL:-http://127.0.0.1:47838}"
receipt_mode="${RUNBRAKE_RECEIPTS:-quiet}"
runbrake_bin="${RUNBRAKE_BIN:-runbrake}"
status=0

if ! command -v "$runbrake_bin" >/dev/null; then
  echo "RunBrake status: not configured"
  echo "RunBrake CLI: missing"
  exit 1
fi
test -d "$hermes_home" || {
  echo "RunBrake status: not configured"
  echo "Hermes home: missing ($hermes_home)"
  exit 1
}

if curl -fsS "$sidecar_url/healthz" >/dev/null 2>&1; then
  sidecar_status="reachable"
  runbrake_status="active"
else
  sidecar_status="unavailable"
  runbrake_status="fail-open"
fi

if test -d "$plugin_dir"; then
  plugin_status="installed"
else
  plugin_status="missing"
  status=1
fi

echo "RunBrake status: $runbrake_status"
echo "RunBrake CLI: available ($runbrake_bin)"
echo "Hermes home: $hermes_home"
echo "Plugin: $plugin_status ($plugin_dir)"
echo "Sidecar: $sidecar_status ($sidecar_url)"
echo "Receipts: $receipt_mode"

if [[ "$plugin_status" == "missing" ]]; then
  echo "Next check: install plugins/hermes-policy into $plugin_dir"
elif [[ "$sidecar_status" == "unavailable" ]]; then
  echo "Next check: $runbrake_bin sidecar --policy \"$hermes_home/runbrake-policy.json\""
else
  echo "Next check: runbrake watch-hermes --once --path \"$hermes_home\" --format console"
fi

exit "$status"
