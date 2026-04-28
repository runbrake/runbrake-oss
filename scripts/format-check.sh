#!/usr/bin/env bash
set -euo pipefail

pnpm exec prettier --check .

unformatted_go="$(gofmt -l cmd internal)"
if [[ -n "$unformatted_go" ]]; then
  echo "Go files need formatting:" >&2
  echo "$unformatted_go" >&2
  exit 1
fi
