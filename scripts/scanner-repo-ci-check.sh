#!/usr/bin/env bash
set -euo pipefail

mkdir -p .cache/go-build .cache/go-mod .cache/bin

pnpm run format:check
pnpm run lint
pnpm run schema:check
pnpm run test
pnpm run build
GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/go-mod go test ./...
GOCACHE=$PWD/.cache/go-build GOMODCACHE=$PWD/.cache/go-mod go build -o .cache/bin/runbrake ./cmd/runbrake
