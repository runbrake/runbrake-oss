#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
if [[ -z "$version" ]]; then
  echo "usage: scripts/build-release-artifacts.sh v0.1.1" >&2
  exit 2
fi

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="$root_dir/dist/release"
work_dir="$root_dir/.cache/release"
checksums="runbrake_${version}_checksums.txt"

rm -rf "$dist_dir" "$work_dir"
mkdir -p "$dist_dir" "$work_dir"

platforms=(
  "darwin arm64"
  "darwin amd64"
  "linux arm64"
  "linux amd64"
)

for platform in "${platforms[@]}"; do
  read -r os arch <<<"$platform"
  archive="runbrake_${version}_${os}_${arch}.tar.gz"
  build_dir="$work_dir/${os}_${arch}"
  mkdir -p "$build_dir"

  env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    GOCACHE="$root_dir/.cache/go-build" \
    GOMODCACHE="$root_dir/.cache/go-mod" \
    go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$build_dir/runbrake" ./cmd/runbrake

  cp "$root_dir/LICENSE" "$build_dir/LICENSE"
  tar -C "$build_dir" -czf "$dist_dir/$archive" runbrake LICENSE
done

(
  cd "$dist_dir"
  : >"$checksums"
  for archive in runbrake_"${version}"_*.tar.gz; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$archive" >>"$checksums"
    else
      shasum -a 256 "$archive" >>"$checksums"
    fi
  done
)

echo "release artifacts written to $dist_dir"
