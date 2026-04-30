# RunBrake OSS Release Verification

## Goal

RunBrake OSS scans supply-chain risk, so its own releases must be verifiable before users run the CLI or install the OpenClaw and Hermes policy adapters.

## Release Artifacts

| Artifact              | Integrity Requirement                                                            |
| --------------------- | -------------------------------------------------------------------------------- |
| Go CLI binary         | Tagged source, platform archive, and published SHA-256 hash                      |
| Source archive        | Git tag and checksum                                                             |
| TypeScript packages   | Reproducible build from tagged source and lockfile                               |
| Agent policy adapters | Versioned OpenClaw and Hermes adapter packages plus contract compatibility tests |
| GitHub Action         | Pinned action ref and checksum-verified CLI install                              |
| Documentation bundle  | Versioned with the release tag                                                   |

## Artifact Names

The release workflow and GitHub Action installer must use the same archive names:

```text
runbrake_v0.1.2_darwin_arm64.tar.gz
runbrake_v0.1.2_darwin_amd64.tar.gz
runbrake_v0.1.2_linux_arm64.tar.gz
runbrake_v0.1.2_linux_amd64.tar.gz
runbrake_v0.1.2_checksums.txt
```

The checksums file uses standard SHA-256 lines:

```text
<sha256>  <archive>
```

## Verification Steps

Manual binary installs should verify checksums before execution:

OpenClaw and Hermes use the same `runbrake` CLI package. Hermes runtime/session support is enabled by installing the Hermes plugin and `runbrake-security` skill into the Hermes home; there is no separate Hermes Homebrew formula.

```bash
curl -fsSLO https://github.com/runbrake/runbrake-oss/releases/download/v0.1.2/runbrake_v0.1.2_darwin_arm64.tar.gz
curl -fsSLO https://github.com/runbrake/runbrake-oss/releases/download/v0.1.2/runbrake_v0.1.2_checksums.txt
grep " runbrake_v0.1.2_darwin_arm64.tar.gz$" runbrake_v0.1.2_checksums.txt | shasum -a 256 -c -
tar -xzf runbrake_v0.1.2_darwin_arm64.tar.gz
./runbrake doctor --path ~/.openclaw
./runbrake doctor --ecosystem hermes --path ~/.hermes
```

Do not use `curl | sh` as the recommended install path.

## Provenance

Each release should record:

- Git tag
- Commit SHA
- Go version
- Node and pnpm versions
- Lockfile hash
- Test command evidence
- Platform archive checksums

## Local Verification

Before a release, run:

```bash
pnpm install --frozen-lockfile
pnpm run ci:check
scripts/build-release-artifacts.sh v0.1.2
```

The CI gate checks formatting, TypeScript lint, Go vet, schema compatibility, TypeScript tests, Go tests, TypeScript build, Go build, and scanner binary build output.

The release workflow runs the same CI gate, builds checksummed Linux and macOS archives, and publishes them to the tag's GitHub Release.
