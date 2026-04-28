# RunBrake OSS Release Verification

## Goal

RunBrake OSS scans supply-chain risk, so its own releases must be verifiable before users run the CLI or install the OpenClaw policy-plugin adapter.

## Release Artifacts

| Artifact               | Integrity Requirement                                        |
| ---------------------- | ------------------------------------------------------------ |
| Go CLI binary          | Tagged source, platform archive, and published SHA-256 hash  |
| Source archive         | Git tag and checksum                                         |
| TypeScript packages    | Reproducible build from tagged source and lockfile           |
| OpenClaw policy plugin | Versioned package, checksum, and contract compatibility test |
| GitHub Action          | Pinned action ref and checksum-verified CLI install          |
| Documentation bundle   | Versioned with the release tag                               |

## Verification Steps

Manual binary installs should verify checksums before execution:

```bash
curl -fsSLO https://github.com/runbrake/runbrake-oss/releases/download/v0.1.0/runbrake_v0.1.0_darwin_arm64.tar.gz
curl -fsSLO https://github.com/runbrake/runbrake-oss/releases/download/v0.1.0/runbrake_v0.1.0_checksums.txt
grep " runbrake_v0.1.0_darwin_arm64.tar.gz$" runbrake_v0.1.0_checksums.txt | shasum -a 256 -c -
tar -xzf runbrake_v0.1.0_darwin_arm64.tar.gz
./runbrake doctor --path ~/.openclaw
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
```

The CI gate checks formatting, TypeScript lint, Go vet, schema compatibility, TypeScript tests, Go tests, TypeScript build, Go build, and scanner binary build output.
