# RunBrake OSS

Open-source scanner and OpenClaw policy-plugin adapter for reviewing OpenClaw installs, skills, plugins, and public registry snapshots before they run.

OpenClaw is powerful because skills and plugins can touch real tools, files, shell, credentials, and long-lived agent state. That is also the risk. RunBrake OSS gives developers a local-first way to inspect those artifacts, produce reviewable reports, and wire findings into CI.

This repository is the open-source trust wedge for RunBrake. The paid RunBrake control plane adds team inventory, continuous monitoring, approvals, audit retention, private approved catalogs, enterprise integrations, and hosted isolation.

## Evidence

RunBrake scanned a pinned snapshot of the public OpenClaw skills repository and found:

| Signal                       |    Count |
| ---------------------------- | -------: |
| Public OpenClaw skills       | `45,014` |
| Review-worthy skills         | `30,778` |
| Remote-script execution      |  `1,604` |
| Shell-execution signals      |  `7,234` |
| Obfuscated-command signals   |  `3,220` |
| Plaintext secret-like values |    `949` |

Read the full report: [OpenClaw Public Skills Risk Report](docs/security/openclaw-public-skills-risk-report-2026-04-28.md).

This is static defensive analysis. A finding means "needs review before trust," not "confirmed malicious."

## Quick Start

Install the published binary with Homebrew:

```bash
brew install runbrake/tap/runbrake
runbrake
```

Or build from source:

```bash
pnpm install
pnpm run ci:check
go build -o .cache/bin/runbrake ./cmd/runbrake
```

Then scan an OpenClaw install or skill:

```bash
runbrake doctor --path ~/.openclaw
runbrake scan-skill ./skills/my-skill
runbrake assess --path ~/.openclaw
```

## What It Scans

- Local OpenClaw install posture.
- OpenClaw skills and plugin packages.
- Local folders where skills/plugins can be dropped manually.
- Public OpenClaw/ClawHub registry snapshots.
- Dependency manifests and optional OSV/GHSA vulnerability enrichment.

## Commands

```bash
runbrake doctor --path ~/.openclaw
runbrake export-report --format markdown --path ~/.openclaw
runbrake scan-skill ./skills/my-skill
runbrake scan-skills ./skills
runbrake assess --path ~/.openclaw --format markdown --output runbrake-assessment.md
runbrake watch-openclaw --once --path ~/.openclaw
runbrake scan-registry openclaw --source github --limit 100 --format summary
runbrake diff-scan-report --baseline previous.json --current current.json
```

Reports are available as console, Markdown, JSON, and SARIF depending on the command.

## Rule IDs

RunBrake emits stable `RB-*` rule IDs. Examples:

| Rule ID                            | Severity | Meaning                                                    |
| ---------------------------------- | -------- | ---------------------------------------------------------- |
| `RB-SKILL-REMOTE-SCRIPT-EXECUTION` | Critical | Skill downloads a remote script and pipes it to a shell.   |
| `RB-SKILL-SHELL-EXECUTION`         | High     | Skill can execute shell commands or documents shell usage. |
| `RB-SKILL-PLAINTEXT-SECRET`        | High     | Skill package contains secret-looking material.            |
| `RB-SKILL-UNKNOWN-EGRESS`          | Medium   | Skill references domains outside the local allowlist.      |

See [Skill Risk Rules](docs/security/skill-risk-rules.md) for the full rule table.

## GitHub Action And SARIF

Use the scanner in CI and upload SARIF to GitHub code scanning:

```yaml
name: RunBrake Skill Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  runbrake:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: runbrake/runbrake-oss/.github/actions/runbrake-skill-scan@v0.1.0
        with:
          path: .
          version: v0.1.0
          upload-sarif: "true"
```

See [the complete workflow example](docs/examples/github-action-skill-scan.yml).

## Privacy Model

RunBrake OSS is local-first:

- Scanner reports are generated locally by default.
- Secret-looking evidence is redacted before console, Markdown, JSON, or SARIF rendering.
- Remote package scans are bounded by size, file-count, timeout, and archive-expansion limits.
- Static registry scans do not execute public skills or contact third-party services referenced by skills.
- The OpenClaw policy-plugin adapter uses metadata-first event shapes and redacted argument summaries.

See [Privacy Model](docs/security/privacy-model.md) and [Threat Model](docs/security/threat-model.md).

## Included In This Repo

- Local OpenClaw posture scanner.
- Skill and plugin static scanner.
- Public OpenClaw/ClawHub registry scanner.
- Report diffing and assessment bundles.
- SARIF and GitHub Action integration.
- OpenClaw policy-plugin adapter.
- Public `RB-*` rules and security docs.
- Example vulnerable skill fixtures.

## Commercial RunBrake Control Plane

The hosted dashboard, team inventory, approval workflows, audit retention, private approved-skill catalog, enterprise integrations, and hosted isolation features are part of the commercial RunBrake control plane.

The split is intentional: this repo should be inspectable and useful on its own, while teams that need continuous governance can adopt the paid product.

## Development

```bash
pnpm install
pnpm run ci:check
```

## Documentation

- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)
- [v0.1.0 release note](docs/releases/v0.1.0.md)
- [Release verification](docs/security/release-integrity.md)

## Security

Please do not publish exploitable scanner bypasses or secret-leak issues before coordination. See [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, parser hardening, fixture improvements, and rule-quality improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
