# RunBrake OSS

Open-source scanner and local policy adapters for reviewing OpenClaw and Hermes installs, skills, plugins, and public registry snapshots before they run.

OpenClaw and Hermes are powerful because skills and plugins can touch real tools, files, shell, credentials, and long-lived agent state. That is also the risk. RunBrake OSS gives developers a local-first way to inspect those artifacts, produce reviewable reports, and wire findings into CI.

This repository is the open-source trust wedge for RunBrake. The paid RunBrake control plane adds team inventory, continuous monitoring, approvals, audit retention, private approved catalogs, enterprise integrations, and hosted isolation.

## Evidence

RunBrake scanned pinned snapshots of public OpenClaw and Hermes skill ecosystems.

| Signal                       |    Count |
| ---------------------------- | -------: |
| Public OpenClaw skills       | `45,014` |
| Review-worthy skills         | `30,778` |
| Remote-script execution      |  `1,604` |
| Shell-execution signals      |  `7,234` |
| Obfuscated-command signals   |  `3,220` |
| Plaintext secret-like values |    `949` |

Read the full report: [OpenClaw Public Skills Risk Report](docs/security/openclaw-public-skills-risk-report-2026-04-28.md).

RunBrake also scanned the official Hermes Agent repository at commit `9be3ab1a5b8ab4990b284c0a0e46ed9ae6d9fc64` and found:

| Signal                  | Count |
| ----------------------- | ----: |
| Hermes skills scanned   | `144` |
| Review-worthy skills    | `112` |
| Remote-script execution |  `14` |
| Shell-execution signals |  `36` |
| Unknown-egress signals  | `102` |

Read the full report: [Hermes Skills Risk Report](docs/security/hermes-skills-risk-report-2026-04-29.md).

This is static defensive analysis. A finding means "needs review before trust," not "confirmed malicious."

## Quick Start

Install the RunBrake CLI with the same Homebrew tap for OpenClaw and Hermes:

```bash
brew update
brew install runbrake/tap/runbrake
runbrake doctor --path ~/.openclaw
runbrake doctor --ecosystem hermes --path ~/.hermes
```

Hermes does not require a separate Homebrew package. The tap installs the shared `runbrake` CLI; runtime/session receipts in Hermes require copying and enabling the Hermes adapter and `runbrake-security` skill in the Hermes home.

For source checkout development:

```bash
pnpm install
pnpm run ci:check
go build -o .cache/bin/runbrake ./cmd/runbrake

runbrake doctor --path ~/.openclaw
runbrake doctor --ecosystem hermes --path ~/.hermes
runbrake scan-skill ./skills/my-skill
runbrake scan-skills --ecosystem hermes ~/.hermes/skills
runbrake assess --path ~/.openclaw
runbrake assess --ecosystem hermes --path ~/.hermes
```

## What It Scans

- Local OpenClaw install posture.
- Local Hermes install posture.
- OpenClaw and Hermes skills and plugin packages.
- Local folders where skills/plugins can be dropped manually.
- Public OpenClaw/ClawHub and Hermes registry snapshots.
- Dependency manifests and optional OSV/GHSA vulnerability enrichment.

## Commands

```bash
runbrake doctor --path ~/.openclaw
runbrake export-report --format markdown --path ~/.openclaw
runbrake scan-skill ./skills/my-skill
runbrake scan-skills ./skills
runbrake scan-skill --dependency-scan --vuln osv --cache-dir .cache/runbrake/enrichment ./skills/my-skill
runbrake assess --path ~/.openclaw --format markdown --output runbrake-assessment.md
runbrake watch-openclaw --once --path ~/.openclaw
runbrake doctor --ecosystem hermes --path ~/.hermes
runbrake scan-skills --ecosystem hermes ~/.hermes/skills
runbrake watch-hermes --once --path ~/.hermes
runbrake assess --ecosystem hermes --path ~/.hermes --format markdown --output runbrake-hermes-assessment.md
runbrake scan-registry openclaw --source github --limit 100 --format summary
runbrake scan-registry hermes --source github --repo https://github.com/NousResearch/hermes-agent.git
runbrake diff-scan-report --baseline previous.json --current current.json
```

Reports are available as console, Markdown, JSON, and SARIF depending on the command.

Local skill scans can use the same dependency and OSV enrichment path as registry scans. `--dependency-scan --vuln osv` extracts supported dependency manifests and lockfiles, emits `RB-SKILL-VULNERABLE-DEPENDENCY`, and includes optional `dependencies` and `vulnerabilities` arrays in JSON output. Supported sources include `package-lock.json`, `package.json` exact versions, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `go.mod`, `go.sum`, and `Cargo.lock`.

`doctor --openclaw-bin /path/to/openclaw` can import OpenClaw plugin diagnostics from `plugins list --json`, `plugins inspect <id> --json`, and `plugins doctor --json`. RunBrake flags runtime tools, hooks, or routes that exceed manifest claims, plugin doctor warnings, risky skill precedence, and missing or wildcarded agent skill allowlists.

## Rule IDs

RunBrake emits stable `RB-*` rule IDs. Examples:

| Rule ID                            | Severity | Meaning                                                     |
| ---------------------------------- | -------- | ----------------------------------------------------------- |
| `RB-SKILL-REMOTE-SCRIPT-EXECUTION` | Critical | Skill downloads a remote script and pipes it to a shell.    |
| `RB-SKILL-SHELL-EXECUTION`         | High     | Skill can execute shell commands or documents shell usage.  |
| `RB-SKILL-PLAINTEXT-SECRET`        | High     | Skill package contains secret-looking material.             |
| `RB-SKILL-UNKNOWN-EGRESS`          | Medium   | Skill references domains outside the local allowlist.       |
| `RB-SKILL-CONSTRUCTED-EGRESS`      | Medium   | Skill dynamically assembles or decodes egress destinations. |
| `RB-SKILL-VULNERABLE-DEPENDENCY`   | High     | Dependency coordinates match OSV advisory data.             |

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
      - uses: runbrake/runbrake-oss/.github/actions/runbrake-skill-scan@v0.1.2
        with:
          path: .
          version: v0.1.2
          upload-sarif: "true"
```

See [the complete workflow example](docs/examples/github-action-skill-scan.yml).

## Privacy Model

RunBrake OSS is local-first:

- Scanner reports are generated locally by default.
- Secret-looking evidence is redacted before console, Markdown, JSON, or SARIF rendering.
- Remote package scans are bounded by size, file-count, timeout, and archive-expansion limits.
- Static registry scans do not execute public skills or contact third-party services referenced by skills.
- The local sidecar, policy engine, receipts, and audit events are local-only by default.
- The OpenClaw and Hermes policy adapters use metadata-first event shapes, redacted argument summaries, and runtime-observation posts to the local RunBrake sidecar when runtime policy checks are enabled.
- Scanner, doctor, registry, watch, and assessment commands work without the sidecar. Runtime enforcement and in-session receipts are optional local adapter features; if the sidecar is unavailable, adapters fail open locally and surface that state instead of blocking by surprise.

See [Privacy Model](docs/security/privacy-model.md) and [Threat Model](docs/security/threat-model.md).

## Included In This Repo

- Local OpenClaw posture scanner.
- Skill and plugin static scanner.
- Public OpenClaw/ClawHub registry scanner.
- Public Hermes registry scanner.
- Local sidecar, local policy engine, local install/runtime decisions, local receipts, and local signed audit events.
- Report diffing and assessment bundles.
- SARIF and GitHub Action integration.
- OpenClaw policy-plugin adapter.
- Hermes policy-plugin adapter and convenience skill.
- Public `RB-*` rules and security docs.
- Example vulnerable skill fixtures.

## Commercial RunBrake Control Plane

The hosted dashboard, team inventory, recurring scans, hosted policy rollout, Slack/web approval workflows, retained audit history, private approved-skill catalog, enterprise integrations, and hosted isolation features are part of the commercial RunBrake control plane.

The split is intentional: this repo should be inspectable and useful on one machine without an account, while teams that need continuous governance and coordination can adopt the paid product.

## Development

```bash
pnpm install
pnpm run ci:check
```

## Security

Please do not publish exploitable scanner bypasses or secret-leak issues before coordination. See [SECURITY.md](SECURITY.md).

## Contributing

Bug reports, parser hardening, fixture improvements, and rule-quality improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
