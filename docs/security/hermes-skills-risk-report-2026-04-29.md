# Hermes Skills Risk Report

RunBrake scanned a pinned snapshot of the official Hermes Agent repository to measure ecosystem-level risk signals across bundled and optional Hermes skills.

This is static defensive analysis. RunBrake did not execute Hermes skills, run helper scripts, exploit packages, or contact third-party services referenced by skills. A finding means "needs review before trust," not "confirmed malicious."

## Snapshot

| Field        | Value                                                                                |
| ------------ | ------------------------------------------------------------------------------------ |
| Registry     | Hermes Agent skills                                                                  |
| Source       | `https://github.com/NousResearch/hermes-agent.git`                                   |
| Commit       | `9be3ab1a5b8ab4990b284c0a0e46ed9ae6d9fc64`                                           |
| Scan ID      | `registry-scan-295fb923b646`                                                         |
| Generated    | `2026-04-29T19:44:47Z`                                                               |
| Scanner      | RunBrake                                                                             |
| Report pack  | `.cache/runbrake/hermes-full-report-pack-v0.1.2`                                     |
| Repo archive | `reports/registry/20260429T194447Z-registry-scan-295fb923b646/report-pack/report.md` |

## Executive Summary

RunBrake discovered and scanned `144` Hermes skills in the pinned snapshot: `85` bundled skills and `59` optional skills. The scan found `32` clean skills, `112` skills with one or more review-worthy risk signals, and `0` scan errors.

The largest signal was unknown egress: `102` skills referenced domains outside the scanner allowlist. That does not mean those skills are malicious. It means reviewers should understand which destinations a skill can reference before enabling it in a Hermes runtime.

The higher-priority signals were execution and credential related:

- `36` skills contained shell execution capability or shell execution syntax.
- `14` skills contained remote script execution patterns.
- `13` skills contained obfuscated command execution markers.
- `4` skills contained plaintext secret-looking material after local redaction checks.
- `2` skills declared required secret material.

Dependency and OSV vulnerability rows were `0` in this snapshot because the scanned Hermes `skills/` and `optional-skills/` folders did not include supported dependency manifests or lockfiles inside the skill folders.

## Headline Counts

| Metric                   | Count |
| ------------------------ | ----: |
| Discovered skills        |   144 |
| Scanned skills           |   144 |
| Bundled skills scanned   |    85 |
| Optional skills scanned  |    59 |
| Clean skills             |    32 |
| Risky skills             |   112 |
| Scan errors              |     0 |
| Critical findings        |    14 |
| High findings            |    54 |
| Medium findings          |   107 |
| Low findings             |     4 |
| Dependencies extracted   |     0 |
| Vulnerability advisories |     0 |

## Top Static Risk Signals

| Rule                               | Severity | Count | Meaning                                                |
| ---------------------------------- | -------- | ----: | ------------------------------------------------------ |
| `RB-SKILL-UNKNOWN-EGRESS`          | Medium   |   102 | Skill references domains outside the scanner allowlist |
| `RB-SKILL-SHELL-EXECUTION`         | High     |    36 | Skill can execute shell commands                       |
| `RB-SKILL-REMOTE-SCRIPT-EXECUTION` | Critical |    14 | Skill downloads a remote script and pipes it to shell  |
| `RB-SKILL-OBFUSCATED-COMMAND`      | High     |    13 | Skill contains command-obfuscation markers             |
| `RB-SKILL-PLAINTEXT-SECRET`        | High     |     4 | Skill package contains secret-looking material         |
| `RB-HERMES-TERMINAL-REQUIRED`      | Low      |     4 | Hermes artifact declares terminal access               |
| `RB-HERMES-REQUIRED-SECRET`        | Medium   |     2 | Hermes artifact declares required secret material      |
| `RB-SKILL-BASE64-DECODE`           | High     |     1 | Skill decodes base64 payloads before execution         |
| `RB-HERMES-INLINE-SHELL`           | Medium   |     1 | Hermes skill uses inline shell                         |
| `RB-SKILL-HIDDEN-UNICODE`          | Medium   |     1 | Skill contains hidden Unicode controls                 |
| `RB-SKILL-PROMPT-INJECTION-BAIT`   | Medium   |     1 | Skill contains prompt-injection bait phrases           |

## Highest-risk Hermes Skills

| Skill                                        | Display Name            | Findings | Critical | High | Medium |
| -------------------------------------------- | ----------------------- | -------: | -------: | ---: | -----: |
| `mlops/unsloth`                              | `unsloth`               |        5 |        1 |    2 |      2 |
| `mlops/axolotl`                              | `axolotl`               |        4 |        1 |    2 |      1 |
| `research/qmd`                               | `qmd`                   |        4 |        1 |    2 |      1 |
| `devops/docker-management`                   | `docker-management`     |        4 |        1 |    2 |      0 |
| `health/fitness-nutrition`                   | `fitness-nutrition`     |        4 |        1 |    1 |      2 |
| `autonomous-ai-agents/hermes-agent`          | `hermes-agent`          |        3 |        1 |    1 |      1 |
| `devops/cli`                                 | `inference-sh-cli`      |        3 |        1 |    1 |      1 |
| `mlops/huggingface-hub`                      | `huggingface-hub`       |        3 |        1 |    1 |      1 |
| `mlops/lambda-labs`                          | `lambda-labs-gpu-cloud` |        3 |        1 |    1 |      1 |
| `research/parallel-cli`                      | `parallel-cli`          |        3 |        1 |    1 |      1 |
| `social-media/xurl`                          | `xurl`                  |        3 |        1 |    1 |      1 |
| `creative/baoyu-infographic`                 | `baoyu-infographic`     |        2 |        1 |    1 |      0 |
| `data-science/jupyter-live-kernel`           | `jupyter-live-kernel`   |        2 |        1 |    1 |      0 |
| `software-development/node-inspect-debugger` | `node-inspect-debugger` |        2 |        1 |    1 |      0 |
| `security/oss-forensics`                     | `oss-forensics`         |        4 |        0 |    2 |      2 |

## How To Read This Report

`Risky` means a skill matched at least one static policy signal. Some signals are intentionally conservative. Unknown egress includes ordinary documentation links and service references that are not yet in RunBrake's allowlist, so it should be used for review and policy routing rather than treated as proof of abuse.

The highest-priority review queue should start with skills that combine remote script execution, shell execution, obfuscated command execution, plaintext secrets, and required secret material.

## Reproduction

```bash
runbrake scan-registry hermes \
  --source github \
  --mirror-path .cache/runbrake/registries/hermes-agent \
  --limit 0 \
  --workers 12 \
  --dependency-scan \
  --vuln osv \
  --cache-dir .cache/runbrake/enrichment \
  --progress \
  --fail-on none \
  --format json \
  --output /tmp/runbrake-hermes-full-registry.json

runbrake registry-report-pack \
  --input /tmp/runbrake-hermes-full-registry.json \
  --output-dir /tmp/runbrake-hermes-report-pack \
  --top-skills 50 \
  --examples 40
```

The report pack includes:

- `report.md`
- `summary.json`
- `top-skills.csv`
- `top-vulnerabilities.csv`
- `README.md`

RunBrake also saves durable repo-local copies under `reports/registry/<timestamp>-<scan-id>/` whenever registry JSON or report packs are written to temporary paths. Full registry JSON is stored as `full-registry-report.json.gz` so the evidence remains GitHub-compatible.

## Recommended Next Actions

1. Review Hermes skills with `RB-SKILL-REMOTE-SCRIPT-EXECUTION`, `RB-SKILL-SHELL-EXECUTION`, and `RB-SKILL-OBFUSCATED-COMMAND` before installation.
2. Require explicit approval before Hermes skills with terminal access execute commands.
3. Keep required secrets outside skill source control and rotate any secret-like material found in packages.
4. Re-run this scan by pinned commit and publish diffs instead of relying on one-off totals.
