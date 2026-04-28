# OpenClaw Public Skills Risk Report

RunBrake scanned a pinned snapshot of the public OpenClaw skills repository to measure ecosystem-level risk signals across skill manifests, source files, dependency manifests, and known vulnerability databases.

This is a static defensive scan. RunBrake did not execute public skills, exploit packages, or contact third-party services referenced by skills. A finding means "needs review before trust," not "confirmed malicious."

## Snapshot

| Field        | Value                                                          |
| ------------ | -------------------------------------------------------------- |
| Registry     | OpenClaw public skills                                         |
| Source       | `https://github.com/openclaw/skills.git`                       |
| Commit       | `dd56db06ce89efdfbf7e66501bd978a3bbcc8a9f`                     |
| Scan ID      | `registry-scan-a3418a4388c9`                                   |
| Generated    | `2026-04-28T06:29:01Z`                                         |
| Scanner      | RunBrake                                                       |
| Full JSON    | `/tmp/runbrake-openclaw-full-enriched-registry.json`           |
| Report pack  | `/tmp/runbrake-openclaw-public-skills-report-pack`             |
| Repo archive | `reports/registry/20260428T062901Z-registry-scan-a3418a4388c9` |

## Executive Summary

RunBrake discovered and scanned `45,014` public OpenClaw skills in the pinned snapshot. The scan found `14,226` clean skills, `30,778` skills with one or more review-worthy risk signals, and `10` scan errors. The remaining errors are malformed manifest JSON, not network failures or vulnerability database failures.

The largest signal was unknown egress: `28,549` skills referenced domains outside the scanner allowlist. That does not mean those skills are malicious. It does mean a user, team, or registry should know which domains a skill can talk about or reach before allowing it into an agent runtime.

The more urgent signals were execution-related:

- `7,234` skills showed shell execution capability or shell execution syntax.
- `3,220` skills contained obfuscated command execution markers such as child process invocation, eval-like behavior, or shell wrappers.
- `1,604` skills contained remote script execution patterns.
- `949` skills contained plaintext secret-looking material after local redaction checks.

Dependency enrichment found `110,178` dependency records. Of those, `659` skills included dependencies matched to known advisories through OSV/GHSA enrichment.

## Headline Counts

| Metric                              |   Count |
| ----------------------------------- | ------: |
| Discovered skills                   |  45,014 |
| Scanned skills                      |  45,014 |
| Clean skills                        |  14,226 |
| Risky skills                        |  30,778 |
| Scan errors                         |      10 |
| Critical static findings            |   1,604 |
| High static findings                |  11,765 |
| Medium static findings              |  29,811 |
| Dependencies extracted              | 110,178 |
| Skills with vulnerable dependencies |     659 |
| Vulnerable dependency instances     |   3,002 |
| Advisory hits                       |  11,893 |
| Unique vulnerabilities              |     964 |

## Top Static Risk Signals

| Rule                               | Severity |  Count | Meaning                                                       |
| ---------------------------------- | -------- | -----: | ------------------------------------------------------------- |
| `RB-SKILL-UNKNOWN-EGRESS`          | Medium   | 28,549 | Skill references domains outside the scanner allowlist        |
| `RB-SKILL-SHELL-EXECUTION`         | High     |  7,234 | Skill can execute shell commands or documents shell execution |
| `RB-SKILL-OBFUSCATED-COMMAND`      | High     |  3,220 | Skill contains command-obfuscation or child-process markers   |
| `RB-SKILL-REMOTE-SCRIPT-EXECUTION` | Critical |  1,604 | Skill downloads a remote script and pipes it to a shell       |
| `RB-SKILL-PLAINTEXT-SECRET`        | High     |    949 | Skill package contains secret-looking material                |
| `RB-SKILL-HIDDEN-UNICODE`          | Medium   |    546 | Skill contains hidden Unicode controls                        |
| `RB-SKILL-PROMPT-INJECTION-BAIT`   | Medium   |    463 | Skill contains prompt-injection bait phrases                  |
| `RB-SKILL-BASE64-DECODE`           | High     |    362 | Skill decodes base64 payloads before execution                |
| `RB-SKILL-SIMILAR-NAME-PACKAGE`    | Medium   |    252 | Skill depends on package names similar to popular packages    |

## Vulnerability Intelligence

RunBrake cross-referenced extracted dependency coordinates with OSV/GHSA-style advisory data. The scan found `11,893` advisory hits across `964` unique vulnerabilities.

| Severity | Advisory Hits |
| -------- | ------------: |
| Critical |           412 |
| High     |         3,947 |
| Medium   |         6,288 |
| Low      |         1,063 |
| Unknown  |           183 |

Top recurring critical advisories in this snapshot included:

| Advisory              | Ecosystem | Package           | Version  | Hits |
| --------------------- | --------- | ----------------- | -------- | ---: |
| `GHSA-c67j-w6g6-q2cm` | PyPI      | `langchain-core`  | `1.0.2`  |   41 |
| `GHSA-wvwj-cvrp-7pv5` | PyPI      | `Authlib`         | `1.6.6`  |   40 |
| `GHSA-xq3m-2v4x-88gg` | npm       | `protobufjs`      | `7.5.4`  |   36 |
| `GHSA-2w6w-674q-4c4q` | npm       | `handlebars`      | `4.7.8`  |   26 |
| `GHSA-5rq4-664w-9x2c` | npm       | `basic-ftp`       | `5.1.0`  |   16 |
| `GHSA-r275-fr43-pm7q` | npm       | `simple-git`      | `3.30.0` |   11 |
| `GHSA-m7jm-9gc2-mpf2` | npm       | `fast-xml-parser` | `5.3.4`  |   10 |
| `GHSA-xq3m-2v4x-88gg` | npm       | `protobufjs`      | `6.11.4` |    8 |

## Error Triage

The initial full registry run surfaced many scan errors caused by real-world schema variation: object-shaped `permissions`, array/object-shaped `tools`, object-shaped metadata fields, and nonstandard `package.json` fields. RunBrake was hardened to parse those safely instead of failing the whole skill.

After the hardening pass, the current pinned snapshot has `10` remaining scan errors. All 10 are malformed `skill.json` or `plugin.json` files that cannot be decoded as JSON without repair.

Remaining error slugs:

| Skill                                      | Error Class                              |
| ------------------------------------------ | ---------------------------------------- |
| `345968504/openclaw-troubleshooter`        | Invalid JSON comment or slash            |
| `agimodel/medium`                          | Unexpected end of JSON                   |
| `askjda/text-cleaner-lite`                 | Non-JSON leading bytes                   |
| `durenzidu/powpow-financing-plan-openclaw` | Invalid character after object key/value |
| `glorysunshine/openclaw-expense-tracker`   | Invalid quote after object key/value     |
| `hzheigege/math-arithmetic-orc`            | Invalid slash after array element        |
| `ingjosemendez/jose-self-improving-agent`  | Unexpected end of JSON                   |
| `jononovo/sendclaw`                        | Invalid character after object key/value |
| `kunyashaw/openclaw-newbie-faq`            | Invalid character after object key/value |
| `laomao-at/short-video-ecommerce`          | Invalid bracket after object key/value   |

## How To Read This Report

`Risky` means a skill matched at least one static policy signal or dependency vulnerability signal. Some signals are intentionally conservative. For example, unknown egress includes ordinary links to services not yet in RunBrake's allowlist, so it should be used for review and policy routing rather than treated as proof of abuse.

The highest-priority review queue should start with skills that combine multiple high-signal findings: remote script execution, shell execution, obfuscated command execution, plaintext secrets, and known vulnerable dependencies.

## Reproduction

The scan was generated with a local mirror of the official public repository and cached OSV enrichment:

```bash
/tmp/runbrake-phase2-8 scan-registry openclaw \
  --source github \
  --mirror-path .cache/runbrake/registries/openclaw-skills \
  --limit 0 \
  --workers 12 \
  --dependency-scan \
  --vuln osv \
  --cache-dir .cache/runbrake/enrichment \
  --progress \
  --progress-interval 1000 \
  --fail-on none \
  --format json \
  --output /tmp/runbrake-openclaw-full-enriched-registry.json

/tmp/runbrake-phase2-8 registry-report-pack \
  --input /tmp/runbrake-openclaw-full-enriched-registry.json \
  --output-dir /tmp/runbrake-openclaw-public-skills-report-pack \
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

1. Review skills with `RB-SKILL-REMOTE-SCRIPT-EXECUTION`, `RB-SKILL-SHELL-EXECUTION`, and `RB-SKILL-OBFUSCATED-COMMAND` before installation.
2. Add registry policy modes: quarantine, require approval, allow with egress restrictions, and allow.
3. Feed the vulnerability table into a remediation queue grouped by package and version.
4. Ask maintainers of the 10 malformed-manifest skills to repair JSON so the registry can scan them.
5. Re-run this scan on a schedule and publish diffs by commit, not just one-off totals.
