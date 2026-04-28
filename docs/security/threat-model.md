# RunBrake OSS Threat Model

## Security Goal

RunBrake OSS reduces the blast radius of OpenClaw deployments by discovering risky local installs, scoring skills and plugins before trust, producing redacted evidence, and shaping metadata-first policy events for local enforcement surfaces.

RunBrake OSS does not claim guaranteed protection. A finding means an artifact needs review before trust; it is not proof of malicious intent.

## Trust Boundaries

| Boundary                    | Trusted Side             | Untrusted Or Less-Trusted Side                       | Main Risk                                                         |
| --------------------------- | ------------------------ | ---------------------------------------------------- | ----------------------------------------------------------------- |
| Local CLI to file system    | RunBrake scanner binary  | OpenClaw configs, skills, logs, and local user files | Malicious local artifacts attempt parser abuse or secret exposure |
| Scanner to remote package   | Bounded scanner intake   | User-provided remote ZIP or manifest                 | Archive traversal, oversized input, symlink abuse, parser abuse   |
| Registry scanner to public  | RunBrake registry client | Public OpenClaw/ClawHub source and metadata          | Evidence poisoning, malformed manifests, rate-limit failures      |
| Plugin adapter to local API | Metadata-first adapter   | OpenClaw runtime and install hook payloads           | Raw prompts, tool args, or package bodies leak into decisions     |
| CI action to repository     | GitHub runner workflow   | Pull-request skill/plugin contents                   | Untrusted package content poisons SARIF or workflow output        |

## Assets

- Local OpenClaw configuration and install posture.
- Skill and plugin source packages.
- Artifact hashes and manifest metadata.
- Scanner findings, severities, evidence, and remediation text.
- SARIF, Markdown, JSON, and report-pack outputs.
- Policy hook metadata and redacted argument summaries.
- Release binaries, checksums, and provenance metadata.

## Local Doctor

Risk: the local doctor reads untrusted OpenClaw configs, skill manifests, plugin manifests, logs, persistence files, and memory files. A malicious artifact could try to poison output, leak secrets through evidence strings, or hide risky persistence.

Controls:

- Treat local files as untrusted.
- Keep parsing isolated under scanner packages.
- Redact secret-like values before rendering findings.
- Test exposed gateways, broad OAuth scopes, plaintext secrets, unsafe permissions, and persistence indicators.
- Assert raw secret fixture values do not appear in console, Markdown, JSON, or SARIF.

## Skill And Plugin Scanner

Risk: the scanner reads untrusted local and remote packages before installation. A malicious package could attempt ZIP traversal, hidden Unicode spoofing, dependency lifecycle execution, prompt-injection bait, secret exposure, or noisy reports that users learn to ignore.

Controls:

- Parse OpenClaw `SKILL.md`/`skill.md`, `skill.json`, `plugin.json`, and package metadata.
- Bound remote downloads, extracted content, archive file count, and relevant-file reads.
- Reject absolute paths, parent-directory traversal, and symlink entries during ZIP extraction.
- Reject local relevant-file symlinks instead of following them.
- Hash relevant manifest and source files.
- Emit stable `RB-*` rule IDs with severity, confidence, evidence, and remediation.
- Support domain allowlists, audit-mode egress tuning, and reasoned suppressions.

## Public Registry Scanner

Risk: public registry scans read large volumes of untrusted public skill source and registry metadata. A malicious public skill could attempt parser abuse, evidence poisoning, secret-looking bait, hidden Unicode spoofing, or output paths that make reports hard to reproduce.

Controls:

- Use public read sources only.
- Record registry source URL, source commit, generated time, limits, and scanned/skipped counts.
- Redact evidence before JSON, Markdown, summary, or SARIF output.
- Honor ClawHub rate limits and `Retry-After`.
- Use stable public source URLs instead of leaking temporary local filesystem paths.
- Compare saved reports with `diff-scan-report` for scheduled monitoring.

## Policy Plugin Adapter

Risk: the OpenClaw policy-plugin adapter could leak raw prompts, tool arguments, OAuth tokens, file contents, or package bodies to a local decision service.

Controls:

- Convert hooks into metadata-first `ToolCallEvent` and `InstallEvent` records.
- Redact and truncate argument summaries.
- Reject raw payload fields in shared contract tests.
- Fail open locally when the sidecar is unavailable instead of uploading fallback data.
- Treat local sidecar policy enforcement as an explicit operator-controlled local runtime surface.

## GitHub Action And SARIF

Risk: scanner output from untrusted pull requests could leak secret-like material or make code-scanning results misleading.

Controls:

- Run static analysis only.
- Redact secret-like findings before SARIF output.
- Do not require RunBrake account credentials.
- Use checksum-verified release binaries for action execution.
- Keep SARIF upload opt-in through the workflow.

## Required Security Tests

| Surface          | Required Test                                                                                           |
| ---------------- | ------------------------------------------------------------------------------------------------------- |
| Local doctor     | Secret fixtures are redacted in every output format                                                     |
| Skill scanner    | Malicious fixtures for shell, hidden Unicode, broad OAuth, remote scripts, and dependency scripts alert |
| Remote packages  | Oversized archives, traversal paths, and symlink entries are rejected                                   |
| Registry scanner | Public source metadata is preserved and secret-like evidence is redacted                                |
| Plugin adapter   | Raw payload fields are rejected and sidecar-unavailable behavior fails open                             |
| Export tooling   | Private packages and commercial control-plane references do not appear in the public repo export        |

## Disclosure Language

Use "risk reduction," "local scanning," "policy enforcement," and "auditability." Do not promise complete protection, malware elimination, or guaranteed compliance.
