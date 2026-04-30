# RunBrake OSS Privacy Model

## Goal

RunBrake OSS is local-first defensive tooling for OpenClaw and Hermes installs, skills, plugins, registry snapshots, and policy-plugin adapter events. It should produce useful security evidence without collecting raw prompts, file contents, credentials, email bodies, chat messages, or customer records by default.

## Included Surfaces

- `runbrake doctor`
- `runbrake assess`
- `runbrake scan-skill`
- `runbrake scan-skills`
- Public registry scans and report packs
- SARIF output and GitHub Action support
- OpenClaw policy-plugin adapter event shaping
- Hermes policy-plugin adapter event shaping
- Local sidecar, local policy engine, local install/runtime decisions, local receipts, and local signed audit events
- Hermes convenience skill workflow
- Agent-session receipt summaries for supported local adapters
- Public `RB-*` rule definitions
- Example fixtures and policies

The scanner, doctor, registry, watch, and assessment commands work without a local sidecar. Runtime enforcement and in-session receipts are optional local adapter surfaces that pair with the local sidecar when enabled. Hosted dashboard, team inventory, hosted approval queues, retained audit history, private approved catalogs, enterprise integrations, and hosted isolation remain commercial RunBrake control-plane scope.

## Data Handling Defaults

| Data Class           | Default Handling       | Examples                                              |
| -------------------- | ---------------------- | ----------------------------------------------------- |
| Local metadata       | Kept local             | Scanner version, command name, finding severity       |
| Package metadata     | Kept local and hashed  | Skill name, version, manifest fields, package hash    |
| Security evidence    | Redacted before output | Bind host, broad scope name, destination domain       |
| Secret material      | Redacted locally       | API keys, OAuth tokens, private keys, session cookies |
| User content         | Not collected by OSS   | Prompt bodies, email bodies, chat transcripts         |
| Registry scan output | Written by user choice | JSON, Markdown, SARIF, report packs, local archives   |
| Policy hook metadata | Metadata-first         | Tool name, skill name, redacted argument summaries    |
| Session receipts     | Local summary only     | Status, policy ID, rule IDs, audit IDs, evidence hash |
| Dependency evidence  | Metadata-first         | Package ecosystem, name, exact version, advisory ID   |

## Local Redaction

Redaction runs before findings are rendered to console, Markdown, JSON, or SARIF. Built-in redaction covers:

- API keys
- OAuth access and refresh tokens
- Private keys
- Session cookies
- Bearer tokens
- Webhook signing secrets
- Database connection strings
- Common provider tokens such as AWS, Slack, Stripe, GitHub fine-grained, npm, PyPI, JWT, and Google service-account private-key patterns

Redacted evidence should preserve enough context for review without exposing the secret value.

## Remote Input Limits

Remote skill scans are bounded by default:

- Request timeout
- Maximum download size
- Maximum extracted ZIP size
- Maximum archive file count
- Maximum relevant-file read size

Remote ZIP extraction rejects absolute paths, parent-directory traversal, and symlink entries. Local relevant-file symlinks are rejected instead of followed.

## GitHub Action And SARIF

The GitHub Action runs the scanner in the user's workflow and can upload SARIF through GitHub code scanning. It does not require RunBrake account credentials. Reports remain in the workflow unless the user explicitly uploads or stores them.

## Registry Scans

Public registry scans read public OpenClaw/ClawHub and Hermes sources. They do not execute public skills and do not contact third-party services referenced by scanned skills. Reports may include public owner handles, slugs, versions, source URLs, source commit SHAs, artifact hashes, rule IDs, severities, dependency coordinates, advisory IDs, and redacted evidence.

## Policy Plugin Adapter

The OpenClaw and Hermes policy-plugin adapters use metadata-first event shapes. Runtime and install hook payloads are converted into contract-shaped records with IDs, tool or package names, destination domains, data classifications, and optional redacted argument summaries. Runtime observations are recorded separately from policy decisions so operators can distinguish "observed tool-call metadata" from "allowed or blocked by policy." Raw package bodies, prompt transcripts, file contents, and unredacted secrets are not part of the default adapter contract.

The local sidecar evaluates those records on the user's machine and returns local decisions, receipts, and signed local audit events. It does not upload policy decisions, audit events, prompt text, package bodies, or raw tool arguments to RunBrake by default.

Agent-session receipts are privacy-safe summaries. They may include receipt IDs, surface, ecosystem, status, severity, policy ID, audit event ID, evidence hash, rule IDs, and timestamp. They must not include raw tool arguments, prompt bodies, message bodies, memory contents, file contents, package bodies, or unredacted secrets. Receipt visibility is local and controlled with `RUNBRAKE_RECEIPTS=quiet`, `RUNBRAKE_RECEIPTS=all`, or `RUNBRAKE_RECEIPTS=off`.

Hermes `pre_tool_call` events can block terminal actions only when a local sidecar policy decision says to block. The Hermes convenience skill is an operator workflow for scan/setup commands; it is not a privacy or security boundary.

## User Controls

Users can:

- Keep reports local.
- Choose console, Markdown, JSON, or SARIF output.
- Tune unknown-egress findings with allowlisted domains.
- Use suppression files with reasons and optional expiry metadata.
- Clear local caches and generated reports.
- Review package hashes and source metadata before trusting a skill.
