# Changelog

## v0.1.2 - Agent Session Receipts

- Add privacy-safe receipt summaries for local policy, install, and runtime-observation responses.
- Add visible OpenClaw and Hermes session notices for startup, fail-open, install, and important runtime policy outcomes.
- Include the local sidecar, local policy engine, install guard, and local audit signer in the free/open-core boundary.
- Ship the OpenClaw `runbrake-security` skill and expand the Hermes `/runbrake-security` skill so users can ask their agent for status, recent receipts, scans, watcher checks, setup, and enforcement guidance.
- Add watcher digest summaries for skills and plugins added outside supported install hooks.
- Keep receipt verbosity local with `RUNBRAKE_RECEIPTS=quiet`, `all`, or `off`.

## v0.1.1 - Scanner Evidence Hardening

- Add metadata-only runtime observation contracts for the OpenClaw policy adapter.
- Add constructed-egress and broader provider-token scanner coverage.
- Add local `scan-skill` / `scan-skills` dependency extraction and OSV vulnerability enrichment.
- Add OpenClaw skill precedence, agent allowlist, and plugin diagnostics evidence to `doctor`.

## v0.1.0 - Developer Preview

Initial public RunBrake OSS scanner release.

Included:

- Local OpenClaw install doctor.
- Skill and plugin static scanner.
- Public OpenClaw/ClawHub registry scanner.
- SARIF output and GitHub Action integration.
- Report diffing and assessment bundles.
- Local sidecar, local policy decisions, local receipts, and local signed audit events.
- OpenClaw policy-plugin adapter.
- Public `RB-*` rule documentation.
- Privacy, threat-model, release-integrity, and security disclosure docs.

Known limits:

- RunBrake OSS performs static defensive analysis; findings mean "needs review before trust," not "confirmed malicious."
- The hosted dashboard, team inventory, hosted approval workflows, retained audit history, private catalogs, enterprise integrations, and hosted isolation are not included in this OSS repo.
- Binary release artifacts must be installed from the checksummed release channel before external GitHub Action usage works.
