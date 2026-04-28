# Changelog

## v0.1.0 - Developer Preview

Initial public RunBrake OSS scanner release.

Included:

- Local OpenClaw install doctor.
- Skill and plugin static scanner.
- Public OpenClaw/ClawHub registry scanner.
- SARIF output and GitHub Action integration.
- Report diffing and assessment bundles.
- OpenClaw policy-plugin adapter.
- Public `RB-*` rule documentation.
- Privacy, threat-model, release-integrity, and security disclosure docs.

Known limits:

- RunBrake OSS performs static defensive analysis; findings mean "needs review before trust," not "confirmed malicious."
- The commercial dashboard, team inventory, approval workflows, audit retention, private catalogs, enterprise integrations, and hosted isolation are not included in this OSS repo.
- Binary release artifacts must be installed from the checksummed release channel before external GitHub Action usage works.
