# Security Policy

RunBrake Scanner reviews security-sensitive OpenClaw artifacts. Please report vulnerabilities privately before publishing exploit details.

## Reporting A Vulnerability

Email security reports to `security@runbrake.dev`.

Include:

- A short description of the issue.
- Affected command, package, or rule.
- Reproduction steps.
- Impact and any suggested fix.

Do not include live secrets, production credentials, or private customer data in a report.

## Scope

In scope:

- Scanner parsing bugs that allow unsafe artifacts to bypass detection.
- Archive traversal, symlink, or resource-exhaustion issues.
- Secret-redaction failures.
- SARIF/report output that leaks raw sensitive values.
- OpenClaw policy-plugin adapter behavior that can unexpectedly allow terminal decisions.

Out of scope:

- Issues in third-party OpenClaw skills or plugins unless RunBrake Scanner mishandles them.
- Social engineering.
- Denial-of-service against public websites.

## Coordination

We aim to acknowledge reports within 3 business days and coordinate disclosure timing based on severity.
