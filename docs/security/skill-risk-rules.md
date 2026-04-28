# RunBrake Skill Risk Rules

Phase 2 skill scans emit stable `RB-SKILL-*` rule IDs. Rule IDs are part of the local report contract and should not be renamed once released.

| Rule ID                             | Severity | Detection Summary                                                                                              | Recommended Policy                   |
| ----------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| `RB-SKILL-REMOTE-SCRIPT-EXECUTION`  | Critical | Skill text or dependency scripts download a remote script and pipe it to a shell.                              | Quarantine                           |
| `RB-SKILL-DANGEROUS-INSTALL-SCRIPT` | High     | Package lifecycle scripts execute shell, network downloads, child processes, or similar install-time behavior. | Quarantine                           |
| `RB-SKILL-SHELL-EXECUTION`          | High     | Manifest permissions or skill text allow shell execution.                                                      | Deny destructive shell               |
| `RB-SKILL-PLAINTEXT-SECRET`         | High     | Skill package files contain API keys, OAuth tokens, private keys, session cookies, or database URLs.           | Quarantine                           |
| `RB-SKILL-BROAD-OAUTH`              | High     | Manifest requests broad Gmail, Drive, repository, admin, chat write, file write, or payment scopes.            | Approval required for send/write     |
| `RB-SKILL-BASE64-DECODE`            | High     | Skill text or scripts decode base64 payloads.                                                                  | Quarantine                           |
| `RB-SKILL-OBFUSCATED-COMMAND`       | High     | Skill text or scripts use `eval`, child-process execution, encoded PowerShell, or shell command wrappers.      | Quarantine                           |
| `RB-SKILL-FILE-WRITE`               | Medium   | Manifest grants file, Drive, or GitHub write permissions.                                                      | Approval required for send/write     |
| `RB-SKILL-HIDDEN-UNICODE`           | Medium   | Skill files contain bidirectional or zero-width Unicode controls.                                              | Quarantine                           |
| `RB-SKILL-PROMPT-INJECTION-BAIT`    | Medium   | Skill instructions ask the agent to ignore higher-priority instructions, exfiltrate data, or reveal secrets.   | Quarantine                           |
| `RB-SKILL-UNKNOWN-EGRESS`           | Medium   | Skill source, text, or scripts reference network domains outside the local allowlist.                          | Approval required for network egress |
| `RB-SKILL-SIMILAR-NAME-PACKAGE`     | Medium   | Dependencies are within a small edit distance of common package names, indicating typosquat risk.              | Quarantine                           |

Evidence is redacted locally before rendering console, Markdown, JSON, or SARIF output.
