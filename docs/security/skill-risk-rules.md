# RunBrake Skill Risk Rules

Scanner releases emit stable `RB-SKILL-*` rule IDs. Rule IDs are part of the local report contract and should not be renamed once released.

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
| `RB-SKILL-CONSTRUCTED-EGRESS`       | Medium   | Skill source or scripts dynamically assemble or decode network destinations.                                   | Approval required for network egress |
| `RB-SKILL-VULNERABLE-DEPENDENCY`    | High     | Local dependency or lockfile coordinates match OSV advisory data.                                              | Quarantine                           |
| `RB-SKILL-SIMILAR-NAME-PACKAGE`     | Medium   | Dependencies are within a small edit distance of common package names, indicating typosquat risk.              | Quarantine                           |
| `RB-HERMES-INLINE-SHELL`            | Medium   | Hermes skill metadata or content declares inline shell snippets.                                               | Approval required for terminal       |
| `RB-HERMES-PLUGIN-HOOK`             | High     | Hermes plugin registers runtime hooks such as `pre_tool_call`.                                                 | Review plugin hook policy            |
| `RB-HERMES-TERMINAL-REQUIRED`       | Low      | Hermes skill or plugin declares required terminal access.                                                      | Approval required for terminal       |
| `RB-HERMES-REQUIRED-SECRET`         | Medium   | Hermes skill or plugin declares required secrets or credential files.                                          | Approval required for secret access  |

Evidence is redacted locally before rendering console, Markdown, JSON, or SARIF output.

Hermes skill findings are static review signals. They are not proof of maliciousness, and the Hermes convenience skill is not an enforcement boundary. Runtime blocking depends on the Hermes policy plugin calling the local sidecar through `pre_tool_call` and receiving a blocking terminal policy decision.
