---
name: runbrake-security
description: Use RunBrake to scan, report, and locally govern Hermes Agent skills and plugins.
version: 0.1.2
platforms: [macos, linux]
user-invocable: true
metadata:
  hermes:
    category: security
    requires_toolsets: [terminal]
---

# RunBrake Security For Hermes

## When to Use

Use this skill when the user asks for RunBrake status, recent RunBrake receipts, what RunBrake blocked, whether Hermes skills are safe, how to check new skills, how to set up the sidecar, how to turn enforcement on or off, or how to generate a Hermes skills risk report.

Hermes users can invoke it directly or ask naturally:

```text
/runbrake-security status
/runbrake-security recent receipts
/runbrake-security scan my Hermes skills
/runbrake-security check new skills
/runbrake-security setup sidecar
Use RunBrake to check my Hermes skills
What did RunBrake block?
```

## Procedure

1. Classify the user's intent as status, recent receipts, block history, scan skills, check new skills, sidecar setup, enforcement guidance, or report generation.
2. Keep the response privacy-safe. Do not quote raw tool arguments, prompt bodies, file contents, message bodies, memory contents, package bodies, or unredacted secrets.
3. For status, run `${HERMES_SKILL_DIR}/scripts/check-runbrake-hermes.sh` when terminal access is available. Otherwise explain the health and doctor commands from `references/hermes-runbrake-commands.md`.
4. For recent RunBrake receipts, summarize in-session receipt notices, local audit IDs, policy IDs, rule IDs, and severity only. If local receipt history is unavailable, use the watcher and assessment commands to reconstruct recent skill risk.
5. For "what did RunBrake block?", report only the receipt headline, policy ID, audit event ID, and rule IDs when available.
6. For "scan my Hermes skills", run `runbrake assess --ecosystem hermes --path ~/.hermes --format markdown --output runbrake-hermes-assessment.md`.
7. For "check new skills", run `runbrake watch-hermes --once --path ~/.hermes --format console`.
8. If the user wants runtime policy, install the plugin from `plugins/hermes-policy` into `~/.hermes/plugins/runbrake-policy`, enable it in Hermes config, and start the local sidecar with `runbrake sidecar --policy ~/.hermes/runbrake-policy.json`. If the sidecar is not running, scanner, doctor, watch, and assessment commands still work and runtime receipts fail open until a local sidecar endpoint is available.
9. For enforcement guidance, explain quiet/all/off receipt modes and the local sidecar policy file, but do not change policy unless the user explicitly asks.
10. For public ecosystem analysis, run `runbrake scan-registry hermes` and `runbrake registry-report-pack`.

## Response Shape

For status, use:

```text
RunBrake status: <active | fail-open | not configured>
Hermes home: <path>
Plugin: <installed | missing>
Sidecar: <reachable | unavailable>
Receipts: <quiet | all | off>
Next check: <one command or next action>
```

For scans, use:

```text
RunBrake checked <target>: <clean | findings | command failed>
Highest severity: <info | low | medium | high | critical>
Top rule: <rule id or none>
Report: <path if generated>
```

## Verification

Run `${HERMES_SKILL_DIR}/scripts/check-runbrake-hermes.sh` to confirm RunBrake, the Hermes plugin directory, and the sidecar URL are visible.

## Notes

This skill is an operator workflow. Runtime receipts and enforcement come from the RunBrake Hermes plugin and sidecar policy decision path. This skill does not upload receipts or create a hosted ledger.
