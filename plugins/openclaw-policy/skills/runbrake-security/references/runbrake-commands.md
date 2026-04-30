# RunBrake Commands For OpenClaw Sessions

## Status

```bash
curl -fsS http://127.0.0.1:47838/healthz
```

```bash
runbrake doctor --path ~/.openclaw
```

Use this when the user asks for RunBrake status or sidecar state.

## Assessment Report

```bash
runbrake assess --path ~/.openclaw --format markdown --output runbrake-assessment.md
```

Use this when the user asks for a readable risk report.

## Check New Skills And Plugins

```bash
runbrake watch-openclaw --once --path ~/.openclaw --format console
```

Use this when the user asks to check new skills, changed skills, manually copied plugins, or bypasses outside the install hook.

## Start The Sidecar

Runtime policy checks are optional. Scanner, doctor, watch, and assessment commands work without a sidecar. The public RunBrake CLI includes the local sidecar; start it with:

```bash
runbrake sidecar --policy ~/.openclaw/runbrake-policy.json
```

Use this when the user asks how to turn runtime policy checks on. If the sidecar is not running, the adapter should fail open locally and the user can continue using scanner commands.

## Exit Codes

- `0`: command completed and the result is clean or below the configured threshold.
- `1`: command completed and found high or critical risk.
- `2`: command failed before completing the check.

## Receipt Wording

Expected session messages include:

```text
RunBrake active - sidecar connected - policy checks visible in this session
RunBrake not enforcing - sidecar unavailable - agent will fail open locally
RunBrake checked <tool> - <status> - <policyId>
RunBrake blocked install <name> - <policyId>
```
