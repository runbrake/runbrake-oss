# Hermes RunBrake Commands

## Local Install Checks

```bash
runbrake doctor --ecosystem hermes --path "${HERMES_HOME:-$HOME/.hermes}"
```

```bash
runbrake scan-skills --ecosystem hermes "${HERMES_HOME:-$HOME/.hermes}/skills"
```

```bash
runbrake watch-hermes --once \
  --path "${HERMES_HOME:-$HOME/.hermes}" \
  --state "${HERMES_HOME:-$HOME/.hermes}/runbrake-watch-state.json" \
  --format json
```

```bash
curl -fsS http://127.0.0.1:47838/healthz
```

Use this when the user asks whether the RunBrake sidecar is active.

## Receipts And Watcher Checks

```bash
runbrake watch-hermes --once --path ~/.hermes --format console
```

Use this when the user asks to check new skills, changed skills, manually copied plugins, or bypasses outside a supported install hook.

```bash
RUNBRAKE_RECEIPTS=quiet
RUNBRAKE_RECEIPTS=all
RUNBRAKE_RECEIPTS=off
```

Quiet is the default: blocks, quarantines, kill switches, fail-open, redactions, approval-required decisions, and shadow would-block decisions are visible. `all` also shows ordinary allowed and observed receipts. `off` suppresses non-blocking notices.

Expected session messages include:

```text
RunBrake active - sidecar connected - policy checks visible in this session
RunBrake not enforcing - sidecar unavailable - agent will fail open locally
RunBrake checked <tool> - <status> - <policyId>
RunBrake blocked install <name> - <policyId>
```

## Assessment Report

```bash
runbrake assess \
  --ecosystem hermes \
  --path "${HERMES_HOME:-$HOME/.hermes}" \
  --state "${HERMES_HOME:-$HOME/.hermes}/runbrake-assess-state.json" \
  --format markdown \
  --output runbrake-hermes-assessment.md
```

## Runtime Plugin Install

Hermes uses the same RunBrake CLI package as OpenClaw:

```bash
brew install runbrake/tap/runbrake
runbrake doctor --ecosystem hermes --path "${HERMES_HOME:-$HOME/.hermes}"
```

There is no separate Hermes Homebrew package. Copy the adapter and skill into the Hermes home only when the user wants runtime policy checks and receipt notices inside Hermes sessions.

```bash
mkdir -p "${HERMES_HOME:-$HOME/.hermes}/plugins" "${HERMES_HOME:-$HOME/.hermes}/skills"
cp -R plugins/hermes-policy "${HERMES_HOME:-$HOME/.hermes}/plugins/runbrake-policy"
cp -R skills/hermes/runbrake-security "${HERMES_HOME:-$HOME/.hermes}/skills/runbrake-security"
```

Enable the plugin in `${HERMES_HOME:-$HOME/.hermes}/config.yaml`:

```yaml
plugins:
  enabled:
    - runbrake-policy
```

Start the local sidecar:

Runtime policy checks are optional. Scanner, doctor, watch, and assessment commands work without a sidecar. The public RunBrake CLI includes the local sidecar; start it with:

```bash
runbrake sidecar \
  --policy "${HERMES_HOME:-$HOME/.hermes}/runbrake-policy.json" \
  --addr 127.0.0.1:47838
```

If the sidecar is not running, the Hermes adapter fails open locally and the user can continue using scanner commands until a local sidecar endpoint is available.

Point the Hermes plugin at the sidecar:

```bash
export RUNBRAKE_SIDECAR_URL="${RUNBRAKE_SIDECAR_URL:-http://127.0.0.1:47838}"
```

## Public Hermes Ecosystem Report

```bash
runbrake scan-registry hermes \
  --source github \
  --repo https://github.com/NousResearch/hermes-agent.git \
  --dependency-scan \
  --vuln osv \
  --format json \
  --output runbrake-hermes-registry.json
```

```bash
runbrake registry-report-pack \
  --input runbrake-hermes-registry.json \
  --output-dir runbrake-hermes-report-pack
```

## Helper

```bash
HERMES_SKILL_DIR="${HERMES_SKILL_DIR:-$PWD/skills/hermes/runbrake-security}" \
  "$HERMES_SKILL_DIR/scripts/check-runbrake-hermes.sh"
```

## Exit Codes

- `0`: command completed and the result is clean or below the configured threshold.
- `1`: command completed and found high or critical risk, or a required local setup item is missing.
- `2`: command failed before completing the check.
