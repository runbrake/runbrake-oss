# RunBrake Hermes Policy Adapter

This adapter connects Hermes Agent to the local RunBrake sidecar. Users install the same RunBrake CLI for OpenClaw and Hermes:

```bash
brew install runbrake/tap/runbrake
runbrake doctor --ecosystem hermes --path ~/.hermes
```

There is not a separate Homebrew package for Hermes. The Homebrew tap installs the `runbrake` CLI. Hermes runtime/session integration is enabled by copying this adapter and the `runbrake-security` skill into the local Hermes home:

```bash
mkdir -p "${HERMES_HOME:-$HOME/.hermes}/plugins" "${HERMES_HOME:-$HOME/.hermes}/skills"
cp -R plugins/hermes-policy "${HERMES_HOME:-$HOME/.hermes}/plugins/runbrake-policy"
cp -R skills/hermes/runbrake-security "${HERMES_HOME:-$HOME/.hermes}/skills/runbrake-security"
```

Enable the plugin in `${HERMES_HOME:-$HOME/.hermes}/config.yaml`:

```yaml
plugins:
  runbrake-policy:
    enabled: true
```

Point the plugin at the local sidecar:

```bash
export RUNBRAKE_SIDECAR_URL=http://127.0.0.1:47838
export RUNBRAKE_RECEIPTS=quiet
```

The adapter posts metadata-first runtime observations and policy decisions to the local sidecar. It emits compact startup, runtime, block, and fail-open notices for the Hermes session when supported. It intentionally does not send raw prompts, raw tool arguments, file contents, package bodies, memory contents, or unredacted secrets.

The `runbrake-security` Hermes skill is an operator workflow for asking about RunBrake status, recent receipts, scans, watcher checks, sidecar setup, and enforcement guidance. It is not the enforcement boundary; enforcement lives in this plugin and the local sidecar policy.
