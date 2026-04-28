# RunBrake OpenClaw Policy Plugin

This package adapts OpenClaw install and tool-call hooks to the local RunBrake sidecar.

It registers:

- `before_install` for install-time policy decisions.
- `before_tool_call` for runtime tool-call policy decisions.

RunBrake fails open when the local sidecar is unavailable, so OpenClaw is not bricked by a missing local service.

## Install

After the package is published to ClawHub:

```bash
openclaw plugins install clawhub:@runbrake/openclaw-policy
```

For local testing from this repository:

```bash
pnpm --filter @runbrake/openclaw-policy run build
openclaw plugins install ./plugins/openclaw-policy
```

## Publish Dry Run

Use ClawHub's package flow, not the skill publish flow:

```bash
pnpm --filter @runbrake/openclaw-policy run build
clawhub package publish ./plugins/openclaw-policy --dry-run
```

Do not run the non-dry publish until the package dry run is clean.
