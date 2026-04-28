# Contributing

Thanks for helping improve RunBrake Scanner.

## Development

```bash
pnpm install
pnpm run ci:check
```

## Pull Requests

Before opening a PR:

- Add or update tests for scanner behavior.
- Keep rule IDs stable.
- Do not include raw secrets in fixtures, snapshots, or reports.
- Keep the scanner local-first and metadata-first.
- Run `pnpm run ci:check`.

## Rule Changes

Rule changes should explain:

- What behavior the rule detects.
- Why the behavior is risky.
- Expected severity and confidence.
- False-positive considerations.
- Remediation guidance.

## Security Issues

Please do not open public issues for exploitable scanner bypasses or secret leaks. Use `SECURITY.md`.
