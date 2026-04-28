## Summary

Describe the scanner, rule, documentation, or CI change.

## Type

- [ ] Scanner bug fix
- [ ] Rule change
- [ ] False-positive reduction
- [ ] Report/SARIF change
- [ ] GitHub Action change
- [ ] OpenClaw policy-plugin adapter change
- [ ] Documentation

## Verification

Paste the commands you ran:

```bash
pnpm run ci:check
```

## Safety

- [ ] I did not add live secrets, credentials, private prompts, or customer data.
- [ ] New or changed rules include false-positive considerations.
- [ ] Rule IDs are stable, or the change explains why a new ID is required.
- [ ] Reports and snapshots do not expose raw secret values.
