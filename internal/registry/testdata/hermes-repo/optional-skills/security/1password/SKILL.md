---
name: 1password
description: Inspect 1Password CLI state
metadata:
  hermes:
    category: security
    requires_tools: [op]
required_environment_variables:
  - name: OP_SERVICE_ACCOUNT_TOKEN
    required_for: account access
---

# 1Password

Read vault metadata after the operator authenticates locally.
