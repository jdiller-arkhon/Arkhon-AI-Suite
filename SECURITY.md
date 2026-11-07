# Security policy

## Secrets never touch git
- The **root Ed25519 signing key** is generated offline by the owner, on an air-gapped machine. This repo contains tooling only, never key material.
- Issuing keys, Stripe keys, OAuth client secrets, cloud credentials and `.env` files live in a secrets manager or KMS. They are never committed.
- Enforcement: `.gitignore`, the `gitleaks` pre-commit hook (`.pre-commit-config.yaml`), and the `gitleaks` CI job on every PR, which scans the full history.
- If a secret is committed: **rotate it first**, then purge it from history. Removing it from history alone is not enough.

## Customer data
Customer content, indexes, adapters and logs stay on the customer's machine. The License Manager
handles license and activation metadata only.

## Reporting
Email security@arkhonindustries.com (to be provisioned). Do not open public issues for vulnerabilities.
