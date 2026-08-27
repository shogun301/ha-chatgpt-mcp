# Security policy

Report a suspected vulnerability through GitHub's private vulnerability
reporting feature. Do not open a public issue containing credentials, private
URLs, entity inventories, schedules, household presence data, or network
topology.

This repository intentionally contains no deployment secrets. Copy
`.env.example` to a local ignored `.env`, keep token and key material in the
ignored `secrets/` directory, and use GitHub or Cloudflare secret storage for
hosted deployments. Never commit a Home Assistant token, OAuth password hash,
JWT secret, tunnel token, SolarEdge credential, private key, or real household
configuration.

Run `python scripts/public_release_audit.py` before publishing a release. The
same audit runs in CI.
