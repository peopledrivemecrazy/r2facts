# r2facts

Keyless CI storage on Cloudflare R2. A Cloudflare Worker checks GitHub
Actions OIDC tokens and writes to R2 through a bucket binding. No secrets
or API keys go in any repository.

- **Worker**: verifies the OIDC token (issuer, audience, owner allowlist) and
  limits each repository to `github/<owner>/<repo>/...`.
- **Action**: composite `upload` / `download` using `curl`. The calling
  workflow only needs `permissions: id-token: write`.

Status: work in progress.

## License

MIT
