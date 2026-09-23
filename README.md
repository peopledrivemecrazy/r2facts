# r2facts

Keyless CI storage on Cloudflare R2. A Cloudflare Worker checks GitHub
Actions OIDC tokens and writes to R2 through a bucket binding. No secrets
or API keys go in any repository.

- **Worker**: verifies the OIDC token (RS256 signature, issuer, audience,
  expiry, owner ID allowlist) and limits each repository to
  `github.com/<owner>/<repo>/...`.
- **Action**: composite `upload` / `download` / `delete` using `curl` only.
  The calling job needs `permissions: id-token: write` and nothing else.

## Deploy

Each user deploys their own Worker. The repository holds no account IDs,
bucket names or allowlists.

1. Install, log in and deploy:

   ```sh
   pnpm install
   pnpm wrangler login
   pnpm wrangler deploy
   ```

   - If your account has no workers.dev subdomain yet, wrangler asks you to
     register one. The Worker is then served at
     `https://r2facts.<subdomain>.workers.dev`. DNS for a new subdomain can
     take a few minutes.
   - On the first deploy, wrangler creates an R2 bucket named
     `r2facts-bucket` and writes `bucket_name` into `wrangler.toml`. Discard
     that change with `git restore wrangler.toml`; later deploys find the
     bucket without it. To use a bucket you already have, set
     `bucket_name = "<bucket>"` under `[[r2_buckets]]` before deploying.

2. Allow your GitHub account or org by its numeric ID:

   ```sh
   gh api users/<name> --jq .id
   echo <id> | pnpm wrangler secret put ALLOWED_OWNER_IDS
   ```

   `ALLOWED_OWNER_IDS` is comma-separated. IDs are matched against the
   token's `repository_owner_id` claim, which never changes and is never
   reused, so someone who registers a name you gave up gets no access. The
   Worker rejects every request until it is set.

3. Check it is live. Both requests should return `401`, not `500`:

   ```sh
   curl -i https://r2facts.<subdomain>.workers.dev/x
   curl -i -H 'Authorization: Bearer a.b.c' https://r2facts.<subdomain>.workers.dev/x
   ```

4. Point this repository's `e2e` workflow at it:

   ```sh
   gh variable set R2FACTS_URL --body https://r2facts.<subdomain>.workers.dev
   ```

Other settings:

- `AUDIENCE` (default `r2facts`) is the OIDC audience the Worker accepts. If
  you change it, pass the same value as the action's `audience` input.
- `MAX_UPLOAD_BYTES` (default 100 MB) caps uploads.
- `ALLOWED_WRITE_REFS` (optional) limits `PUT` and `DELETE` to tokens whose
  `ref` claim matches, e.g. `refs/heads/master,refs/tags/v*`. A trailing `*`
  matches a prefix. Reads are never limited. Without it, a workflow on any
  branch can overwrite an object a release job later reads. It applies to
  every repository using the Worker, and pull request runs have refs like
  `refs/pull/<n>/merge`, so list those too if they upload.
- `keep_vars = true` keeps vars set in the dashboard across deploys.

## Use the action

```yaml
permissions:
  contents: read
  id-token: write

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: make dist
      - uses: peopledrivemecrazy/r2facts@master
        with:
          url: https://r2facts.<your-subdomain>.workers.dev
          mode: upload
          path: dist
          key: candidates/${{ github.sha }}

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: peopledrivemecrazy/r2facts@master
        with:
          url: https://r2facts.<your-subdomain>.workers.dev
          mode: download
          path: dist
          key: candidates/${{ github.sha }}
```

| Input      | Required         | Description                                   |
| ---------- | ---------------- | --------------------------------------------- |
| `url`      | yes              | Worker URL                                    |
| `mode`     | yes              | `upload`, `download` or `delete`              |
| `path`     | upload, download | Local file or directory                       |
| `key`      | yes              | Remote key under `github.com/<owner>/<repo>/` |
| `audience` | no               | OIDC audience, default `r2facts`              |

- Other repositories can use the action only if this repository is public,
  or, if private, it allows access under Settings → Actions → General →
  Access.
- A file is stored as-is at `key`.
- A directory is stored as one `.tar.gz` object at `key` and extracted back
  into `path` on download.
- Downloading a file into an existing directory writes
  `<path>/<basename of key>`.

## API

Every request needs `Authorization: Bearer <GitHub OIDC token>`. Paths map
to `github.com/<repository>/<path>`, where `<repository>` comes from the
token, so a workflow can only reach its own repository's objects.

| Method   | Result                                                        |
| -------- | ------------------------------------------------------------- |
| `PUT`    | Streams the body into R2. Requires `Content-Length`. `201`    |
| `GET`    | Streams the object back. `404` if missing                     |
| `HEAD`   | Existence, size and ETag                                      |
| `DELETE` | Removes the object. `204`                                     |

Errors are JSON `{"error": "..."}` with `400` (bad path), `401` (bad
token), `403` (owner not allowed), `404`, `411`, `413` or `503` (GitHub
JWKS unreachable). Paths with `..`, `.`, empty segments, encoded `/` or
`\`, or control characters are rejected.

Objects are keyed by repository name, not ID. If you delete or rename a
repository and later create another with the old name under the same owner,
the new one can read and delete the old one's objects.

## Size limit

Cloudflare Workers accept request bodies up to 100 MB on the Free and Pro
plans (Business 200 MB, Enterprise 500 MB), so a single upload, including a
directory's archive, must fit under that. Multipart upload for larger files
isn't implemented yet.

## Develop

```sh
pnpm test
pnpm typecheck
echo 'ALLOWED_OWNER_IDS=<id>' > .dev.vars
pnpm dev
```

`pnpm test` runs vitest inside the Workers runtime against a local R2
bucket, with test signing keys standing in for GitHub's.

Only GitHub Actions can issue real OIDC tokens, so a full upload and
download can't run locally; `pnpm dev` only lets you check rejections. The
`e2e` workflow covers the real round trip: it uploads, downloads and
compares a file and a directory against the deployed Worker, then deletes
them. It runs on pushes to `master` and on manual dispatch, once the
`R2FACTS_URL` variable is set.

## License

MIT
