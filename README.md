# codewarden-secrets

A GitHub Action that gets CodeWarden secrets with the job's own OIDC
token, so no long-lived secret is stored in GitHub (CodeWarden design
§32.21). Licensed under Apache-2.0.

1. On the secret's page in CodeWarden, a person adds a **GitHub workflow**
   share: the repository's ID and owner ID (`gh api repos/OWNER/REPO --jq
   '.id, .owner.id'`), and preferably an environment, a ref and the
   workflow.
2. The job asks GitHub for an ID token for `https://id.ferrite.no/secrets`,
   exchanges it at CodeWarden's `/token` (RFC 8693) for a token that lasts
   at most 10 minutes, and reads the secrets the share allows.
3. Every value is masked (each line of a multi-line value too) before it is
   exported as a variable or written to a 0600 file under `RUNNER_TEMP`;
   the post step removes the files at the end of the job.

```yaml
permissions:
  id-token: write
  contents: read
jobs:
  deploy:
    environment: production
    runs-on: [self-hosted]
    steps:
      - uses: ferrite-no/codewarden-secrets@v1   # or pin v1.0.0's commit SHA
        with:
          secrets: |
            ASC_P8=asc#p8
            file:ASC_KEY_FILE=asc#p8
            aws-deploy
      - run: ./deploy.sh   # sees ASC_P8, ASC_KEY_FILE, AWS_DEPLOY_ACCESS_KEY_ID, ...
```

Input `secrets`, one per line: `NAME=secret#field` (one field),
`NAME=secret` (every field as `NAME_<FIELD>`), `secret` (every field as
`<SECRET>_<FIELD>`); a `file:` prefix writes a file and exports its path.
A secret is its name or `id:<uuid>`. Binary fields are exported as base64,
or as raw bytes in a file. Output `exported`: a JSON array of `{name,
secret, field, file}`, never a value.

Masking hides only exact lines of a value in the log. A value printed
transformed (encoded, split, in part) is not hidden: prefer files, and
keep `set -x` off in steps that use secrets.

The App Store Connect key, for example (`asc` with the fields `key_id`,
`issuer_id` and `p8`):

```yaml
      - uses: ferrite-no/codewarden-secrets@v1
        with:
          secrets: |
            ASC_KEY_ID=asc#key_id
            ASC_ISSUER_ID=asc#issuer_id
            file:ASC_KEY_P8=asc#p8
      # ASC_KEY_P8 is the path of a 0600 file holding the .p8, removed at job end.
```

Build: `npm ci --ignore-scripts && npm run check && npm test && npm run
build`. Every dependency is pinned in `package-lock.json` with its
integrity hash. The source lives in CodeWarden's repository under
`actions/codewarden-secrets`, without `dist/`; the published repository
`ferrite-no/codewarden-secrets` carries the built `dist/`, which Actions
run directly, and the tags `v1.x.y` and the moving `v1`.
