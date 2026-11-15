# codewarden-secrets

A GitHub Action that gets CodeWarden secrets with the job's own OIDC
token, so no long-lived secret is stored in GitHub (design §32.22).

1. On the secret's page in CodeWarden, a person adds a **GitHub workflow**
   rule (or approves an agent's proposal with a passkey): the repository's
   ID and owner ID (`gh api repos/OWNER/REPO --jq '.id, .owner.id'`), and
   preferably an environment, a ref and the workflow.
2. The job names each secret by its **ID** (shown with a copy button on the
   secret's page; agents find it with `secrets.search`). It asks GitHub for
   an ID token for `https://id.ferrite.no/secrets`, exchanges it at
   CodeWarden's `/token` (RFC 8693) with those IDs for a token that lasts
   at most 10 minutes, and reads exactly those secrets, as their rules
   allow.
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
      - uses: ferrite-no/codewarden-secrets@v1   # or pin v1.1.0's commit SHA
        with:
          secrets: |
            ASC_P8=0b6a4f1e-5f46-4ab2-9c01-000000000001#p8
            file:ASC_KEY_FILE=0b6a4f1e-5f46-4ab2-9c01-000000000001#p8
            AWS=0b6a4f1e-5f46-4ab2-9c01-000000000002
      - run: ./deploy.sh   # sees ASC_P8, ASC_KEY_FILE, AWS_ACCESS_KEY_ID, ...
```

Input `secrets`, one per line: `NAME=<secret id>#field` (one field) or
`NAME=<secret id>` (every field as `NAME_<FIELD>`); a `file:` prefix writes
a file and exports its path. A secret is named by its ID, never its name:
a name could be another team's secret of the same name, so it is never
looked up. At most 20 secrets per step. Binary fields are exported as
base64, or as raw bytes in a file. Output `exported`: a JSON array of `{name,
secret, field, file}`, never a value.

Masking hides only exact lines of a value in the log. A value printed
transformed (encoded, split, in part) is not hidden: prefer files, and
keep `set -x` off in steps that use secrets.

The App Store Connect key, for example (the secret `asc` with the fields
`key_id`, `issuer_id` and `p8`; its ID kept in a repository variable):

```yaml
      - uses: ferrite-no/codewarden-secrets@v1
        with:
          secrets: |
            ASC_KEY_ID=${{ vars.CODEWARDEN_ASC_SECRET_ID }}#key_id
            ASC_ISSUER_ID=${{ vars.CODEWARDEN_ASC_SECRET_ID }}#issuer_id
            file:ASC_KEY_P8=${{ vars.CODEWARDEN_ASC_SECRET_ID }}#p8
      # ASC_KEY_P8 is the path of a 0600 file holding the .p8, removed at job end.
```

Build: `npm ci --ignore-scripts && npm run check && npm test && npm run
build`. Every dependency is pinned in `package-lock.json` with its
integrity hash. The source lives in CodeWarden's repository under
`actions/codewarden-secrets`, without `dist/`; the published repository
`ferrite-no/codewarden-secrets` carries the built `dist/`, which Actions
run directly, and the tags `v1.x.y` and the moving `v1`.

Changes: **1.1.0** secrets are named by ID only (`NAME=<id>#field`,
`NAME=<id>`); names, `id:` and bare secrets are refused; the exchange
sends `secret_ids`. **1.0.0** first version.
