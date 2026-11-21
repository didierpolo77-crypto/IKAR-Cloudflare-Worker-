# IKAR Assistant API — Cloudflare Worker

API backend for IKAR Assistant. This repository is the Cloudflare deployment source; Render is kept as a fallback during migration.

## Cloudflare deployment

- Worker name: `bold-fire-498brikar-assistant-api` (matches the currently created dashboard Worker)
- Entry point: `src/index.js`
- Cloudflare Workers AI binding: `AI` (configured in `wrangler.toml`)
- Deploy manually with Wrangler or through GitHub Actions after configuring repository settings.

### GitHub Actions secrets and variables

Add these to the repository settings:

- Secret `CF_API_TOKEN`: Cloudflare API token with Workers Scripts edit permission and account access.
- Variable `CF_ACCOUNT_ID`: Cloudflare account ID.

Workflow: `.github/workflows/deploy-cloudflare-worker.yml`. It deploys on pushes to `main` affecting Worker files, or via manual workflow dispatch.

### Worker secrets

In Cloudflare Worker **Settings → Variables and Secrets**, add as encrypted secrets:

- `IKAR_API_TOKEN`: long random API bearer token shared with the Android app backend configuration.
- `URLHAUS_AUTH_KEY`: URLhaus Auth-Key for URL threat checks.

Do not store these values in source code, GitHub commits, APKs, or chat.

## Routes

- `GET /health`: basic Worker status and whether AI binding exists; does not reveal secret values.
- `POST /v1/chat`: authenticated chat. Header `Authorization: Bearer <IKAR_API_TOKEN>`. JSON body: `{ "message": "...", "history": [] }`.
- `POST /v1/url/check`: authenticated URLhaus lookup. Header same as above. JSON body: `{ "url": "https://example.com/" }`. The URL is submitted to URLhaus; do not submit private or sensitive URLs.

URLhaus returns `verdict: "malicious"` when its record is currently online, `"listed"` for a listed record that is not online, and `"no_match"` when it has no result. A no-match is not a guarantee of safety.

## AI provider

This Worker currently uses the Cloudflare Workers AI binding configured in `wrangler.toml`, not Hugging Face. Render's existing Hugging Face backend remains available while the provider and Android endpoint are migrated and tested.

## Test

- `GET /health`
- `POST /v1/chat` with bearer token
- `POST /v1/url/check` with bearer token and a URL

