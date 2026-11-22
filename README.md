# IKAR API — Vercel

API backend for IKAR. **Vercel is the active deployment target.** Cloudflare Workers deployment is disabled; the legacy Worker files are retained for reference only and are not part of the active Vercel runtime.

## Active architecture

- Hosting and API runtime: Vercel (Node.js serverless functions / Node.js server entry point).
- DNS-over-HTTPS: AdGuard Public DNS (`https://dns.adguard-dns.com/resolve`).
- Threat intelligence: URLhaus and ThreatFox (abuse.ch).
- AI provider: Hugging Face Inference Providers, when `HF_TOKEN` is configured.

A successful DNS response only confirms name resolution. It does not prove that a domain is safe.

## API routes

All security and assistant routes require the IKAR bearer token unless otherwise stated.

- `GET /health`: service status and non-secret configuration indicators.
- `POST /api/dns/resolve`: authenticated AdGuard DNS-over-HTTPS lookup. JSON body: `{ "name": "example.com", "type": "A" }`. Supported types: A, AAAA, CNAME, MX, NS, TXT.
- `POST /v1/security/domain-check`: authenticated domain or IP reputation check using DNS (for domains), URLhaus and ThreatFox. JSON body: `{ "domain": "example.com" }`.
- `POST /v1/security/analyze`: authenticated AI-assisted interpretation of Android security metadata. This is an advisory analysis, not proof of malware.
- `POST /v1/chat`: authenticated IKAR assistant chat.

Authentication header: `Authorization: Bearer <IKAR_API_TOKEN>`.

## Environment variables

Configure these in the Vercel project settings. Never commit their values or share them in logs or screenshots.

- `IKAR_API_TOKEN`: bearer token used by IKAR clients.
- `URLHAUS_AUTH_KEY`: abuse.ch Auth-Key used for URLhaus and ThreatFox requests.
- `HF_TOKEN`: Hugging Face access token for AI routes.
- `HF_MODEL`: optional model override.

Do not create a new `IKAR_API_TOKEN` without updating every client that uses the existing token. Keep secrets separate between Preview and Production environments as appropriate.

## Reputation interpretation and limitations

IKAR combines source results and reports source coverage, freshness, confidence-as-coverage, divergences and limitations. The confidence score measures how many source/indicator lookups returned usable responses; it is **not** a probability that a domain is malicious or safe.

- An URLhaus historical/offline listing is not by itself proof of an active threat.
- A no-match is not a guarantee of safety.
- Incomplete or unavailable source responses must not be reported as a clean result.
- Conflicting source results are surfaced rather than silently discarded.

See [Threat intelligence sources](docs/THREAT-INTELLIGENCE-SOURCES.md) and [AdGuard DoH](docs/ADGUARD-DOH.md).

## Tests

Run the automated test suite with:

```sh
npm test
```

The GitHub Actions validation and reputation test workflows run on the active development branch and pull requests.

## Legacy Cloudflare files

`src/index.js` and `wrangler.toml` are retained as legacy reference material. The Cloudflare deployment workflow is intentionally disabled. Do not restore Cloudflare deployment unless the hosting architecture is deliberately changed and reviewed.
