# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-22

Initial release. Phase 2 of the [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) evolution brief (Option B — webhook package).

### Added
- `createSigner({ hmacSecret, pqSecretKey, pqKid })` — opinionated builder for outbound webhook signers
- `createVerifier({ hmacSecret, pqPublicKey, pinnedKid, windowSeconds, required })` — opinionated builder for inbound verifiers, with a `required` policy (`'hmac' | 'pq' | 'both' | 'either'`) and structured failure reasons (`timestamp_skew`, `kid_mismatch`, `missing_hmac`, `missing_pq`, `hmac_invalid`, `pq_invalid`)
- `signedFetch(url, opts)` — one-line client SDK that signs + POSTs
- `signedEnvelope(signer, body, opts)` — lower-level helper returning `{ rawBody, headers }` for callers using axios/undici/their own HTTP client
- **Express adapter** (`/express`): `pqWebhook(verifier)` middleware
- **Fastify adapter** (`/fastify`): plugin with raw-body content-type parser + preHandler hook
- **Hono adapter** (`/hono`): `pqWebhook(verifier)` middleware (works on any Fetch-API runtime via `c.req.raw`)
- **Cloudflare Workers adapter** (`/workers`): `withPqWebhook(verifier, handler)` wrapper + lower-level `verifyRequest(verifier, request)`. Works in any Fetch-API environment (Workers, Deno, Bun, Vercel Edge)
- **Vercel Functions adapter** (`/vercel`): `nodePqWebhook(verifier, handler)` for the Node runtime. Edge runtime uses the Workers adapter
- Six runnable examples under `examples/` — one per framework + one sender
- Canonical wire-format spec under `docs/webhook-contract.md` — language-neutral; receivers in any language can re-implement against it without depending on this package

### Test coverage
- 53 tests covering builder validation, sign/verify roundtrips across all four `required` policies, tampering, kid mismatch, timestamp skew, header normalisation, all four framework adapters
- 95.72% line coverage, 100% function coverage on the public surface

### Known issues + caveats
- Upstream `kxco-post-quantum/src/webhook.js`'s `signDelivery()` always calls `pqSign()` even when only HMAC is configured; this would crash for HMAC-only senders. **Worked around** in `createSigner` by bypassing `signDelivery` when only one of the two secrets is present. To be filed as an upstream bug.
- Fastify is a soft dependency; the plugin only loads when `fastify` is installed. The Fastify test file skips if `fastify` isn't present.
- No browser-side examples yet — outbound webhook signing typically happens server-to-server, but `signedFetch` works in any Fetch-API runtime including browsers.

### License
Apache 2.0. Upstream `kxco-post-quantum` remains MIT. The split is deliberate — receivers of this package can audit the verification path in isolation.

[0.1.0]: https://github.com/JackKXCO/kxco-post-quantum-webhook/releases/tag/v0.1.0
