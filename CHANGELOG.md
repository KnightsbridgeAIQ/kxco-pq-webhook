# Changelog

All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-05-22

Phase 3 of the kxco-post-quantum evolution brief, scoped to Option A
(webhook 0.2.0 only; JWT package deferred indefinitely; DKIM deferred
indefinitely). No behaviour change for existing 0.1.0 users — every new
surface is opt-in via explicit import.

### Added
- **`pqResponseSigner`** middleware for Express, Hono, Cloudflare Workers,
  and Vercel Node Functions (subpath imports). Captures the response body
  on its way out and attaches `X-KXCO-Timestamp` / `X-KXCO-PQ-Signature` /
  `X-KXCO-PQ-Kid` (plus `X-KXCO-Signature` if HMAC is configured) over the
  canonical `${ts}.${body}` envelope. Per-route, opt-in, never global —
  patches the response object for THIS request only.
- **`pqResponseSignerPlugin`** Fastify plugin equivalent using Fastify's
  `onSend` hook.
- **`signResponse(signer, body, opts?)`** + **`isStreamingBody(body)`**
  helpers in the new `kxco-post-quantum-webhook/response-core` subpath for
  callers building their own framework adapter.
- **`verifiedFetch(url, init, { verifier, permissive?, fetchImpl? })`** in
  the new `kxco-post-quantum-webhook/verified-fetch` subpath. Wraps `fetch`,
  runs the verifier against the response body BEFORE handing it to the
  caller. Throws `KxcoResponseError` on bad signature (strict default) so
  unverified bytes can't leak into application logic. Returns
  `{ response, kxcoResponse }` on success; the returned `response` is
  re-wrapped so it can still be `.json()`-ed / `.text()`-ed normally.
- **`KxcoResponseError`** class with `.code`, `.kxcoResponse`, `.response`
  fields for programmatic handling of verification failures.

### Tests + coverage
- 78 tests total (was 53 in 0.1.0)
- 94.72% line coverage, 93.18% function coverage across the public surface
- New test files: `test/response-signing.test.js`, `test/verified-fetch.test.js`

### Non-goals (documented)
- README now carries an explicit "non-goals" section. JWT, JWKS, DKIM,
  hosted signing service, and any generic HTTP-security framework
  expansion are explicitly out of scope. See README for the rationale.

### Wire format
- The response-signing wire format is **identical** to the webhook wire
  format — same envelope (`${ts}.${body}`), same headers, same kid, same
  `required` policy. A receiver verifying webhooks from a platform can
  verify the same platform's API responses with no code change.
- The canonical spec at [docs/webhook-contract.md](./docs/webhook-contract.md)
  applies to both. The contract is forward-compatible: a signature
  produced by 0.1.0 verifies under 0.2.0 unchanged.

### Compatibility notes
- 0.2.0 is a minor bump because no existing API changed. Users on 0.1.0
  who don't import the new middleware see zero behaviour change.
- Streaming response bodies (SSE, chunked transfer) cannot be signed —
  the middleware buffers the body to compute the envelope. Don't mount
  the response-signing middleware on streaming routes. With `strict: true`
  the middleware throws on streaming bodies; with the default `strict: false`
  it buffers (which defeats streaming).
- Same upstream caveat from 0.1.0 still applies: `kxco-post-quantum/src/webhook.js`'s
  `signDelivery()` calls `pqSign()` unconditionally. Worked around in our
  `createSigner`; upstream bug still tracked.

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
