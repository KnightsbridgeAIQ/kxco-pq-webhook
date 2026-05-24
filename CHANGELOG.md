# Changelog

## 1.0.0 — 2026-05-24

Stable release.



## 0.3.4 — 2026-05-24

Maintenance release. No breaking changes.



## 0.3.3 — 2026-05-24

Maintenance release. No breaking changes.



## 0.3.2 — 2026-05-24

Maintenance release. No breaking changes.



## 0.3.1 â€” 2026-05-23

Maintenance release. No breaking changes.


All notable changes to this project will be documented in this file. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project follows [Semantic Versioning](https://semver.org/).

## [0.3.0] â€” 2026-05-22

Phase 5 of the kxco-post-quantum evolution brief. Adds operational
support for **key rotation** under the existing wire contract. Additive:
zero behaviour change for 0.2.0 callers who don't use the new API.

### Added
- **`createVerifier({ pinnedKids: [...] })`** â€” accept an array of
  `{ kid, publicKey }` entries instead of a single `pinnedKid`. The
  verifier resolves the incoming `X-KXCO-PQ-Kid` against the keystore
  and selects the matching pubkey. `kid_mismatch` is returned (same
  reason code as the singular case) when the header kid is in neither
  entry. `pinnedKid` (singular) continues to work unchanged and is
  mutually exclusive with `pinnedKids`.
- **`resolvedKid`** field on `VerifyResult` when `pinnedKids[]` matched
  successfully â€” tells the caller which key was used for this delivery.
  Useful for logging/metrics during rotation windows.
- **`docs/webhook-contract.md`** Â§"Key rotation and history" â€” defines
  the multi-kid `.well-known/kxco-pq-pubkey` schema, the rotation
  manifest format (RFC 8785 JCS canonical, signed by outgoing key),
  and verifier semantics for `pinnedKids[]`. Language-neutral; receivers
  in Rust/Go/Python can implement against this spec.
- **`docs/key-rotation-playbook.md`** â€” operational playbook for
  routine + compromise rotation. Covers prereqs, the cutover sequence,
  drain windows, and the (interim) out-of-band approach for compromise
  scenarios pending revocation-manifest spec work.

### Tests + coverage
- 89 tests total (was 78 in 0.2.0). 11 new `pinnedKids[]` cases covering
  argument validation, single-kid signing â†’ multi-kid acceptance for
  both old + new keys, kid not in pin set, tampered body with valid kid,
  hex-string pubkey entries, `required: 'both'` with multi-kid PQ, and
  backward compatibility of the singular `pinnedKid` form.

### Companion package: `kxco-pq-cli@0.1.0`
- New separate npm package exposing `kxco-pq` binary for ops/CI use.
- Commands: `keygen`, `fingerprint`, `rotate`. The `rotate` command
  produces a signed manifest + multi-kid well-known doc ready to publish.
- Includes a subset of RFC 8785 JCS canonicalization sufficient for
  the rotation-manifest schema (strings/arrays/objects/integers; throws
  on floats so a future schema change is caught early rather than
  silently producing language-incompatible signatures).

### Wire format
- The base envelope (`${ts}.${rawBody}`), HMAC + ML-DSA-65 signature
  prefixes, and `X-KXCO-PQ-Kid` semantics are unchanged. Receivers on
  0.2.0 continue to verify deliveries from 0.3.0 senders that haven't
  rotated â€” the multi-kid path is opt-in for both sides.

### Out of scope (documented)
- **Verifier auto-refresh** of the well-known endpoint. Deferred to
  0.4.0 â€” the manual `pinnedKids[]` path is exercised in production
  first, then auto-refresh adds the trust-path mitigations on top.
- **Revocation manifests** for compromise rotation. The current spec
  bridges trust from old kid to new kid via the old key's signature,
  which assumes the old key is still trustworthy. A compromise event
  needs a different trust path; see playbook Â§3.

### Compatibility notes
- 0.3.0 is a minor bump because no existing API changed. Singular
  `pinnedKid` + `pqPublicKey` callers see zero behaviour change.
- The new `kxco-pq-cli` is a separate package (`npm install -g kxco-pq-cli`)
  and is not required to use the multi-kid verifier path.

## [0.2.0] â€” 2026-05-22

Phase 3 of the kxco-post-quantum evolution brief, scoped to Option A
(webhook 0.2.0 only; JWT package deferred indefinitely; DKIM deferred
indefinitely). No behaviour change for existing 0.1.0 users â€” every new
surface is opt-in via explicit import.

### Added
- **`pqResponseSigner`** middleware for Express, Hono, Cloudflare Workers,
  and Vercel Node Functions (subpath imports). Captures the response body
  on its way out and attaches `X-KXCO-Timestamp` / `X-KXCO-PQ-Signature` /
  `X-KXCO-PQ-Kid` (plus `X-KXCO-Signature` if HMAC is configured) over the
  canonical `${ts}.${body}` envelope. Per-route, opt-in, never global â€”
  patches the response object for THIS request only.
- **`pqResponseSignerPlugin`** Fastify plugin equivalent using Fastify's
  `onSend` hook.
- **`signResponse(signer, body, opts—)`** + **`isStreamingBody(body)`**
  helpers in the new `kxco-post-quantum-webhook/response-core` subpath for
  callers building their own framework adapter.
- **`verifiedFetch(url, init, { verifier, permissive—, fetchImpl— })`** in
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
  format â€” same envelope (`${ts}.${body}`), same headers, same kid, same
  `required` policy. A receiver verifying webhooks from a platform can
  verify the same platform's API responses with no code change.
- The canonical spec at [docs/webhook-contract.md](./docs/webhook-contract.md)
  applies to both. The contract is forward-compatible: a signature
  produced by 0.1.0 verifies under 0.2.0 unchanged.

### Compatibility notes
- 0.2.0 is a minor bump because no existing API changed. Users on 0.1.0
  who don't import the new middleware see zero behaviour change.
- Streaming response bodies (SSE, chunked transfer) cannot be signed â€”
  the middleware buffers the body to compute the envelope. Don't mount
  the response-signing middleware on streaming routes. With `strict: true`
  the middleware throws on streaming bodies; with the default `strict: false`
  it buffers (which defeats streaming).
- Same upstream caveat from 0.1.0 still applies: `kxco-post-quantum/src/webhook.js`'s
  `signDelivery()` calls `pqSign()` unconditionally. Worked around in our
  `createSigner`; upstream bug still tracked.

## [0.1.0] â€” 2026-05-22

Initial release. Phase 2 of the [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) evolution brief (Option B â€” webhook package).

### Added
- `createSigner({ hmacSecret, pqSecretKey, pqKid })` â€” opinionated builder for outbound webhook signers
- `createVerifier({ hmacSecret, pqPublicKey, pinnedKid, windowSeconds, required })` â€” opinionated builder for inbound verifiers, with a `required` policy (`'hmac' | 'pq' | 'both' | 'either'`) and structured failure reasons (`timestamp_skew`, `kid_mismatch`, `missing_hmac`, `missing_pq`, `hmac_invalid`, `pq_invalid`)
- `signedFetch(url, opts)` â€” one-line client SDK that signs + POSTs
- `signedEnvelope(signer, body, opts)` â€” lower-level helper returning `{ rawBody, headers }` for callers using axios/undici/their own HTTP client
- **Express adapter** (`/express`): `pqWebhook(verifier)` middleware
- **Fastify adapter** (`/fastify`): plugin with raw-body content-type parser + preHandler hook
- **Hono adapter** (`/hono`): `pqWebhook(verifier)` middleware (works on any Fetch-API runtime via `c.req.raw`)
- **Cloudflare Workers adapter** (`/workers`): `withPqWebhook(verifier, handler)` wrapper + lower-level `verifyRequest(verifier, request)`. Works in any Fetch-API environment (Workers, Deno, Bun, Vercel Edge)
- **Vercel Functions adapter** (`/vercel`): `nodePqWebhook(verifier, handler)` for the Node runtime. Edge runtime uses the Workers adapter
- Six runnable examples under `examples/` â€” one per framework + one sender
- Canonical wire-format spec under `docs/webhook-contract.md` â€” language-neutral; receivers in any language can re-implement against it without depending on this package

### Test coverage
- 53 tests covering builder validation, sign/verify roundtrips across all four `required` policies, tampering, kid mismatch, timestamp skew, header normalisation, all four framework adapters
- 95.72% line coverage, 100% function coverage on the public surface

### Known issues + caveats
- Upstream `kxco-post-quantum/src/webhook.js`'s `signDelivery()` always calls `pqSign()` even when only HMAC is configured; this would crash for HMAC-only senders. **Worked around** in `createSigner` by bypassing `signDelivery` when only one of the two secrets is present. To be filed as an upstream bug.
- Fastify is a soft dependency; the plugin only loads when `fastify` is installed. The Fastify test file skips if `fastify` isn't present.
- No browser-side examples yet â€” outbound webhook signing typically happens server-to-server, but `signedFetch` works in any Fetch-API runtime including browsers.

### License
Apache 2.0. Upstream `kxco-post-quantum` remains MIT. The split is deliberate â€” receivers of this package can audit the verification path in isolation.

[0.1.0]: https://github.com/JackKXCO/kxco-post-quantum-webhook/releases/tag/v0.1.0