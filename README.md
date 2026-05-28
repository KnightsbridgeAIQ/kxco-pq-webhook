# kxco-post-quantum-webhook

[![npm](https://img.shields.io/npm/v/kxco-post-quantum-webhook?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum-webhook)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-post-quantum-webhook)](https://socket.dev/npm/package/kxco-post-quantum-webhook)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-post-quantum-webhook.svg)](https://nodejs.org)

Post-quantum ML-DSA-65 webhook signing and verification. Sign outgoing webhook payloads so recipients can prove they came from you. Verify incoming webhooks before processing them. Drop-in replacement for HMAC-SHA256 webhook patterns, but quantum-safe.

---

## When to use this

Use this package when you need proof that a webhook delivery came from a specific sender — not just that the payload was not tampered with in transit.

HMAC-SHA256 is a shared secret: the sender and receiver both hold the key, so either party could have produced the signature. ML-DSA-65 is an asymmetric signature scheme: only the sender holds the private key, and anyone holding the corresponding public key can verify. That property is called non-repudiation, and it matters when:

- You are receiving webhooks from a partner and need to be certain they originated from that partner's infrastructure, not a replay or a man-in-the-middle.
- You are sending webhooks to customers who need to prove, to a third party, that a specific event was delivered by your platform and not fabricated by them.
- You are replacing HMAC-SHA256 webhook patterns with something that holds up against quantum computers.

This package sends both HMAC-SHA256 and ML-DSA-65 signatures by default. Receivers can require either or both. During migration from HMAC-only setups, the `required: 'either'` policy lets receivers accept both old and new deliveries.

---

## Install

```bash
npm install kxco-post-quantum-webhook kxco-post-quantum
```

`kxco-post-quantum` is a peer dependency. Your application supplies the version.

---

## Quick start

### Sign an outgoing webhook

```js
import { mlDsa, fingerprint }                from 'kxco-post-quantum'
import { createSigner, signedFetch }         from 'kxco-post-quantum-webhook'

const kp     = mlDsa.keypairFromMaster(process.env.KEY_MASTER, 'my-app-v1')
const kid    = fingerprint(kp.publicKey)

const signer = createSigner({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqSecretKey: kp.secretKey,
  pqKid:       kid,
})

await signedFetch('https://receiver.example.com/webhooks/incoming', {
  signer,
  body:  { event: 'invoice.paid', amount: 12500 },
  event: 'invoice.paid',
})
```

### Verify an incoming webhook

```js
import { createVerifier } from 'kxco-post-quantum-webhook'

const verifier = createVerifier({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqPublicKey: process.env.SENDER_PQ_PUBKEY_HEX,
  pinnedKid:   process.env.SENDER_PQ_KID,
  required:    'both',
})

// In your request handler — rawBody must be the exact bytes received
const result = verifier.verify(req.headers, rawBody)

if (!result.ok) {
  // result.reason is one of: timestamp_skew | kid_mismatch |
  // missing_hmac | missing_pq | hmac_invalid | pq_invalid
  return res.status(401).json({ error: result.reason })
}

// Signature is valid — safe to process
```

Framework adapters (Express, Fastify, Hono, Cloudflare Workers, Vercel) handle raw-body capture and the 401 response automatically. See the per-framework examples below.

---

## Framework adapters

Pick the adapter that matches your stack.

### Express

```js
import express                            from 'express'
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import { pqWebhook }                      from 'kxco-post-quantum-webhook/express'

const verifier = createVerifier({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqPublicKey: process.env.SENDER_PQ_PUBKEY_HEX,
  pinnedKid:   process.env.SENDER_PQ_KID,
  required:    'both',
})

const app = express()

app.post('/webhooks/incoming',
  express.raw({ type: '*/*' }),
  pqWebhook(verifier),
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf-8'))
    res.json({ ok: true })
  },
)
```

`express.raw()` is required. The signature is over the exact body bytes — if Express parses the body first, verification will fail.

### Fastify

```js
import Fastify                            from 'fastify'
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import pqWebhookPlugin                    from 'kxco-post-quantum-webhook/fastify'

const app = Fastify()
await app.register(pqWebhookPlugin, { verifier })

app.post('/webhooks/incoming', async (req) => ({
  ok:   req.kxcoWebhook.ok,
  body: JSON.parse(req.body.toString('utf-8')),
}))
```

### Hono

```js
import { Hono }                           from 'hono'
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import { pqWebhook }                      from 'kxco-post-quantum-webhook/hono'

const app = new Hono()
app.use('/webhooks/incoming', pqWebhook(verifier))
app.post('/webhooks/incoming', async (c) => c.json({ ok: true }))
```

### Cloudflare Workers

```js
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import { withPqWebhook }                  from 'kxco-post-quantum-webhook/workers'

export default {
  fetch: withPqWebhook(verifier, async (req, env, ctx, result) => {
    const event = JSON.parse(await req.text())
    return new Response(JSON.stringify({ ok: true }))
  }),
}
```

### Vercel Functions (Node runtime)

```js
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import { nodePqWebhook }                  from 'kxco-post-quantum-webhook/vercel'

export const config = { api: { bodyParser: false } }

export default nodePqWebhook(verifier, async (req, res) => {
  const event = JSON.parse(req.rawBody.toString('utf-8'))
  res.status(200).json({ ok: true })
})
```

For the Vercel Edge runtime, use the Workers adapter (`withPqWebhook`).

---

## The `required` policy

`createVerifier({ required })` controls what counts as a passing verification:

| `required`  | Passes when                                       |
|-------------|---------------------------------------------------|
| `'both'`    | Both HMAC and ML-DSA-65 signatures are valid — default; recommended for production |
| `'pq'`      | ML-DSA-65 signature is valid                      |
| `'hmac'`    | HMAC-SHA256 signature is valid                    |
| `'either'`  | Either signature passes — useful during migration from HMAC-only |

When `ok` is false, `result.reason` contains one of: `timestamp_skew`, `kid_mismatch`, `missing_hmac`, `missing_pq`, `hmac_invalid`, `pq_invalid`.

---

## Wire format

The signature envelope is `${timestamp}.${rawBody}`. Headers sent with every delivery:

| Header                | Description                                      |
|-----------------------|--------------------------------------------------|
| `X-KXCO-Timestamp`    | Unix seconds                                     |
| `X-KXCO-Signature`    | `sha256=<64 hex chars>` HMAC-SHA256              |
| `X-KXCO-PQ-Signature` | `ml-dsa-65=<hex>` ML-DSA-65 signature            |
| `X-KXCO-PQ-Kid`       | 16 hex chars — SHA-256 of the public key bytes, first 8 bytes |
| `X-KXCO-Event`        | Optional event name                              |
| `X-KXCO-Delivery`     | Optional idempotency / trace ID                  |

The full wire-format spec is in [`docs/webhook-contract.md`](./docs/webhook-contract.md). It is language-neutral — anyone can re-implement the verifier in Rust, Go, Python, or any other language against the canonical math.

---

## Key rotation

When rotating signing keys, a verifier can accept multiple kids during the drain window — in-flight deliveries signed by the old key continue to verify until they expire.

```js
const verifier = createVerifier({
  pinnedKids: [
    { kid: '<new-kid>', publicKey: '<new-pubkey-hex>' },   // active
    { kid: '<old-kid>', publicKey: '<old-pubkey-hex>' }    // retiring
  ],
  required: 'pq',
})

const result = verifier.verify(req.headers, req.body)
// result.resolvedKid — which key was used for this delivery
```

`pinnedKid` (singular) continues to work unchanged and is mutually exclusive with `pinnedKids`.

---

## API

All exports from the main entry point (`kxco-post-quantum-webhook`):

### `createSigner(opts)` → `Signer`

Builds a reusable signing object. At least one of `hmacSecret` or `pqSecretKey` is required.

```
opts:
  hmacSecret   string | Buffer        — shared HMAC-SHA256 secret
  pqSecretKey  Buffer | Uint8Array    — ML-DSA-65 secret key (4032 bytes)
  pqKid        string                 — fingerprint of the matching public key; required when pqSecretKey is set

Returns:
  signer.sign(rawBody, { event?, deliveryId? }) → Record<string, string>
  signer.pqKid  string | undefined
```

### `createVerifier(opts)` → `Verifier`

Builds a reusable verifier. At least one of `hmacSecret`, `pqPublicKey`, or `pinnedKids` is required.

```
opts:
  hmacSecret     string | Buffer               — shared HMAC-SHA256 secret
  pqPublicKey    string | Buffer | Uint8Array  — ML-DSA-65 public key (1952 bytes or hex string)
  pinnedKid      string                        — required when pqPublicKey is set
  pinnedKids     Array<{ kid, publicKey }>     — multi-key form for rotation; mutually exclusive with pinnedKid/pqPublicKey
  windowSeconds  number                        — max clock skew in seconds (default: 300)
  required       'both' | 'pq' | 'hmac' | 'either'  — verification policy (default: 'both')

Returns:
  verifier.verify(headers, rawBody) → VerifyResult
  verifier.required  string

VerifyResult:
  ok            boolean   — overall verdict
  hmacOk        boolean   — HMAC check passed
  pqOk          boolean   — ML-DSA-65 check passed
  timestampOk   boolean   — timestamp within windowSeconds
  kidOk         boolean   — kid header matched pinnedKid
  reason        string?   — when !ok: timestamp_skew | kid_mismatch | missing_hmac | missing_pq | hmac_invalid | pq_invalid
  resolvedKid   string?   — when pinnedKids[] matched: which kid was used
```

### `signedFetch(url, opts)` → `Promise<Response>`

Signs and POSTs a body in one call. Returns the raw fetch `Response` — does not throw on non-2xx status codes.

```
url   string                    — absolute http(s) URL
opts:
  signer      Signer            — from createSigner()
  body        any               — JSON-stringified if not already a string or Buffer
  event       string?           — sets X-KXCO-Event header
  deliveryId  string?           — sets X-KXCO-Delivery header
  headers     Record<string, string>?  — merged after signing; signing headers take precedence
  method      string?           — default: 'POST'
  fetchImpl   function?         — custom fetch implementation; defaults to globalThis.fetch
```

### `signedEnvelope(signer, body, opts?)` → `{ rawBody, headers }`

Lower-level helper. Returns the signed headers and canonical body without making a request. Use when you already have your own HTTP client.

### `signResponse(signer, body, opts?)` → `Record<string, string>`

Computes signing headers for an outgoing API response body. Same wire format as `signer.sign()`. Used internally by the response-signing middleware in each framework adapter. Import from `kxco-post-quantum-webhook/response-core`.

### `isStreamingBody(body)` → `boolean`

Returns `true` if `body` is a Node.js Readable stream or a Web `ReadableStream`. Response-signing middleware uses this to skip signing on streaming routes. Import from `kxco-post-quantum-webhook/response-core`.

### `verifiedFetch(url, init, opts)` → `Promise<{ response, kxcoResponse }>`

Fetch-and-verify in one call. Buffers the response body, runs the verifier, then returns a re-wrapped `Response` that can still be `.json()`-ed or `.text()`-ed. Import from `kxco-post-quantum-webhook/verified-fetch`.

Throws `KxcoResponseError` before the caller can read the body when the signature fails. Pass `permissive: true` to return the result even on failure.

```
opts:
  verifier    Verifier      — from createVerifier()
  permissive  boolean?      — if true, return result even when !ok instead of throwing
  fetchImpl   function?     — custom fetch implementation
```

### `KxcoResponseError`

Thrown by `verifiedFetch` on signature failure. Import from `kxco-post-quantum-webhook/verified-fetch`.

```
err.kxcoResponse   VerifyResult   — the full verification result
err.response       Response       — the unverified response (buffered body)
err.code           string         — 'kxco_response_unverified'
```

### `webhook`

Re-export of the low-level webhook namespace from `kxco-post-quantum`. Use this if you want to drop below the opinionated builders and call `signDelivery` / `verifyDelivery` directly.

---

## Response signing

The same wire format applies to outbound API responses. Mount the response-signing middleware on specific routes so recipients can verify API responses with the same verifier they use for webhooks.

```js
// Express — opt-in per route
import { createSigner }                   from 'kxco-post-quantum-webhook'
import { pqResponseSigner }               from 'kxco-post-quantum-webhook/express'

const signer = createSigner({ pqSecretKey: kp.secretKey, pqKid: kid })

app.post('/api/order',
  pqResponseSigner({ signer }),
  (req, res) => res.json({ orderId: 'ord_123' }),
)
```

The same pattern is available for Fastify (`pqResponseSignerPlugin`), Hono (`pqResponseSigner`), Cloudflare Workers (`withPqResponseSigning`), and Vercel Node Functions (`pqResponseSigner`).

Do not mount response-signing middleware on streaming routes (SSE, chunked transfer). The middleware buffers the full body to compute the signature envelope.

---

## What this does NOT do

**Payload encryption** — signatures prove origin and integrity; they do not hide the content. For encrypted payloads, use [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault).

**Identity credentials** — this package does not issue, verify, or manage identity documents. For KYC-backed identity credentials tied to ML-DSA-65 keys, use [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk).

**JWT signing or JWKS endpoints** — JWT envelopes have different semantics (JOSE `alg` fields, header/payload separation, JWKS discovery). ML-DSA-65 signatures at ~3 KB also exceed browser cookie limits, making JWT use impractical. Not in scope.

**Generic HTTP security** — CSRF, rate limiting, mTLS, and other HTTP-security concerns belong in your existing stack. This package does one thing: sign and verify webhook and API response payloads.

---

## Part of the KXCO stack

| Package | What it does |
|---------|--------------|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65 + ML-KEM-768 primitives; keypair derivation; fingerprinting |
| `kxco-post-quantum-webhook` | Webhook and API response signing + verification (this package) |
| [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) | `kxco-pq` binary for keygen, fingerprint, and signed rotation manifests |
| [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) | Browser-safe verifier for deploy attestations and webhook deliveries |

---

## Compatibility

- Node.js >= 18 (uses native `crypto.subtle` via `@noble/post-quantum`)
- Cloudflare Workers, Deno Deploy, Vercel Edge, Bun
- Any modern browser via a bundler (Express and Fastify adapters are server-only)

---

## Security

All signing and verification delegates to [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which wraps [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) — audited by Cure53 (2024). HMAC-SHA256 uses the Node.js built-in `crypto` module. No outbound network calls are made; this is a pure signing and verification layer.

Keep private keys in environment variables or a KMS. Never log `pqSecretKey` or `hmacSecret`. Use `required: 'both'` in production unless you have a documented reason not to.

To report a vulnerability, open a [private security advisory](https://github.com/JackKXCO/kxco-post-quantum-webhook/security/advisories/new) or email security@kxco.ai.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE). The upstream signer ([`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum)) is MIT. The split is deliberate — receivers of this package can audit the verification path in isolation.

---

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
