# kxco-post-quantum-webhook

**Dual-signed webhooks: HMAC-SHA256 and post-quantum ML-DSA-87 or ML-DSA-65 over the same bytes, so a receiver can prove who sent each delivery.**

[![npm](https://img.shields.io/npm/v/kxco-post-quantum-webhook?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum-webhook)
[![downloads](https://img.shields.io/npm/dm/kxco-post-quantum-webhook?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum-webhook)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-post-quantum-webhook)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-post-quantum-webhook)](https://socket.dev/npm/package/kxco-post-quantum-webhook)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-post-quantum-webhook.svg)](https://nodejs.org)

Post-quantum ML-DSA-87 and ML-DSA-65 webhook signing and verification. Sign outgoing webhook payloads so recipients can prove they came from you. Verify incoming webhooks before processing them. Drop-in replacement for HMAC-SHA256 webhook patterns, signed with a NIST-standardised post-quantum algorithm. An optional compact-JWS path is available for receivers whose stack already speaks JWS.

- **Two signatures over the same bytes.** A dual-signed delivery carries HMAC-SHA256 and ML-DSA-87 or ML-DSA-65, both over `${timestamp}.${rawBody}`, so a receiver checking either one is checking the same message.
- **Proof of origin a shared secret cannot give.** Only the sender holds the ML-DSA private key, so a receiver can prove to a third party that a delivery came from you, even if the HMAC secret has leaked.
- **Migrate with no flag day.** `required: 'either'` accepts HMAC-only and dual-signed deliveries side by side, and a single setting then tightens it to `'both'` or `'pq'`.
- **Rotate keys without dropping a delivery.** `pinnedKids` accepts several keys at once and `resolvedKid` names the one that verified, so deliveries signed by the retiring key keep verifying through the drain window.
- **A few lines in the framework you run.** Adapters for Express, Fastify, Hono, Cloudflare Workers and Vercel verify on the route and answer a failed signature with a 401 and its reason.
- **A wire format anyone can implement.** The [webhook contract](./docs/webhook-contract.md) is language-neutral, and an optional compact JWS uses the RFC 9964 `alg` names `ML-DSA-87` and `ML-DSA-65` for receivers whose stack already speaks JWS.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [Framework adapters](#framework-adapters) · [Key rotation](#key-rotation) · [For institutions](#for-institutions) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## When to use this

Use this package when you need proof that a webhook delivery came from a specific sender, as well as proof that the payload arrived unchanged.

HMAC-SHA256 is a shared secret: the sender and receiver both hold the key, so either party could have produced the signature. ML-DSA-65 is an asymmetric signature scheme: only the sender holds the private key, and anyone holding the corresponding public key can verify. That property is called non-repudiation, and it matters when:

- You are receiving webhooks from a partner and need to be certain they originated from that partner's infrastructure, not a replay or a man-in-the-middle.
- You are sending webhooks to customers who need to prove, to a third party, that a specific event was delivered by your platform and not fabricated by them.
- You are replacing HMAC-SHA256 webhook patterns with something that holds up against quantum computers.

This package sends both HMAC-SHA256 and ML-DSA signatures by default. Receivers can require either or both. During migration from HMAC-only setups, the `required: 'either'` policy lets receivers accept both old and new deliveries.

## Install

```bash
npm install kxco-post-quantum-webhook kxco-post-quantum
```

`kxco-post-quantum` is a peer dependency. Your application supplies the version.

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

// In your request handler: rawBody must be the exact bytes received
const result = verifier.verify(req.headers, rawBody)

if (!result.ok) {
  // result.reason is one of: timestamp_skew | kid_mismatch |
  // missing_hmac | missing_pq | hmac_invalid | pq_invalid
  return res.status(401).json({ error: result.reason })
}

// Signature is valid: safe to process
```

Framework adapters (Express, Fastify, Hono, Cloudflare Workers, Vercel) handle raw-body capture and the 401 response automatically. See the per-framework examples below.

## Framework adapters

Pick the adapter that matches your stack. Each one takes the `verifier` built in [Verify an incoming webhook](#verify-an-incoming-webhook).

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

Mount `express.raw()` on the route ahead of `pqWebhook`. The signature covers the exact body bytes, and `express.raw()` hands them to the verifier as received.

### Fastify

```js
import Fastify                            from 'fastify'
import { createVerifier }                 from 'kxco-post-quantum-webhook'
import pqWebhookPlugin                    from 'kxco-post-quantum-webhook/fastify'

const app = Fastify()
// Hand every body to the plugin as the exact bytes received
app.removeContentTypeParser(['application/json', 'text/plain'])
await app.register(pqWebhookPlugin, { verifier })

app.post('/webhooks/incoming', async (req) => ({
  ok:   req.kxcoWebhook.ok,
  body: JSON.parse(req.body.toString('utf-8')),
}))
```

With Fastify's built-in JSON and text parsers removed, the plugin's raw-body parser takes every request, so the verifier checks the bytes that were signed and `req.body` arrives as a Buffer.

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

On Vercel, run the route on the Node.js runtime and use this adapter.

## The `required` policy

`createVerifier({ required })` controls what counts as a passing verification:

| `required` | Passes when |
|---|---|
| `'both'` | Both HMAC and ML-DSA signatures are valid. The default, and the one for production |
| `'pq'` | ML-DSA signature is valid |
| `'hmac'` | HMAC-SHA256 signature is valid |
| `'either'` | Either signature passes, for migration from HMAC-only |

When `ok` is false, `result.reason` contains one of: `timestamp_skew`, `kid_mismatch`, `missing_hmac`, `missing_pq`, `hmac_invalid`, `pq_invalid`.

## Wire format

The signature envelope is `${timestamp}.${rawBody}`. Headers sent with every delivery:

| Header | Description |
|---|---|
| `X-KXCO-Timestamp` | Unix seconds |
| `X-KXCO-Signature` | `sha256=<64 hex chars>` HMAC-SHA256 |
| `X-KXCO-PQ-Signature` | `ml-dsa-65=<hex>` ML-DSA-65 signature, or `ml-dsa-87=<hex>` from an ML-DSA-87 key |
| `X-KXCO-PQ-Kid` | 16 hex chars: the first 8 bytes of the SHA-256 of the public key bytes |
| `X-KXCO-Event` | Optional event name |
| `X-KXCO-Delivery` | Optional idempotency / trace ID |

The full wire-format spec is in [`docs/webhook-contract.md`](./docs/webhook-contract.md). It is language-neutral: anyone can re-implement the verifier in Rust, Go, Python, or any other language against the canonical mathematics.

## Key rotation

When rotating signing keys, a verifier can accept multiple kids during the drain window: in-flight deliveries signed by the old key continue to verify until they expire.

```js
const verifier = createVerifier({
  pinnedKids: [
    { kid: '<new-kid>', publicKey: '<new-pubkey-hex>' },   // active
    { kid: '<old-kid>', publicKey: '<old-pubkey-hex>' }    // retiring
  ],
  required: 'pq',
})

const result = verifier.verify(req.headers, req.body)
// result.resolvedKid: which key was used for this delivery
```

`pinnedKid` (singular) continues to work unchanged and is mutually exclusive with `pinnedKids`.

Each key decides its own parameter set, so a rotation from an ML-DSA-65 key to
an ML-DSA-87 key is the same configuration: list both. Each `pinnedKids` entry may
carry the publisher's `algorithm` from its well-known document, and is refused
if it disagrees with the key.

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

## API

All exports from the main entry point (`kxco-post-quantum-webhook`):

### `createSigner(opts)` → `Signer`

Builds a reusable signing object. At least one of `hmacSecret` or `pqSecretKey` is required.

```
opts:
  hmacSecret   string | Buffer        // shared HMAC-SHA256 secret
  pqSecretKey  Buffer | Uint8Array    // ML-DSA-65 (4032 bytes) or ML-DSA-87 (4896 bytes) secret key; decides the header form
  pqKid        string                 // fingerprint of the matching public key; required when pqSecretKey is set

Returns:
  signer.sign(rawBody, { event?, deliveryId? }) → Record<string, string>
  signer.pqKid  string | undefined
  signer.pqAlgorithm  'ml-dsa-65' | 'ml-dsa-87' | undefined
```

An ML-DSA-87 key signs `X-KXCO-PQ-Signature: ml-dsa-87=<hex>` over the same
envelope. An ML-DSA-65 key signs exactly as before.

### `createVerifier(opts)` → `Verifier`

Builds a reusable verifier. At least one of `hmacSecret`, `pqPublicKey`, or `pinnedKids` is required.

```
opts:
  hmacSecret     string | Buffer               // shared HMAC-SHA256 secret
  pqPublicKey    string | Buffer | Uint8Array  // ML-DSA-65 (1952 bytes) or ML-DSA-87 (2592 bytes) public key, or hex
  pqAlgorithm    'ml-dsa-65' | 'ml-dsa-87'     // optional: the well-known `algorithm` for pqPublicKey; refused if it disagrees
  pinnedKid      string                        // required when pqPublicKey is set
  pinnedKids     Array<{ kid, publicKey, algorithm? }>  // multi-key form for rotation; mutually exclusive with pinnedKid/pqPublicKey
  windowSeconds  number                        // max clock skew in seconds (default: 300)
  required       'both' | 'pq' | 'hmac' | 'either'  // verification policy (default: 'both')

Returns:
  verifier.verify(headers, rawBody) → VerifyResult
  verifier.required  string

VerifyResult:
  ok            boolean   // overall verdict
  hmacOk        boolean   // HMAC check passed
  pqOk          boolean   // ML-DSA check passed, under the set the key belongs to
  timestampOk   boolean   // timestamp within windowSeconds
  kidOk         boolean   // kid header matched pinnedKid
  reason        string?   // when !ok: timestamp_skew | kid_mismatch | missing_hmac | missing_pq | hmac_invalid | pq_invalid
  resolvedKid   string?   // when pinnedKids[] matched: which kid was used
```

### `signedFetch(url, opts)` → `Promise<Response>`

Signs and POSTs a body in one call. Returns the raw fetch `Response` for every status code, 2xx or otherwise, just as `fetch` does.

```
url   string                    // absolute http(s) URL
opts:
  signer      Signer            // from createSigner()
  body        any               // JSON-stringified if not already a string or Buffer
  event       string?           // sets X-KXCO-Event header
  deliveryId  string?           // sets X-KXCO-Delivery header
  headers     Record<string, string>?  // merged after signing; signing headers take precedence
  method      string?           // default: 'POST'
  fetchImpl   function?         // custom fetch implementation; defaults to globalThis.fetch
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
  verifier    Verifier      // from createVerifier()
  permissive  boolean?      // if true, return result even when !ok instead of throwing
  fetchImpl   function?     // custom fetch implementation
```

### `KxcoResponseError`

Thrown by `verifiedFetch` on signature failure. Import from `kxco-post-quantum-webhook/verified-fetch`.

```
err.kxcoResponse   VerifyResult   // the full verification result
err.response       Response       // the unverified response (buffered body)
err.code           string         // 'kxco_response_unverified'
```

### `webhook`

Re-export of the low-level webhook namespace from `kxco-post-quantum`. Use this if you want to drop below the opinionated builders and call `signDelivery` / `verifyDelivery` directly.

## Response signing

The same wire format applies to outbound API responses. Mount the response-signing middleware on specific routes so recipients can verify API responses with the same verifier they use for webhooks.

```js
// Express, opt-in per route
import { createSigner }                   from 'kxco-post-quantum-webhook'
import { pqResponseSigner }               from 'kxco-post-quantum-webhook/express'

const signer = createSigner({ pqSecretKey: kp.secretKey, pqKid: kid })

app.post('/api/order',
  pqResponseSigner({ signer }),
  (req, res) => res.json({ orderId: 'ord_123' }),
)
```

The same pattern is available for Fastify (`pqResponseSignerPlugin`), Hono (`pqResponseSigner`), Cloudflare Workers (`withPqResponseSigning`), and Vercel Node Functions (`pqResponseSigner`).

Mount response-signing middleware on routes that return a complete body, and keep streaming routes (SSE, chunked transfer) on routes without it. The middleware buffers the full body to compute the signature envelope.

## Compatibility

- Node.js 20.19 and later, matching the `engines` field
- Cloudflare Workers with the `nodejs_compat` flag, Deno and Bun, which supply Node's `crypto` and `Buffer`
- Vercel on the Node.js runtime, through the Vercel adapter
- Browsers through a bundler that supplies Node's `crypto` and `Buffer`, with the Express and Fastify adapters on the server

## The optional JWS path

The `X-KXCO-*` header scheme above is the default and stays the default. It is what every existing receiver parses and it is smaller on the wire.

For a receiver whose stack already speaks JWS, such as a gateway, an IdP or a partner's verifier, there is a second path. For them, "add a JWS header" is a config change and "parse three bespoke headers" is a project.

```js
import { signBodyJws, verifyBodyJws, JWS_HEADER } from 'kxco-post-quantum-webhook'

// sender
headers[JWS_HEADER] = signBodyJws({
  rawBody, secretKey, kid,
  event: 'payment.settled',
  deliveryId: 'dlv_123',
  audience: 'https://acme.example/hooks',   // optional
})

// receiver
const result = verifyBodyJws({
  token: headers['x-kxco-jws'],
  rawBody,
  publicKey,
  pinnedKid: 'aa29f37ab7f4b2cf',
  audience: 'https://acme.example/hooks',
})
if (!result.valid) return reject(result.reason)
```

The token uses the RFC 9964 `alg` name for its key's set, `ML-DSA-87` or `ML-DSA-65`, so a JWS library that knows the registration can identify it.

**The payload is detached.** The claims carry `body_sha256`, not the body. Duplicating a webhook body into a header would double the bytes on the wire and give a lazy verifier two copies to disagree about. The digest binds the signature to exactly one body and to nothing else.

`iat` is checked against a 300 second window by default, the same as `X-KXCO-Timestamp`. `aud` is checked when you pass one.

The two paths are independent proofs of the same delivery. Attach either, or both.

## Examples

Receiver templates you can copy and run, for Express, Next.js, AWS Lambda, Cloudflare Workers, GitHub Actions, key rotation and response signing, live in [`./examples`](./examples).

## The KXCO post-quantum family

This signs webhooks and API responses, so a receiver can prove where a delivery
came from and that it arrived unchanged. The rest of the family covers the jobs
around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Releases from 1.2.5 carry a SLSA provenance attestation tying the published
tarball to the commit and workflow that built it: verify with
`npm audit signatures`, or read it from
`registry.npmjs.org/-/npm/v1/attestations/kxco-post-quantum-webhook@<version>`.
Each of those releases also publishes a CycloneDX SBOM as a GitHub Release asset
at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
unauthenticated URL. `kxco-post-quantum` is a peer dependency on a caret range, so your
application chooses the version that signs and a correctness fix in the base
package reaches you on the next install, with no release of this package.

## Security

**ML-DSA-87**, **ML-DSA-65** (NIST FIPS 204) and HMAC-SHA256, all from [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), with ML-DSA running on the OpenSSL 3.5 primitives where the runtime provides them. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on releases from 1.2.5: verify with `npm audit signatures`
- **CycloneDX SBOM** published with each of those releases
- `npm run evidence` regenerates this package's evidence bundle from source

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

Both signatures cover exactly the same bytes, and the timestamp is checked before either signature, so a delivery cannot be re-pointed at a different body or replayed once it falls outside the window. Signing and verification run locally, with no call to KXCO or to anyone else. The only requests the package makes are the ones `signedFetch` and `verifiedFetch` send for you.

Keep private keys in environment variables or a KMS. Never log `pqSecretKey` or `hmacSecret`. Use `required: 'both'` in production unless you have a documented reason not to.

To report a vulnerability, open a [private security advisory](https://github.com/KnightsbridgeAIQ/kxco-pq-webhook/security/advisories/new) or email **john@knightsbridgelaw.com**. Acknowledgement within 2 business days, triage decision within 5. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
