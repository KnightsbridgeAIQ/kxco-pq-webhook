# kxco-post-quantum-webhook

[![npm](https://img.shields.io/npm/v/kxco-post-quantum-webhook?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-post-quantum-webhook)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![verify](https://img.shields.io/badge/verify-kxco--verify-b0964f)](https://www.npmjs.com/package/kxco-verify)

**Drop-in webhook signing + verification with hybrid HMAC-SHA-256 + ML-DSA-65 (NIST FIPS 204) signatures.** Apache 2.0. Adapters for **Express, Fastify, Hono, Cloudflare Workers, Vercel Functions**. The signing primitive is upstream [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) — this package adds opinionated builders, a one-line client SDK, and the framework glue.

> **Why hybrid?** HMAC alone is post-quantum-secure as a MAC but offers no non-repudiation. ML-DSA-65 alone gives non-repudiation but requires every receiver to fetch and pin a public key. Sending both gives you the lightest receiver path AND a future-quantum-resistant audit trail in the same delivery.

---

## Install

```bash
npm install kxco-post-quantum-webhook kxco-post-quantum
```

`kxco-post-quantum` is a peer dependency — your app supplies the version.

---

## Send a signed webhook

```js
import { mlDsa, fingerprint }      from 'kxco-post-quantum'
import { createSigner, signedFetch } from 'kxco-post-quantum-webhook'

const kp  = mlDsa.keypairFromMaster(process.env.KEY_MASTER, 'my-app-v1')
const kid = fingerprint(kp.publicKey)

const signer = createSigner({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqSecretKey: kp.secretKey,
  pqKid:       kid,
})

await signedFetch('https://receiver.example.com/webhooks/kxco', {
  signer,
  body:  { event: 'invoice.paid', amount: 12500 },
  event: 'invoice.paid',
})
```

---

## Receive + verify (per framework)

Pick your stack. All adapters set a `verifier` policy on every request and respond with `401` + structured JSON when verification fails.

### Express

```js
import express                   from 'express'
import { createVerifier }        from 'kxco-post-quantum-webhook'
import { pqWebhook }             from 'kxco-post-quantum-webhook/express'

const verifier = createVerifier({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqPublicKey: process.env.SENDER_PQ_PUBKEY_HEX,
  pinnedKid:   process.env.SENDER_PQ_KID,
  required:    'both',
})

const app = express()

// express.raw() captures the EXACT body bytes — needed because the signature
// is over the bytes, not the parsed JSON object.
app.post('/webhooks/kxco',
  express.raw({ type: '*/*' }),
  pqWebhook(verifier),
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf-8'))
    res.json({ ok: true, kxco: req.kxcoWebhook })
  },
)
```

### Fastify

```js
import Fastify                    from 'fastify'
import { createVerifier }         from 'kxco-post-quantum-webhook'
import pqWebhookPlugin            from 'kxco-post-quantum-webhook/fastify'

const app = Fastify()
await app.register(pqWebhookPlugin, { verifier /* same as above */ })

app.post('/webhooks/kxco', async (req) => ({
  ok:   req.kxcoWebhook.ok,
  body: JSON.parse(req.body.toString('utf-8')),
}))
```

### Hono (Workers, Bun, Deno, Node)

```js
import { Hono }              from 'hono'
import { createVerifier }    from 'kxco-post-quantum-webhook'
import { pqWebhook }         from 'kxco-post-quantum-webhook/hono'

const app = new Hono()
app.use('/webhooks/kxco', pqWebhook(verifier))
app.post('/webhooks/kxco', async (c) => c.json({ ok: true, kxco: c.get('kxcoWebhook') }))
```

### Cloudflare Workers (or any Fetch-API runtime)

```js
import { createVerifier }    from 'kxco-post-quantum-webhook'
import { withPqWebhook }     from 'kxco-post-quantum-webhook/workers'

export default {
  fetch: withPqWebhook(verifier, async (req, env, ctx, result) => {
    const event = JSON.parse(await req.text())
    return new Response(JSON.stringify({ ok: true, kxco: result, event }))
  }),
}
```

### Vercel Functions (Node runtime)

```js
import { createVerifier }    from 'kxco-post-quantum-webhook'
import { nodePqWebhook }     from 'kxco-post-quantum-webhook/vercel'

// CRITICAL: disable Vercel's body parser so we receive the raw bytes
export const config = { api: { bodyParser: false } }

export default nodePqWebhook(verifier, async (req, res) => {
  const event = JSON.parse(req.rawBody.toString('utf-8'))
  res.status(200).json({ ok: true, kxco: req.kxcoWebhook })
})
```

For Vercel's **Edge** runtime, use the Workers adapter (`withPqWebhook`) — same code.

---

## The `required` policy

`createVerifier({ required })` controls what counts as "verified":

| `required` | Verdict `ok = true` requires |
|---|---|
| `'hmac'`   | Valid HMAC signature only |
| `'pq'`     | Valid ML-DSA-65 signature only |
| `'both'`   | Both signatures valid — **default; recommended** |
| `'either'` | Either signature passing — useful during HMAC→dual migration |

On failure the result includes a `reason`:

```jsonc
{
  "ok": false,
  "hmacOk": true,
  "pqOk":   false,
  "timestampOk": true,
  "kidOk":  true,
  "reason": "pq_invalid"
}
```

Full reason vocabulary in [`docs/webhook-contract.md`](./docs/webhook-contract.md).

---

## Wire format

The signature covers `${timestamp}.${rawBody}`. The headers sent:

| Header | Description |
|---|---|
| `X-KXCO-Timestamp` | Unix seconds, decimal string |
| `X-KXCO-Signature` | `sha256=<64 hex chars>` HMAC-SHA-256 |
| `X-KXCO-PQ-Signature` | `ml-dsa-65=<6618 hex chars>` ML-DSA-65 |
| `X-KXCO-PQ-Kid` | 16 hex chars — SHA-256(pubKeyBytes)[:8] |
| `X-KXCO-Event` | (optional) sender's event name |
| `X-KXCO-Delivery` | (optional) idempotency / trace ID |

Full spec in [`docs/webhook-contract.md`](./docs/webhook-contract.md). The contract is language-neutral — anyone can re-implement the verifier in Rust, Go, Python, etc. against the canonical math.

---

## Compatibility

- **Node**: ≥ 18 (uses native `crypto.subtle` via `@noble/post-quantum`)
- **Browsers**: works in any modern browser via a bundler. `Express` / `Fastify` adapters are server-only; the rest run anywhere with Fetch.
- **Edge runtimes**: Cloudflare Workers, Deno Deploy, Vercel Edge, Bun.

---

## Independent verification

A receiver who doesn't use this library can verify deliveries with [`kxco-verify`](https://www.npmjs.com/package/kxco-verify), or by re-implementing the math from the [contract spec](./docs/webhook-contract.md). The crypto primitives are wholly upstream in `@noble/post-quantum`.

---

## License

Apache 2.0 — see [LICENSE](./LICENSE). The upstream signer ([`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum)) is MIT; the two are deliberately separately-licensed so a receiver of this package can audit the verification path in isolation.

---

## Response signing (new in 0.2.0)

Same wire format as webhook signing, applied to outbound API responses. A receiver verifying webhooks from your platform can verify your API responses with **zero additional code**. The headers, kid, envelope (`${ts}.${body}`), and `required` policy are all identical.

### Sign API responses (per-framework)

```js
// Express
import { createSigner }       from 'kxco-post-quantum-webhook'
import { pqResponseSigner }   from 'kxco-post-quantum-webhook/express'

const signer = createSigner({ pqSecretKey: kp.secretKey, pqKid: kid })

app.post('/api/order',
  pqResponseSigner({ signer }),       // mount per-route, opt-in
  (req, res) => res.json({ orderId: 'ord_123' }),
)
```

Same shape for Fastify (`pqResponseSignerPlugin`), Hono (`pqResponseSigner` middleware), Cloudflare Workers (`withPqResponseSigning(signer, handler)`), and Vercel Node Functions (`pqResponseSigner({ signer })(handler)`).

**Per-route, never global.** The middleware patches the response object for THIS request only — it does not monkeypatch `res.send` for the entire app. Existing 0.1.0 users who don't import the new middleware see zero behaviour change after upgrading.

### `verifiedFetch` — receive + verify in one call

```js
import { createVerifier }   from 'kxco-post-quantum-webhook'
import { verifiedFetch, KxcoResponseError } from 'kxco-post-quantum-webhook/verified-fetch'

const verifier = createVerifier({
  pqPublicKey: PARTNER_PQ_PUBKEY_HEX,
  pinnedKid:   PARTNER_PQ_KID,
  required:    'pq',
})

try {
  const { response, kxcoResponse } = await verifiedFetch(
    'https://partner-api.example.com/orders/123',
    {},
    { verifier },
  )
  // Body is safe to read — signature has been verified
  const order = await response.json()
} catch (err) {
  if (err instanceof KxcoResponseError) {
    console.error('signature failed:', err.kxcoResponse.reason)
    // Unverified bytes are accessible via err.response if you really want them
  }
}
```

`verifiedFetch` throws `KxcoResponseError` **before** the caller can read the body when the signature fails (strict default). This prevents unverified bytes from leaking into application logic by accident. Pass `permissive: true` to get the result back even on failure.

### Streaming caveat

Response signing requires the full body to compute the envelope. **Don't mount the response-signing middleware on streaming routes** (SSE, chunked transfer). With `strict: true` an attempt to sign a streaming response throws; with the default `strict: false` the body is buffered (defeating the streaming purpose).

---

## Key rotation (new in 0.3.0)

A verifier can accept multiple kids during a rotation window — useful when the publisher cuts over to a new key but receivers may still hold in-flight deliveries signed by the old one.

```js
import { createVerifier } from 'kxco-post-quantum-webhook'

const verifier = createVerifier({
  pinnedKids: [
    { kid: '<new-kid>', publicKey: '<new-pubkey-hex>' },   // active
    { kid: '<old-kid>', publicKey: '<old-pubkey-hex>' }    // retiring
  ],
  required: 'pq',
})

const r = verifier.verify(req.headers, req.body)
//  → { ok: true, resolvedKid: '<which kid was used for this delivery>', ... }
```

`pinnedKid` (singular) continues to work unchanged and is mutually exclusive with `pinnedKids`. Use the singular form when you don't yet hold rotation history; upgrade to the multi-kid form **before** the publisher rotates.

For the operator side — generating new keypairs, building signed rotation manifests, publishing the multi-kid `.well-known/kxco-pq-pubkey` doc — use the companion CLI:

```bash
npx kxco-pq rotate \
  --old-secret @./current-keys/secret-key.hex \
  --old-kid    <current-kid> \
  --new-master <fresh-32-byte-master-hex> \
  --info       'my-publisher-v2' \
  --issuer     'publisher.example.com' \
  --out-dir    ./rotated
```

Full sequence (notify receivers → publish well-known + manifest → cut over signer → drain window → retire old kid) is in [`docs/key-rotation-playbook.md`](./docs/key-rotation-playbook.md). The wire-format spec for the multi-kid `.well-known` and the rotation manifest is in [`docs/webhook-contract.md`](./docs/webhook-contract.md#key-rotation-and-history) — language-neutral, so receivers in Rust/Go/Python can implement the same flow.

---

## Non-goals

This package will deliberately not grow into the following. Each was considered and rejected with explicit reasoning:

| | What we won't do | Why |
|---|---|---|
| **JWT signing/verification** | This is its own concern. JWT envelopes are different (JOSE `alg` fields, JWKS endpoints, header/payload separation), the wire-format risk to a draft-IETF `alg` name is real, and ML-DSA-65 token sizes break browser cookies (~5 KB > 4 KB hard limit). |
| **JWKS / public-key hosting** | Either every adopter hosts their own endpoint or KXCO becomes a centralised trust authority. Both options were rejected in Phase 2 council review for the same reasons — institutions sign with their own keys, KXCO endorses nobody. Pin keys out of band. |
| **Generic HTTP-security framework** | Webhook + response signing share the same wire format (envelope, headers, kid, policy). That's the scope. We will not add CSRF, rate-limiting, JWT verification, mTLS helpers, or anything else web-security adjacent — those belong in separate packages or your existing stack. |
| **DKIM-PQ / email signing** | Requires MTA-level adoption (Postfix, OpenDKIM) and receiver-side support at scale. IETF DKIM-PQ work is too early — shipping a library now signs into a void. Deferred indefinitely; revisit when there's a draft at IETF WGLC and at least one major MTA ships verification support. |
| **Hosted signing service** | KXCO Lab does not operate a hosted signing endpoint as part of this package. The signer runs in the publisher's process holding the publisher's private key. The only KXCO-hosted thing in this ecosystem is the [verify.kxco.ai](https://verify.kxco.ai) verifier (which uses the publisher's own published public key — KXCO performs no policy). |

If you need any of the above, build it as a separate package on top of this one. The wire-format spec in [`docs/webhook-contract.md`](./docs/webhook-contract.md) is language-neutral and stable across the 0.x line.

---

## See also

- [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) — primitives (ML-DSA-65, ML-KEM-768, HMAC envelope)
- [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) — `kxco-pq` binary for keygen / fingerprint / signed rotation manifests
- [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) — browser-safe verifier for deploy attestations + webhook deliveries
- [`verify.kxco.ai`](https://verify.kxco.ai) — paste-URL verifier for the deploy-attestation flow (related but distinct from the webhook flow)

## Maintainers

Shayne Heffernan · John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)

Deployed in production at [target150.com](https://target150.com), [knightsbridgelaw.com](https://knightsbridgelaw.com), [livetradingnews.com](https://livetradingnews.com).
