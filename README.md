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

## See also

- [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) — primitives (ML-DSA-65, ML-KEM-768, HMAC envelope)
- [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) — browser-safe verifier for deploy attestations + webhook deliveries
- [`verify.kxco.ai`](https://verify.kxco.ai) — paste-URL verifier for the deploy-attestation flow (related but distinct from the webhook flow)
