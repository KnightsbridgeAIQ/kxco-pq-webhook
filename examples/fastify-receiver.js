// Example: Fastify webhook receiver.
//
//   node examples/fastify-receiver.js
//   curl -X POST http://localhost:3000/webhooks/kxco -d '{"hello":"world"}' \
//     -H 'X-KXCO-Signature: sha256=...'

import Fastify           from 'fastify'
import { createVerifier } from 'kxco-post-quantum-webhook'
import pqWebhookPlugin    from 'kxco-post-quantum-webhook/fastify'

const app = Fastify()

await app.register(pqWebhookPlugin, {
  verifier: createVerifier({
    hmacSecret:   process.env.WEBHOOK_HMAC_SECRET,
    pqPublicKey:  process.env.KXCO_PQ_PUBLIC_KEY_HEX,
    pinnedKid:    process.env.KXCO_PQ_KID,
    required:     'both',
  }),
  // The plugin's content-type parser captures the raw body bytes (Fastify
  // would otherwise auto-parse JSON, destroying the signed envelope).
})

app.post('/webhooks/kxco', async (req, reply) => {
  // req.kxcoWebhook is the structured verify result.
  // If the signature failed, the plugin already sent a 401 before reaching here.
  const event = JSON.parse(req.body.toString('utf-8'))
  console.log('verified webhook:', req.kxcoWebhook, event)
  return { ok: true }
})

await app.listen({ port: 3000 })
console.log('listening on :3000')
