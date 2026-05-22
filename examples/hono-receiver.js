// Example: Hono webhook receiver (works on Cloudflare Workers, Deno, Bun,
// Node 20+ via @hono/node-server, etc.)
//
//   npm i hono @hono/node-server
//   node examples/hono-receiver.js

import { Hono }          from 'hono'
import { serve }         from '@hono/node-server'
import { createVerifier } from 'kxco-post-quantum-webhook'
import { pqWebhook }      from 'kxco-post-quantum-webhook/hono'

const verifier = createVerifier({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqPublicKey: process.env.KXCO_PQ_PUBLIC_KEY_HEX,
  pinnedKid:   process.env.KXCO_PQ_KID,
  required:    'both',
})

const app = new Hono()

app.use('/webhooks/kxco', pqWebhook(verifier))

app.post('/webhooks/kxco', async (c) => {
  // c.get('kxcoWebhook') is the verify result. The middleware already
  // returned 401 if verification failed.
  const event = await c.req.json()
  console.log('verified webhook:', c.get('kxcoWebhook'), event)
  return c.json({ ok: true })
})

serve({ fetch: app.fetch, port: 3000 })
console.log('listening on :3000')
