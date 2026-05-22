// Example: Vercel Node-runtime Function (drop this at /api/webhooks/kxco.js
// in a Next.js / Vercel project).
//
// For the Edge runtime (`export const config = { runtime: 'edge' }`), use
// the Workers adapter instead — see examples/workers-receiver.js.

import { createVerifier } from 'kxco-post-quantum-webhook'
import { nodePqWebhook }  from 'kxco-post-quantum-webhook/vercel'

// CRITICAL: disable Vercel's default body parser so we get the raw bytes
// (the signature is over the exact bytes — re-stringification breaks verification).
export const config = { api: { bodyParser: false } }

const verifier = createVerifier({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqPublicKey: process.env.KXCO_PQ_PUBLIC_KEY_HEX,
  pinnedKid:   process.env.KXCO_PQ_KID,
  required:    'both',
})

export default nodePqWebhook(verifier, async (req, res) => {
  // The wrapper buffered the body into req.rawBody as a Buffer.
  const event = JSON.parse(req.rawBody.toString('utf-8'))
  console.log('verified webhook on Vercel:', req.kxcoWebhook, event)
  res.status(200).json({ ok: true })
})
