// Example: Express webhook receiver.
//
//   node examples/express-receiver.js
//   curl -X POST http://localhost:3000/webhooks/kxco -d '{"hello":"world"}' \
//     -H 'X-KXCO-Signature: sha256=...'   # add real signing headers, of course
//
// Production setup: the verifier holds the pinned kid of whichever platform
// is sending the webhooks (KXCO Bank's well-known pubkey, in this example).

import express from 'express'
import { createVerifier } from 'kxco-post-quantum-webhook'
import { pqWebhook }      from 'kxco-post-quantum-webhook/express'

// 1. Pin the sender's public key + kid. In production, fetch the pubkey once
//    at startup from the platform's /.well-known endpoint and cache it.
//    For demo purposes we hardcode against a known KXCO Bank kid.
const verifier = createVerifier({
  hmacSecret:   process.env.WEBHOOK_HMAC_SECRET,         // shared secret out of band
  pqPublicKey:  process.env.KXCO_PQ_PUBLIC_KEY_HEX,      // 3904 hex chars
  pinnedKid:    process.env.KXCO_PQ_KID,                 // e.g. 'aa29f37ab7f4b2cf'
  windowSeconds: 300,                                    // reject deliveries older than 5 min
  required:      'both',                                 // demand both HMAC + ML-DSA-65
})

const app = express()

// CRITICAL: use express.raw() so the signature has the EXACT bytes to verify.
// If you let express.json() parse first, the body becomes an object and the
// canonical bytes are lost.
app.post('/webhooks/kxco',
  express.raw({ type: '*/*' }),
  pqWebhook(verifier),
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf-8'))
    console.log('verified webhook:', req.kxcoWebhook, event)
    res.json({ ok: true })
  },
)

app.listen(3000, () => console.log('listening on :3000'))
