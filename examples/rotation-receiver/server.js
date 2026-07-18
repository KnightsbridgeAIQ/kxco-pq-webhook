// Multi-kid rotation receiver (Phase 5 — kxco-post-quantum-webhook ≥ 0.3.0).
//
// Use this pattern during a publisher's key-rotation window: the receiver
// accepts deliveries signed by EITHER the new kid or the old kid, then logs
// which kid actually signed each one so you can monitor the cutover.
//
// Setup:
//   npm install express kxco-post-quantum-webhook
//   KXCO_NEW_KID=...      KXCO_NEW_PUBKEY_HEX=...
//   KXCO_OLD_KID=...      KXCO_OLD_PUBKEY_HEX=...
//   KXCO_WEBHOOK_SECRET=...                              # optional, HMAC
//   PORT=4000 node server.js
//
// Two pieces of guidance hidden in this file:
//
//   1. `pinnedKids` resolves the matching pubkey from the X-KXCO-PQ-Kid header.
//      No need for if/else branches in your handler — the verifier picks
//      the right key automatically.
//
//   2. `resolvedKid` on the result tells you which kid was used. Log it.
//      During a rotation, you want to see traffic shift from the old kid
//      to the new kid; that field is how you measure cutover progress.

import express              from 'express'
import { createVerifier }   from 'kxco-post-quantum-webhook'
import { pqWebhook }        from 'kxco-post-quantum-webhook/express'

const app = express()

const verifier = createVerifier({
  hmacSecret: process.env.KXCO_WEBHOOK_SECRET,
  pinnedKids: [
    { kid: process.env.KXCO_NEW_KID, publicKey: process.env.KXCO_NEW_PUBKEY_HEX },
    { kid: process.env.KXCO_OLD_KID, publicKey: process.env.KXCO_OLD_PUBKEY_HEX },
  ],
  required: process.env.KXCO_WEBHOOK_SECRET ? 'both' : 'pq',
})

app.post('/webhooks/kxco',
  express.raw({ type: '*/*' }),
  pqWebhook(verifier),
  (req, res) => {
    const event = JSON.parse(req.body.toString('utf-8'))
    const v     = req.kxcoWebhook
    console.log(`[verified] resolved_kid=${v.resolvedKid} event=${event.event || '?'}`)
    res.json({ ok: true, kxco: { resolvedKid: v.resolvedKid } })
  },
)

const port = process.env.PORT || 4000
app.listen(port, () => console.log(`rotation-receiver listening on ${port}`))
