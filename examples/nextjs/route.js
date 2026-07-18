// Next.js 13+ App Router route handler.
// File:  app/api/webhooks/kxco/route.js
//
// Capture the raw body with Request.text() — do NOT call request.json() before
// verifying. Whitespace and key-order normalisation will break the signature.
import { webhook } from 'kxco-post-quantum'

const PINNED_KID    = process.env.KXCO_PUBLIC_KID
const PINNED_PUBKEY = Buffer.from(process.env.KXCO_PUBLIC_KEY_HEX, 'hex')
const HMAC_SECRET   = process.env.KXCO_WEBHOOK_SECRET

export async function POST(request) {
  const rawBody = await request.text()

  const headers = {}
  request.headers.forEach((v, k) => { headers[k.toLowerCase()] = v })

  const r = webhook.verifyDelivery({
    headers,
    rawBody,
    hmacSecret:  HMAC_SECRET,
    pqPublicKey: PINNED_PUBKEY,
    pinnedKid:   PINNED_KID,
  })
  if (!r.timestampOk) return Response.json({ error: 'stale timestamp' }, { status: 401 })
  if (!r.kidOk)       return Response.json({ error: 'unknown kid' }, { status: 401 })
  if (!r.hmacOk && !r.pqOk) return Response.json({ error: 'invalid signature' }, { status: 401 })

  const event = JSON.parse(rawBody)
  // Process the event
  return Response.json({ ok: true })
}
