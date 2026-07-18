// Vercel Edge Function — same code as Next.js App Router, with edge runtime.
// File:  app/api/webhooks/kxco/route.js
//
// Note: Vercel Edge runs on V8 isolates without full Node.js. Confirm
// kxco-post-quantum imports cleanly in your project (it depends only on
// @noble/post-quantum which is pure JS and edge-compatible).
import { webhook } from 'kxco-post-quantum'

export const runtime = 'edge'

const PINNED_KID = process.env.KXCO_PUBLIC_KID
const HMAC_SECRET = process.env.KXCO_WEBHOOK_SECRET

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

const PINNED_PUBKEY = hexToBytes(process.env.KXCO_PUBLIC_KEY_HEX)

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

  if (!r.timestampOk || !r.kidOk || (!r.hmacOk && !r.pqOk)) {
    return Response.json({ error: 'invalid' }, { status: 401 })
  }

  // Process event
  return Response.json({ ok: true })
}
