// AWS Lambda webhook receiver for API Gateway proxy events.
// Deploy: zip with kxco-post-quantum, set the three env vars, point an HTTP
// API at the function. The handler returns 200 on success, 401 otherwise.
import { webhook } from 'kxco-post-quantum'

const PINNED_KID    = process.env.KXCO_PUBLIC_KID
const PINNED_PUBKEY = Buffer.from(process.env.KXCO_PUBLIC_KEY_HEX, 'hex')
const HMAC_SECRET   = process.env.KXCO_WEBHOOK_SECRET

export const handler = async (event) => {
  // API Gateway gives us the body as a string; if base64-encoded, decode first.
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body, 'base64').toString('utf8')
    : event.body

  const headers = {}
  for (const [k, v] of Object.entries(event.headers || {})) {
    headers[k.toLowerCase()] = v
  }

  const r = webhook.verifyDelivery({
    headers,
    rawBody,
    hmacSecret:  HMAC_SECRET,
    pqPublicKey: PINNED_PUBKEY,
    pinnedKid:   PINNED_KID,
  })

  if (!r.timestampOk || !r.kidOk || (!r.hmacOk && !r.pqOk)) {
    return { statusCode: 401, body: JSON.stringify({ error: 'invalid' }) }
  }

  // Process event
  return { statusCode: 200, body: JSON.stringify({ ok: true }) }
}
