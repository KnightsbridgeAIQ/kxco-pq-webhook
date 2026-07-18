// Cloudflare Worker webhook receiver.
// wrangler.toml binds env vars; this fetch handler verifies and processes.
import { webhook } from 'kxco-post-quantum'

export default {
  async fetch(request, env) {
    if (request.method !== 'POST') {
      return new Response('method not allowed', { status: 405 })
    }

    const rawBody = await request.text()
    const headers = {}
    request.headers.forEach((v, k) => { headers[k.toLowerCase()] = v })

    const pinnedPubkey = Uint8Array.from(env.KXCO_PUBLIC_KEY_HEX.match(/.{2}/g).map(b => parseInt(b, 16)))

    const r = webhook.verifyDelivery({
      headers,
      rawBody,
      hmacSecret:  env.KXCO_WEBHOOK_SECRET,
      pqPublicKey: pinnedPubkey,
      pinnedKid:   env.KXCO_PUBLIC_KID,
    })

    if (!r.timestampOk || !r.kidOk || (!r.hmacOk && !r.pqOk)) {
      return new Response(JSON.stringify({ error: 'invalid' }), { status: 401 })
    }

    // Process event
    return new Response(JSON.stringify({ ok: true }), { status: 200 })
  },
}
