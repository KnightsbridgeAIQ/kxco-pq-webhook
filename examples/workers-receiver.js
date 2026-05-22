// Example: Cloudflare Workers webhook receiver.
//
// Deploy with `wrangler deploy`. The verifier pubkey + secrets come from
// Wrangler environment vars / secrets:
//   wrangler secret put WEBHOOK_HMAC_SECRET
//   wrangler secret put KXCO_PQ_PUBLIC_KEY_HEX
//   wrangler secret put KXCO_PQ_KID
//
// This same code runs unchanged on Deno Deploy, Vercel Edge, Bun, or any
// other Fetch-API environment.

import { createVerifier }  from 'kxco-post-quantum-webhook'
import { withPqWebhook }   from 'kxco-post-quantum-webhook/workers'

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    if (request.method !== 'POST' || url.pathname !== '/webhooks/kxco') {
      return new Response('not found', { status: 404 })
    }

    const verifier = createVerifier({
      hmacSecret:  env.WEBHOOK_HMAC_SECRET,
      pqPublicKey: env.KXCO_PQ_PUBLIC_KEY_HEX,
      pinnedKid:   env.KXCO_PQ_KID,
      required:    'both',
    })

    return withPqWebhook(verifier, async (req, env, ctx, result) => {
      const body = await req.text()
      const event = JSON.parse(body)
      console.log('verified webhook on Workers:', result, event)
      return new Response(JSON.stringify({ ok: true }), {
        status:  200,
        headers: { 'Content-Type': 'application/json' },
      })
    })(request, env, ctx)
  },
}
