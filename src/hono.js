// Hono middleware adapter (also works for any framework that exposes a
// Fetch-style Request via `c.req.raw`).
//
// USAGE:
//
//   import { Hono }           from 'hono'
//   import { createVerifier } from 'kxco-post-quantum-webhook'
//   import { pqWebhook }      from 'kxco-post-quantum-webhook/hono'
//
//   const app = new Hono()
//   app.use('/webhooks/kxco', pqWebhook(verifier))
//
//   app.post('/webhooks/kxco', async (c) => {
//     // c.get('kxcoWebhook') is the verify result; if !ok, the middleware
//     // already returned 401 unless throwOnFail was set
//     return c.json({ ok: true })
//   })

/**
 * @typedef {import('./builders.js').Verifier} Verifier
 *
 * @typedef {Object} HonoMiddlewareOpts
 * @property {boolean} [throwOnFail=false]
 */

/**
 * @param {Verifier} verifier
 * @param {HonoMiddlewareOpts} [opts]
 */
export function pqWebhook(verifier, opts = {}) {
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('pqWebhook (hono): verifier must be a built verifier (use createVerifier)')
  }
  const throwOnFail = !!opts.throwOnFail

  return async function kxcoWebhookHono(c, next) {
    // We need the raw bytes so we don't lose the canonical body to JSON parsing.
    // c.req.raw is the underlying Request; clone it so the downstream handler
    // can still call c.req.json() / .text() if it wants.
    const cloned = c.req.raw.clone()
    const rawBody = await cloned.text()
    const result  = verifier.verify(c.req.raw.headers, rawBody)
    c.set('kxcoWebhook', result)
    if (!result.ok && !throwOnFail) {
      return c.json({
        error:  'webhook signature verification failed',
        code:   'kxco_webhook_unverified',
        reason: result.reason,
      }, 401)
    }
    await next()
  }
}
