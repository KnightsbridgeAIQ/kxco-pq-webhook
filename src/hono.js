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

import { signResponse, isStreamingBody } from './response-core.js'

/**
 * @typedef {import('./builders.js').Verifier} Verifier
 * @typedef {import('./builders.js').Signer}   Signer
 *
 * @typedef {Object} HonoMiddlewareOpts
 * @property {boolean} [throwOnFail=false]
 *
 * @typedef {Object} HonoResponseSignerOpts
 * @property {Signer}  signer
 * @property {string}  [event]
 * @property {boolean} [strict=false]
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

/**
 * Hono response-signing middleware. Mount on routes that should sign their
 * outbound responses. After the inner handler resolves, captures the
 * Response body, signs `${ts}.${body}`, returns a new Response with the
 * signing headers attached.
 *
 *   const app = new Hono()
 *   app.use('/api/*', pqResponseSigner({ signer }))
 *   app.get('/api/health', (c) => c.json({ ok: true }))
 *
 * @param {HonoResponseSignerOpts} opts
 */
export function pqResponseSigner(opts) {
  if (!opts || !opts.signer || typeof opts.signer.sign !== 'function') {
    throw new TypeError('pqResponseSigner (hono): opts.signer must be a built signer (use createSigner)')
  }
  const { signer, event, strict = false } = opts

  return async function kxcoHonoResponseSigner(c, next) {
    await next()
    // After the handler runs, c.res is the Response it produced.
    const res = c.res
    if (!res) return
    // Buffer the body so we can sign it. NOTE: this middleware is unsuitable
    // for streaming routes (SSE etc.) because .text() drains the stream;
    // don't mount it on routes that need streaming. `strict:true` causes the
    // pre-read to throw if the user wants explicit failure for any genuinely
    // unbuffered body; default lets it through (the stream will still be
    // drained, just signed).
    if (strict && res.body && typeof res.body.getReader === 'function' && res.headers.get('content-length') == null) {
      throw new Error('pqResponseSigner: streaming response body cannot be signed (set strict:false to allow buffering)')
    }
    const cloned = res.clone()
    const bodyText = await cloned.text()
    const headers  = signResponse(signer, bodyText, { event })
    const newHeaders = new Headers(res.headers)
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === 'content-type' && newHeaders.get('content-type')) continue
      newHeaders.set(k, v)
    }
    c.res = new Response(bodyText, { status: res.status, statusText: res.statusText, headers: newHeaders })
  }
}
