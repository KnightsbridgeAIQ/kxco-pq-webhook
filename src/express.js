// Express middleware adapter.
//
// USAGE:
//
//   import express  from 'express'
//   import { createVerifier }  from 'kxco-post-quantum-webhook'
//   import { pqWebhook }       from 'kxco-post-quantum-webhook/express'
//
//   const app = express()
//
//   // CRITICAL: the verifier needs the EXACT bytes of the body, so do NOT
//   // let any other body-parser run on the route first. Mount raw() first
//   // (or use express.json with the `verify` option that captures req.rawBody).
//   app.use('/webhooks/kxco',
//     express.raw({ type: '*/*' }),
//     pqWebhook(verifier),
//     (req, res) => {
//       const event = JSON.parse(req.body.toString('utf-8'))
//       res.json({ ok: true })
//     }
//   )
//
// The middleware sets:
//   req.kxcoWebhook = { ok, hmacOk, pqOk, timestampOk, kidOk, reason? }
//
// On verification failure: responds 401 with `{error, code, reason}` and
// does not call next(). To handle failures yourself, pass `{ throwOnFail: true }`
// — the middleware will then attach `req.kxcoWebhook` and call `next()` even
// on failure, letting your downstream handler decide.

/**
 * @typedef {import('./builders.js').Verifier} Verifier
 *
 * @typedef {Object} ExpressMiddlewareOpts
 * @property {boolean} [throwOnFail=false]  — if true, do not 401; pass control to next() with req.kxcoWebhook set
 */

/**
 * Build an Express middleware function for a configured verifier.
 *
 * @param {Verifier} verifier
 * @param {ExpressMiddlewareOpts} [opts]
 */
export function pqWebhook(verifier, opts = {}) {
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('pqWebhook: verifier must be a built verifier (use createVerifier)')
  }
  const throwOnFail = !!opts.throwOnFail
  return function kxcoWebhookMiddleware(req, res, next) {
    // Body must already be on req.body as a Buffer or string. If a JSON
    // body-parser has already parsed and replaced it with an object, the
    // signature is unverifiable — fail fast with a clear message.
    let body = req.body
    if (body && typeof body === 'object' && !Buffer.isBuffer(body) && !(body instanceof Uint8Array)) {
      const err = new Error('kxco-webhook: req.body has been parsed into an object before this middleware ran. Use express.raw() on the route, or pass the verify option to express.json to capture req.rawBody and assign it back to req.body before calling pqWebhook.')
      return next(err)
    }
    if (body === undefined && req.rawBody !== undefined) body = req.rawBody
    if (!body) body = ''
    const result = verifier.verify(req.headers, body)
    req.kxcoWebhook = result
    if (!result.ok && !throwOnFail) {
      return res.status(401).json({
        error: 'webhook signature verification failed',
        code:  'kxco_webhook_unverified',
        reason: result.reason,
      })
    }
    next()
  }
}
