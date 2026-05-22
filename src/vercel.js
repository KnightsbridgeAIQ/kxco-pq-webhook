// Vercel Functions adapter.
//
// Vercel Functions come in two flavours:
//
// 1. Node.js runtime (default for /api/*.js) — req/res are the Node IncomingMessage / ServerResponse.
//    Use `nodePqWebhook(verifier, handler)` — analogous to the Express middleware.
//
// 2. Edge runtime (export const config = { runtime: 'edge' }) — handler signature is
//    `(request: Request) => Response | Promise<Response>`. Use the workers adapter:
//    import { withPqWebhook } from 'kxco-post-quantum-webhook/workers'
//
// USAGE (Node functions, /api/webhooks/kxco.js):
//
//   import { createVerifier }   from 'kxco-post-quantum-webhook'
//   import { nodePqWebhook }    from 'kxco-post-quantum-webhook/vercel'
//
//   export const config = { api: { bodyParser: false } }   // CRITICAL — see below
//
//   export default nodePqWebhook(verifier, async (req, res) => {
//     const body = req.rawBody.toString('utf-8')
//     const event = JSON.parse(body)
//     res.status(200).json({ ok: true, event })
//   })
//
// CRITICAL: `bodyParser: false` is required so Vercel does not consume the
// request stream before the signature can be verified. The wrapper buffers
// the body into `req.rawBody` (a Buffer) and re-exposes it to the handler.

import { signResponse, isStreamingBody } from './response-core.js'

/**
 * @typedef {import('./builders.js').Verifier}      Verifier
 * @typedef {import('./builders.js').VerifyResult}  VerifyResult
 * @typedef {import('./builders.js').Signer}        Signer
 */

/**
 * Wrap a Vercel Node-runtime function with PQ webhook verification.
 *
 * @param {Verifier} verifier
 * @param {(req: any, res: any) => any | Promise<any>} handler
 * @param {{ throwOnFail?: boolean }} [opts]
 */
export function nodePqWebhook(verifier, handler, opts = {}) {
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('nodePqWebhook: verifier must be a built verifier (use createVerifier)')
  }
  if (typeof handler !== 'function') {
    throw new TypeError('nodePqWebhook: handler must be a function')
  }
  const throwOnFail = !!opts.throwOnFail

  return async function kxcoVercelHandler(req, res) {
    let rawBody
    try {
      rawBody = await readBody_(req)
    } catch (err) {
      res.status(400).json({ error: 'failed to read request body', code: 'kxco_body_read_failed', detail: err.message })
      return
    }
    req.rawBody = rawBody
    const result = verifier.verify(req.headers, rawBody)
    req.kxcoWebhook = result
    if (!result.ok && !throwOnFail) {
      res.status(401).json({
        error:  'webhook signature verification failed',
        code:   'kxco_webhook_unverified',
        reason: result.reason,
      })
      return
    }
    return handler(req, res)
  }
}

/**
 * Vercel Node-runtime response signer. Patches `res.send`/`res.json` on THIS
 * response only — never global — so the outbound body is signed before it
 * leaves the function.
 *
 *   export const config = { api: { bodyParser: true } }   // OK on send-side
 *
 *   export default pqResponseSigner({ signer })(async (req, res) => {
 *     res.status(200).json({ ok: true })
 *   })
 *
 * Note: this is a function-factory — call `pqResponseSigner({ signer })`
 * once and pass the result your handler.
 *
 * @param {{ signer: Signer, event?: string, strict?: boolean }} opts
 */
export function pqResponseSigner(opts) {
  if (!opts || !opts.signer || typeof opts.signer.sign !== 'function') {
    throw new TypeError('pqResponseSigner (vercel): opts.signer must be a built signer (use createSigner)')
  }
  const { signer, event, strict = false } = opts
  return function wrap(handler) {
    return async function kxcoVercelResponseSigner(req, res) {
      const origSend = res.send?.bind(res) || res.end.bind(res)
      const origJson = res.json?.bind(res)

      function attachAndSend(body) {
        if (isStreamingBody(body)) {
          if (strict) throw new Error('pqResponseSigner: streaming response body cannot be signed (set strict:false to send unsigned)')
          return origSend(body)
        }
        const headers = signResponse(signer, body, { event })
        for (const [k, v] of Object.entries(headers)) {
          if (k.toLowerCase() === 'content-type' && res.getHeader('content-type')) continue
          res.setHeader(k, v)
        }
        return origSend(body)
      }

      if (res.send) res.send = attachAndSend
      if (origJson) {
        res.json = function pqJson(body) {
          res.setHeader('Content-Type', 'application/json; charset=utf-8')
          return attachAndSend(JSON.stringify(body))
        }
      }

      return handler(req, res)
    }
  }
}

/**
 * Buffer a Node IncomingMessage into a Buffer. Caps at 1 MB to defend
 * against memory blow-up; webhooks rarely exceed a few KB.
 */
function readBody_(req, maxBytes = 1_048_576) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let total = 0
    req.on('data', chunk => {
      total += chunk.length
      if (total > maxBytes) {
        reject(new Error(`request body exceeds ${maxBytes} bytes`))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', err => reject(err))
  })
}
