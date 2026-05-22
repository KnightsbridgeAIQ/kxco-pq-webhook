// Fastify plugin.
//
// USAGE:
//
//   import Fastify           from 'fastify'
//   import { createVerifier } from 'kxco-post-quantum-webhook'
//   import pqWebhook          from 'kxco-post-quantum-webhook/fastify'
//
//   const app = Fastify()
//
//   await app.register(pqWebhook, {
//     verifier,
//     prefix: '/webhooks/kxco',   // optional; restricts the plugin to a path
//   })
//
//   app.post('/webhooks/kxco', async (request, reply) => {
//     // request.kxcoWebhook is the verify result; if !ok, the plugin already
//     // sent a 401 unless throwOnFail was set
//     return { ok: true }
//   })
//
// Internally the plugin:
//   1. Adds a content-type parser that captures the raw body bytes
//      (necessary because Fastify auto-parses JSON, destroying the canonical
//      bytes the signature covers)
//   2. Adds a preHandler hook that runs verifier.verify() and decorates
//      request.kxcoWebhook

import { signResponse, isStreamingBody } from './response-core.js'

/**
 * @typedef {import('./builders.js').Verifier} Verifier
 * @typedef {import('./builders.js').Signer}   Signer
 *
 * @typedef {Object} FastifyPluginOpts
 * @property {Verifier} verifier
 * @property {string}   [prefix]            — restrict plugin to a route prefix (default: applies to all routes)
 * @property {boolean}  [throwOnFail=false] — if true, don't 401; let the handler decide
 *
 * @typedef {Object} FastifyResponseSignerOpts
 * @property {Signer}  signer
 * @property {string}  [event]
 * @property {boolean} [strict=false]
 */

/**
 * Fastify plugin. Register with `await fastify.register(pqWebhook, { verifier, ... })`.
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {FastifyPluginOpts} opts
 */
async function pqWebhookPlugin(fastify, opts) {
  const { verifier, throwOnFail = false } = opts || {}
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('pqWebhook (fastify): opts.verifier must be a built verifier (use createVerifier)')
  }

  // Capture raw bytes — required so the signature has the exact body to verify.
  fastify.addContentTypeParser('*', { parseAs: 'buffer' }, (req, body, done) => {
    done(null, body)
  })

  fastify.addHook('preHandler', async (request, reply) => {
    const rawBody = request.body
    const body = Buffer.isBuffer(rawBody) || typeof rawBody === 'string'
      ? rawBody
      : (rawBody === undefined || rawBody === null ? '' : JSON.stringify(rawBody))
    const result = verifier.verify(request.headers, body)
    request.kxcoWebhook = result
    if (!result.ok && !throwOnFail) {
      reply.code(401).send({
        error:  'webhook signature verification failed',
        code:   'kxco_webhook_unverified',
        reason: result.reason,
      })
    }
  })
}

// Fastify plugin convention — declare encapsulation off so the parser +
// hook propagate to the parent scope when registered at the root.
pqWebhookPlugin[Symbol.for('skip-override')] = true
pqWebhookPlugin[Symbol.for('fastify.display-name')] = 'kxco-post-quantum-webhook'

export default pqWebhookPlugin

/**
 * Response-signing plugin. Register separately from `pqWebhookPlugin` (the
 * verifier above) — they do unrelated things. Adds an `onSend` hook that
 * signs `${ts}.${payload}` and attaches `X-KXCO-Timestamp` /
 * `X-KXCO-PQ-Signature` / `X-KXCO-PQ-Kid` (and `X-KXCO-Signature` if HMAC
 * is configured) headers to every response on routes within the plugin
 * scope.
 *
 *   await app.register(pqResponseSignerPlugin, { signer, prefix: '/api' })
 *
 * @param {import('fastify').FastifyInstance} fastify
 * @param {FastifyResponseSignerOpts} opts
 */
export async function pqResponseSignerPlugin(fastify, opts) {
  if (!opts || !opts.signer || typeof opts.signer.sign !== 'function') {
    throw new TypeError('pqResponseSigner (fastify): opts.signer must be a built signer (use createSigner)')
  }
  const { signer, event, strict = false } = opts

  fastify.addHook('onSend', async (request, reply, payload) => {
    if (isStreamingBody(payload)) {
      if (strict) throw new Error('pqResponseSigner: streaming response body cannot be signed (set strict:false to send unsigned)')
      return payload
    }
    // Fastify may pass a string, Buffer, or object — normalise to the bytes
    // that will actually go on the wire.
    const bodyBytes = typeof payload === 'string' || Buffer.isBuffer(payload)
      ? payload
      : (payload == null ? '' : JSON.stringify(payload))
    const headers = signResponse(signer, bodyBytes, { event })
    for (const [k, v] of Object.entries(headers)) {
      if (k.toLowerCase() === 'content-type' && reply.getHeader('content-type')) continue
      reply.header(k, v)
    }
    return bodyBytes
  })
}

pqResponseSignerPlugin[Symbol.for('skip-override')] = true
pqResponseSignerPlugin[Symbol.for('fastify.display-name')] = 'kxco-post-quantum-response-signer'
