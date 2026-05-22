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

/**
 * @typedef {import('./builders.js').Verifier} Verifier
 *
 * @typedef {Object} FastifyPluginOpts
 * @property {Verifier} verifier
 * @property {string}   [prefix]            — restrict plugin to a route prefix (default: applies to all routes)
 * @property {boolean}  [throwOnFail=false] — if true, don't 401; let the handler decide
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
