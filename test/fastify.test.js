// Fastify plugin test — uses the real fastify package because mocking its
// preHandler lifecycle faithfully is more work than installing it as a devdep.
//
// Skipped if fastify isn't installed (we don't add it as a real devDependency
// because it's a heavyweight; we just probe at test-load time).

import { test }  from 'node:test'
import assert    from 'node:assert/strict'
import crypto    from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'

let Fastify
try {
  Fastify = (await import('fastify')).default
} catch {
  Fastify = null
}

const KP   = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'kxco-webhook-fastify-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

test('fastify plugin: valid signed delivery → handler runs, kxcoWebhook decorated', { skip: !Fastify }, async () => {
  const { default: pqWebhookPlugin } = await import('../src/fastify.js')
  const app = Fastify()
  await app.register(pqWebhookPlugin, {
    verifier: createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' }),
  })
  app.post('/hook', async (req, reply) => ({
    ok: req.kxcoWebhook.ok,
    bodyType: Buffer.isBuffer(req.body) ? 'buffer' : typeof req.body,
  }))

  const signer = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const body   = '{"event":"fastify"}'
  const headers = signer.sign(body)
  const res = await app.inject({ method: 'POST', url: '/hook', headers, payload: body })
  assert.equal(res.statusCode, 200)
  const parsed = JSON.parse(res.payload)
  assert.equal(parsed.ok, true)
  await app.close()
})

test('fastify plugin: invalid sig → 401', { skip: !Fastify }, async () => {
  const { default: pqWebhookPlugin } = await import('../src/fastify.js')
  const app = Fastify()
  await app.register(pqWebhookPlugin, {
    verifier: createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' }),
  })
  app.post('/hook', async () => ({ ok: true }))

  const signer = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const headers = signer.sign('{"original":"body"}')
  const res = await app.inject({ method: 'POST', url: '/hook', headers, payload: '{"tampered":"body"}' })
  assert.equal(res.statusCode, 401)
  const parsed = JSON.parse(res.payload)
  assert.equal(parsed.code, 'kxco_webhook_unverified')
  assert.equal(parsed.reason, 'hmac_invalid')
  await app.close()
})

test('fastify plugin: rejects missing verifier', { skip: !Fastify }, async () => {
  const { default: pqWebhookPlugin } = await import('../src/fastify.js')
  const app = Fastify()
  // register() returns the instance (chainable); the actual error surfaces on ready()
  app.register(pqWebhookPlugin, {})
  await assert.rejects(app.ready(), /must be a built verifier/)
  await app.close()
})
