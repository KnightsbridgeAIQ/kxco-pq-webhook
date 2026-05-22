// Framework adapter tests — Express, Hono, Workers, Vercel.
//
// Fastify is exercised separately in fastify.test.js because it requires the
// real fastify package to register the plugin (no fake harness gives a
// faithful enough preHandler-hook lifecycle).
//
// Each adapter is tested with a fake req/res/Request that satisfies the
// interface contract without pulling in the real framework deps — keeps the
// suite zero-runtime-dep and fast.

import { test }   from 'node:test'
import assert     from 'node:assert/strict'
import crypto     from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'
import { pqWebhook as expressPq }       from '../src/express.js'
import { pqWebhook as honoPq }          from '../src/hono.js'
import { verifyRequest, withPqWebhook } from '../src/workers.js'
import { nodePqWebhook }                from '../src/vercel.js'

const KP   = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'kxco-webhook-adapters-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

function buildSignedRequest(body = '{"event":"test"}') {
  const signer  = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const headers = signer.sign(body)
  return { body, headers }
}

function buildVerifier(required = 'both') {
  return createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required })
}

// ─────────────────────────────────────────────────────────────────────────────
// Express
// ─────────────────────────────────────────────────────────────────────────────

function fakeExpressReq({ body, headers }) {
  return { body: Buffer.from(body, 'utf-8'), headers, rawBody: undefined }
}

function fakeRes() {
  return {
    statusCode: 0,
    body: undefined,
    status(c) { this.statusCode = c; return this },
    json(o)   { this.body = o; return this },
  }
}

test('express pqWebhook: valid → next() called, no response, req.kxcoWebhook set', () => {
  const { body, headers } = buildSignedRequest()
  const req = fakeExpressReq({ body, headers })
  const res = fakeRes()
  let called = false
  expressPq(buildVerifier())(req, res, () => { called = true })
  assert.equal(called, true)
  assert.equal(res.statusCode, 0)
  assert.equal(req.kxcoWebhook.ok, true)
})

test('express pqWebhook: invalid sig → 401 with reason, next() not called', () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const req = fakeExpressReq({ body: '{"tampered":"body"}', headers })
  const res = fakeRes()
  let called = false
  expressPq(buildVerifier())(req, res, () => { called = true })
  assert.equal(called, false)
  assert.equal(res.statusCode, 401)
  assert.equal(res.body.code, 'kxco_webhook_unverified')
  assert.equal(res.body.reason, 'hmac_invalid')
})

test('express pqWebhook: throwOnFail=true → next() called even when invalid', () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const req = fakeExpressReq({ body: '{"tampered":"body"}', headers })
  const res = fakeRes()
  let called = false
  expressPq(buildVerifier(), { throwOnFail: true })(req, res, () => { called = true })
  assert.equal(called, true)
  assert.equal(res.statusCode, 0)
  assert.equal(req.kxcoWebhook.ok, false)
})

test('express pqWebhook: rejects an already-parsed JSON object body', () => {
  const req = { body: { alreadyParsed: true }, headers: {} }
  const res = fakeRes()
  let errCaught
  expressPq(buildVerifier())(req, res, (err) => { errCaught = err })
  assert.ok(errCaught, 'expected an error to be passed to next()')
  assert.match(errCaught.message, /has been parsed into an object/)
})

test('express pqWebhook: falls back to req.rawBody when req.body is undefined', () => {
  const { body, headers } = buildSignedRequest()
  const req = { body: undefined, rawBody: Buffer.from(body, 'utf-8'), headers }
  const res = fakeRes()
  let called = false
  expressPq(buildVerifier())(req, res, () => { called = true })
  assert.equal(called, true)
  assert.equal(req.kxcoWebhook.ok, true)
})

test('express pqWebhook: rejects when verifier is missing/invalid', () => {
  assert.throws(() => expressPq(),       /built verifier/)
  assert.throws(() => expressPq({}),     /built verifier/)
  assert.throws(() => expressPq(null),   /built verifier/)
})

// ─────────────────────────────────────────────────────────────────────────────
// Hono
// ─────────────────────────────────────────────────────────────────────────────

function fakeHonoContext({ body, headers }) {
  const fetchHeaders = new Headers()
  for (const [k, v] of Object.entries(headers)) fetchHeaders.set(k, v)
  const req = new Request('https://example.com/webhooks/kxco', {
    method:  'POST',
    headers: fetchHeaders,
    body,
  })
  const store = {}
  return {
    set(k, v) { store[k] = v },
    get(k)    { return store[k] },
    req: { raw: req },
    json(obj, status) { this.lastResponse = { obj, status }; return this },
    _store: store,
  }
}

test('hono pqWebhook: valid → next() called, no response, kxcoWebhook context value set', async () => {
  const { body, headers } = buildSignedRequest()
  const c = fakeHonoContext({ body, headers })
  let nextCalled = false
  await honoPq(buildVerifier())(c, async () => { nextCalled = true })
  assert.equal(nextCalled, true)
  assert.equal(c.get('kxcoWebhook').ok, true)
})

test('hono pqWebhook: invalid sig → 401, next() not called', async () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const c = fakeHonoContext({ body: '{"tampered":"body"}', headers })
  let nextCalled = false
  const res = await honoPq(buildVerifier())(c, async () => { nextCalled = true })
  assert.equal(nextCalled, false)
  assert.equal(c.lastResponse.status, 401)
  assert.equal(c.lastResponse.obj.code, 'kxco_webhook_unverified')
})

test('hono pqWebhook: throwOnFail bypasses 401', async () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const c = fakeHonoContext({ body: '{"tampered":"body"}', headers })
  let nextCalled = false
  await honoPq(buildVerifier(), { throwOnFail: true })(c, async () => { nextCalled = true })
  assert.equal(nextCalled, true)
  assert.equal(c.get('kxcoWebhook').ok, false)
})

// ─────────────────────────────────────────────────────────────────────────────
// Workers / Fetch handler
// ─────────────────────────────────────────────────────────────────────────────

function fakeFetchRequest({ body, headers }) {
  const fetchHeaders = new Headers()
  for (const [k, v] of Object.entries(headers)) fetchHeaders.set(k, v)
  return new Request('https://example.com/webhooks/kxco', {
    method:  'POST',
    headers: fetchHeaders,
    body,
  })
}

test('workers verifyRequest: returns result + raw body', async () => {
  const { body, headers } = buildSignedRequest('{"event":"x"}')
  const req = fakeFetchRequest({ body, headers })
  const { result, rawBody } = await verifyRequest(buildVerifier(), req)
  assert.equal(result.ok, true)
  assert.equal(rawBody, '{"event":"x"}')
})

test('workers withPqWebhook: valid → handler receives request + result', async () => {
  const { body, headers } = buildSignedRequest()
  const req = fakeFetchRequest({ body, headers })
  const wrapped = withPqWebhook(buildVerifier(), async (request, env, ctx, result) => {
    assert.equal(result.ok, true)
    const txt = await request.text()
    assert.equal(txt, body)
    return new Response('handler-saw-body', { status: 200 })
  })
  const res = await wrapped(req)
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'handler-saw-body')
})

test('workers withPqWebhook: invalid → 401 Response', async () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const req = fakeFetchRequest({ body: '{"tampered":"body"}', headers })
  const wrapped = withPqWebhook(buildVerifier(), async () => new Response('should-not-run', { status: 200 }))
  const res = await wrapped(req)
  assert.equal(res.status, 401)
  const parsed = await res.json()
  assert.equal(parsed.code, 'kxco_webhook_unverified')
  assert.equal(parsed.reason, 'hmac_invalid')
})

// ─────────────────────────────────────────────────────────────────────────────
// Vercel Node-runtime
// ─────────────────────────────────────────────────────────────────────────────

import { Readable } from 'node:stream'

function fakeNodeReq({ body, headers }) {
  const stream = Readable.from(Buffer.from(body, 'utf-8'))
  // Add the headers as a property since IncomingMessage exposes them that way.
  stream.headers = headers
  return stream
}

function fakeNodeRes() {
  return {
    statusCode: 0,
    body: undefined,
    headersSent: false,
    status(c) { this.statusCode = c; return this },
    json(o)   { this.body = o; this.headersSent = true; return this },
  }
}

test('vercel nodePqWebhook: valid → handler called with rawBody buffered into req', async () => {
  const { body, headers } = buildSignedRequest('{"event":"vercel"}')
  const req = fakeNodeReq({ body, headers })
  const res = fakeNodeRes()
  let seen = null
  await nodePqWebhook(buildVerifier(), async (r, s) => {
    seen = r.rawBody.toString('utf-8')
    s.status(200).json({ ok: true })
  })(req, res)
  assert.equal(seen, body)
  assert.equal(res.body.ok, true)
})

test('vercel nodePqWebhook: invalid → 401 without calling handler', async () => {
  const { headers } = buildSignedRequest('{"original":"body"}')
  const req = fakeNodeReq({ body: '{"tampered":"body"}', headers })
  const res = fakeNodeRes()
  let called = false
  await nodePqWebhook(buildVerifier(), async () => { called = true })(req, res)
  assert.equal(called, false)
  assert.equal(res.statusCode, 401)
  assert.equal(res.body.code, 'kxco_webhook_unverified')
})
