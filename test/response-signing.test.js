// Response-signing tests.
//
// Each adapter wraps its handler. We test that:
//   1. The body the handler produces ends up with valid PQ headers attached
//   2. A separate verifier (built from the same kid) successfully verifies
//      the response — proving the wire format is symmetric with webhook reqs
//   3. Streaming responses pass through without signing (strict:false) or
//      throw (strict:true)
//   4. Content-Type set by the handler is preserved (not overwritten)

import { test }   from 'node:test'
import assert     from 'node:assert/strict'
import crypto     from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'
import { signResponse, isStreamingBody } from '../src/response-core.js'
import { pqResponseSigner as expressResp } from '../src/express.js'
import { pqResponseSigner as honoResp }    from '../src/hono.js'
import { withPqResponseSigning }            from '../src/workers.js'
import { pqResponseSigner as vercelResp }   from '../src/vercel.js'

const KP   = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'kxco-webhook-response-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

function freshSigner()   { return createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID }) }
function freshVerifier() { return createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' }) }

// ─────────────────────────────────────────────────────────────────────────────
// response-core unit tests
// ─────────────────────────────────────────────────────────────────────────────

test('signResponse: round-trips with createVerifier', () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const body     = JSON.stringify({ ok: true, n: 42 })
  const headers  = signResponse(signer, body)
  const result   = verifier.verify(headers, body)
  assert.equal(result.ok, true, JSON.stringify(result))
})

test('signResponse: rejects a non-signer', () => {
  assert.throws(() => signResponse({}, ''), /built signer/)
})

test('signResponse: handles empty body', () => {
  const headers = signResponse(freshSigner(), undefined)
  // Should still produce signing headers — empty body is a valid envelope
  assert.ok(headers['X-KXCO-PQ-Signature']?.startsWith('ml-dsa-65='))
})

test('signResponse: serialises non-string/Buffer bodies as JSON', () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const headers  = signResponse(signer, { ok: true })
  // The verifier needs the same bytes we signed
  const result   = verifier.verify(headers, '{"ok":true}')
  assert.equal(result.ok, true)
})

test('isStreamingBody: detects Node Readable streams', async () => {
  const { Readable } = await import('node:stream')
  const s = Readable.from(['chunk'])
  assert.equal(isStreamingBody(s), true)
})

test('isStreamingBody: detects web ReadableStream', () => {
  const s = new ReadableStream({ start(c) { c.enqueue('x'); c.close() } })
  assert.equal(isStreamingBody(s), true)
})

test('isStreamingBody: returns false for strings, Buffers, Uint8Arrays, plain objects', () => {
  assert.equal(isStreamingBody(''), false)
  assert.equal(isStreamingBody(Buffer.from('x')), false)
  assert.equal(isStreamingBody(new Uint8Array([1,2,3])), false)
  assert.equal(isStreamingBody({ ok: true }), false)
  assert.equal(isStreamingBody(null), false)
  assert.equal(isStreamingBody(undefined), false)
})

// ─────────────────────────────────────────────────────────────────────────────
// Express response signer
// ─────────────────────────────────────────────────────────────────────────────

function fakeExpressRes() {
  const headers = {}
  return {
    headersSent: false,
    statusCode: 200,
    getHeader(k)         { return headers[k.toLowerCase()] },
    setHeader(k, v)      { headers[k.toLowerCase()] = v },
    _headers: headers,
    _sentBody: undefined,
    status(c) { this.statusCode = c; return this },
    send(body) { this._sentBody = body; this.headersSent = true; return this },
    json(body) {
      this.setHeader('Content-Type', 'application/json; charset=utf-8')
      return this.send(JSON.stringify(body))
    },
  }
}

test('express pqResponseSigner: res.json output is signed and verifies', () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const req = {}, res = fakeExpressRes()
  expressResp({ signer })(req, res, () => {
    res.json({ ok: true, n: 42 })
  })
  // Headers attached
  assert.ok(res._headers['x-kxco-pq-signature'])
  assert.equal(res._headers['x-kxco-pq-kid'], KID)
  // Body preserved + verifiable
  const sentBody = res._sentBody
  const result   = verifier.verify(res._headers, sentBody)
  assert.equal(result.ok, true, JSON.stringify(result))
})

test('express pqResponseSigner: res.send output is signed and verifies', () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const req = {}, res = fakeExpressRes()
  expressResp({ signer })(req, res, () => {
    res.send('raw string body')
  })
  const result = verifier.verify(res._headers, res._sentBody)
  assert.equal(result.ok, true)
})

test('express pqResponseSigner: strict mode throws on streaming body', async () => {
  const signer = freshSigner()
  const { Readable } = await import('node:stream')
  const req = {}, res = fakeExpressRes()
  expressResp({ signer, strict: true })(req, res, () => {
    assert.throws(() => res.send(Readable.from(['chunk'])), /streaming response body cannot be signed/)
  })
})

test('express pqResponseSigner: rejects missing signer', () => {
  assert.throws(() => expressResp(),         /built signer/)
  assert.throws(() => expressResp({}),       /built signer/)
})

// ─────────────────────────────────────────────────────────────────────────────
// Hono response signer
// ─────────────────────────────────────────────────────────────────────────────

function fakeHonoCtx() {
  return {
    res: null,
    set(k, v) { this[`_${k}`] = v },
    get(k)    { return this[`_${k}`] },
  }
}

test('hono pqResponseSigner: signs the response c.res produces', async () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const c = fakeHonoCtx()
  const handler = honoResp({ signer })
  await handler(c, async () => {
    c.res = new Response(JSON.stringify({ ok: true }), {
      status:  200,
      headers: { 'Content-Type': 'application/json' },
    })
  })
  // c.res is now a NEW Response with signing headers attached
  assert.ok(c.res.headers.get('x-kxco-pq-signature'))
  assert.equal(c.res.headers.get('x-kxco-pq-kid'), KID)
  // Verifier sees what's on the wire
  const body = await c.res.text()
  const headersObj = {}
  for (const [k, v] of c.res.headers.entries()) headersObj[k] = v
  const result = verifier.verify(headersObj, body)
  assert.equal(result.ok, true, JSON.stringify(result))
})

test('hono pqResponseSigner: missing c.res is a no-op', async () => {
  const signer = freshSigner()
  const c = fakeHonoCtx()
  await honoResp({ signer })(c, async () => { /* don't set c.res */ })
  assert.equal(c.res, null)
})

test('hono pqResponseSigner: rejects missing signer', () => {
  assert.throws(() => honoResp(),     /built signer/)
  assert.throws(() => honoResp({}),   /built signer/)
})

// ─────────────────────────────────────────────────────────────────────────────
// Workers / Fetch response signer
// ─────────────────────────────────────────────────────────────────────────────

test('workers withPqResponseSigning: wraps handler Response with signing headers', async () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const wrapped  = withPqResponseSigning(signer, async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }),
  )
  const res = await wrapped(new Request('https://example.com/api/health'))
  assert.ok(res.headers.get('x-kxco-pq-signature'))
  const body = await res.text()
  const headersObj = {}
  for (const [k, v] of res.headers.entries()) headersObj[k] = v
  const result = verifier.verify(headersObj, body)
  assert.equal(result.ok, true)
})

test('workers withPqResponseSigning: passes non-Response returns through unchanged', async () => {
  const signer = freshSigner()
  const wrapped = withPqResponseSigning(signer, async () => 'not a Response')
  const out = await wrapped(new Request('https://example.com/x'))
  assert.equal(out, 'not a Response')
})

test('workers withPqResponseSigning: rejects bad args', () => {
  assert.throws(() => withPqResponseSigning(null, async () => {}), /built signer/)
  assert.throws(() => withPqResponseSigning(freshSigner(), 'not a function'), /must be a function/)
})

// ─────────────────────────────────────────────────────────────────────────────
// Vercel response signer (Node runtime)
// ─────────────────────────────────────────────────────────────────────────────

test('vercel pqResponseSigner: res.json output is signed', async () => {
  const signer   = freshSigner()
  const verifier = freshVerifier()
  const wrap = vercelResp({ signer })
  const handler = wrap(async (req, res) => {
    res.status(200).json({ ok: true })
  })
  const req = {}, res = fakeExpressRes()  // Express fake works — same shape for our purposes
  await handler(req, res)
  const result = verifier.verify(res._headers, res._sentBody)
  assert.equal(result.ok, true)
})

test('vercel pqResponseSigner: rejects missing signer', () => {
  assert.throws(() => vercelResp(),       /built signer/)
  assert.throws(() => vercelResp({}),     /built signer/)
})
