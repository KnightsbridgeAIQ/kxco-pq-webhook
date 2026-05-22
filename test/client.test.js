// signedFetch + signedEnvelope tests. No real network — fake fetch.

import { test } from 'node:test'
import assert   from 'node:assert/strict'
import crypto   from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'
import { signedFetch, signedEnvelope }  from '../src/client.js'

const KP   = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'kxco-webhook-client-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

test('signedFetch attaches both signing headers and the body unmodified', async () => {
  const signer = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  let captured
  const fakeFetch = async (url, init) => {
    captured = { url, init }
    return new Response('ok', { status: 200 })
  }
  const res = await signedFetch('https://example.com/hook', {
    signer,
    body: { hello: 'world' },
    event: 'test.event',
    fetchImpl: fakeFetch,
  })
  assert.equal(res.status, 200)
  assert.equal(captured.url, 'https://example.com/hook')
  assert.equal(captured.init.method, 'POST')
  assert.equal(captured.init.body, '{"hello":"world"}')
  assert.equal(captured.init.headers['X-KXCO-PQ-Kid'], KID)
  assert.equal(captured.init.headers['X-KXCO-Event'], 'test.event')
})

test('signedFetch + verifier roundtrip', async () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })

  const fakeFetch = async (url, init) => {
    const r = verifier.verify(init.headers, init.body)
    if (!r.ok) return new Response(JSON.stringify(r), { status: 401 })
    return new Response('ok', { status: 200 })
  }

  const res = await signedFetch('https://example.com/hook', {
    signer,
    body: { amount: 100, currency: 'USD' },
    fetchImpl: fakeFetch,
  })
  assert.equal(res.status, 200)
})

test('signedFetch passes string bodies through unchanged', async () => {
  const signer = createSigner({ hmacSecret: HMAC })
  let captured
  const fakeFetch = async (url, init) => { captured = init; return new Response('') }
  await signedFetch('https://example.com/hook', {
    signer,
    body: 'raw string body',
    fetchImpl: fakeFetch,
  })
  assert.equal(captured.body, 'raw string body')
})

test('signedFetch rejects non-http(s) URLs', async () => {
  const signer = createSigner({ hmacSecret: HMAC })
  await assert.rejects(
    signedFetch('ftp://example.com/x', { signer, fetchImpl: async () => new Response() }),
    /absolute http\(s\) URL/,
  )
})

test('signedFetch requires a signer', async () => {
  await assert.rejects(signedFetch('https://x/', {}), /signer is required/)
})

test('signedFetch requires a fetch implementation', async () => {
  const saved = globalThis.fetch
  delete globalThis.fetch
  try {
    await assert.rejects(
      signedFetch('https://x/', { signer: createSigner({ hmacSecret: HMAC }) }),
      /no fetch implementation/,
    )
  } finally {
    globalThis.fetch = saved
  }
})

test('user-provided headers cannot overwrite signing headers', async () => {
  const signer = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  let captured
  const fakeFetch = async (url, init) => { captured = init; return new Response('') }
  await signedFetch('https://example.com/hook', {
    signer,
    body: '{}',
    headers: {
      'X-KXCO-PQ-Kid': 'attacker-controlled-kid',
      'X-Custom':      'value',
    },
    fetchImpl: fakeFetch,
  })
  // signing headers win
  assert.equal(captured.headers['X-KXCO-PQ-Kid'], KID)
  // unrelated user headers survive
  assert.equal(captured.headers['X-Custom'], 'value')
})

test('signedEnvelope returns rawBody + headers without making a request', () => {
  const signer = createSigner({ hmacSecret: HMAC })
  const { rawBody, headers } = signedEnvelope(signer, { a: 1 })
  assert.equal(rawBody, '{"a":1}')
  assert.ok(headers['X-KXCO-Signature']?.startsWith('sha256='))
})

test('signedEnvelope passes event + deliveryId through', () => {
  const signer = createSigner({ hmacSecret: HMAC })
  const { headers } = signedEnvelope(signer, { a: 1 }, { event: 'foo', deliveryId: 'd1' })
  assert.equal(headers['X-KXCO-Event'], 'foo')
  assert.equal(headers['X-KXCO-Delivery'], 'd1')
})

test('signedEnvelope rejects a non-signer', () => {
  assert.throws(() => signedEnvelope({}, {}), /built signer/)
})
