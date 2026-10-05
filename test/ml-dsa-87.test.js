// ML-DSA-87 deliveries: the key decides the header form (`ml-dsa-87=<hex>`)
// and the JWS alg, the contract's `algorithm` field is checked against the key,
// a key of one set never verifies a header or token of the other, and ML-DSA-65
// deliveries are exactly what they were.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mlDsa, mlDsa87, fingerprint, webhook } from 'kxco-post-quantum'

import { createSigner, createVerifier, signBodyJws, verifyBodyJws } from '../src/index.js'

const LEGACY = JSON.parse(readFileSync(new URL('./fixtures/legacy-65.json', import.meta.url), 'utf-8'))

const K65 = mlDsa.keypairFromMaster(Buffer.alloc(32, 1), 'webhook-87-test')
const K87 = mlDsa87.keypairFromMaster(Buffer.alloc(32, 1), 'webhook-87-test')
const KID65 = fingerprint(K65.publicKey)
const KID87 = fingerprint(K87.publicKey)
const HMAC = 'shared-secret'
const BODY = JSON.stringify({ event: 'payment.settled', amount: 100 })

const pqVerifier = (publicKey, pinnedKid, extra = {}) =>
  createVerifier({ pqPublicKey: publicKey, pinnedKid, required: 'pq', ...extra })

test('an ML-DSA-87 signer emits ml-dsa-87=<hex> and an ML-DSA-87 verifier accepts it', () => {
  const signer = createSigner({ pqSecretKey: K87.secretKey, pqKid: KID87 })
  assert.equal(signer.pqAlgorithm, 'ml-dsa-87')
  const headers = signer.sign(BODY)
  const sig = headers['X-KXCO-PQ-Signature']
  assert.ok(sig.startsWith('ml-dsa-87='))
  assert.equal(sig.length, 'ml-dsa-87='.length + 4627 * 2)
  const r = pqVerifier(K87.publicKey, KID87).verify(headers, BODY)
  assert.equal(r.ok, true)
  assert.equal(r.pqOk, true)
})

test('an ML-DSA-87 signer with an HMAC secret signs both, and required both passes', () => {
  const headers = createSigner({ hmacSecret: HMAC, pqSecretKey: K87.secretKey, pqKid: KID87 })
    .sign(BODY, { event: 'payment.settled', deliveryId: 'd-87' })
  assert.ok(headers['X-KXCO-Signature'].startsWith('sha256='))
  assert.ok(headers['X-KXCO-PQ-Signature'].startsWith('ml-dsa-87='))
  assert.equal(headers['X-KXCO-Event'], 'payment.settled')
  assert.equal(headers['X-KXCO-Delivery'], 'd-87')
  const r = createVerifier({ hmacSecret: HMAC, pqPublicKey: K87.publicKey, pinnedKid: KID87, required: 'both' })
    .verify(headers, BODY)
  assert.deepEqual([r.ok, r.hmacOk, r.pqOk], [true, true, true])
})

test('an ML-DSA-65 signer still emits ml-dsa-65=<hex> through the upstream helpers', () => {
  const signer = createSigner({ hmacSecret: HMAC, pqSecretKey: K65.secretKey, pqKid: KID65 })
  assert.equal(signer.pqAlgorithm, 'ml-dsa-65')
  const headers = signer.sign(BODY)
  assert.ok(headers['X-KXCO-PQ-Signature'].startsWith('ml-dsa-65='))
  assert.equal(webhook.verifyPq(K65.publicKey, headers['X-KXCO-Timestamp'], BODY, headers['X-KXCO-PQ-Signature']), true)
  const r = createVerifier({ hmacSecret: HMAC, pqPublicKey: K65.publicKey, pinnedKid: KID65, required: 'both' }).verify(headers, BODY)
  assert.equal(r.ok, true)
})

test('a key of one set never verifies a header of the other, even under a matching kid', () => {
  const h87 = createSigner({ pqSecretKey: K87.secretKey, pqKid: KID87 }).sign(BODY)
  const h65 = createSigner({ pqSecretKey: K65.secretKey, pqKid: KID65 }).sign(BODY)
  // The kid is pinned to whatever the header says, so only the set can refuse it.
  assert.equal(pqVerifier(K65.publicKey, KID87).verify(h87, BODY).reason, 'pq_invalid')
  assert.equal(pqVerifier(K87.publicKey, KID65).verify(h65, BODY).reason, 'pq_invalid')
})

test('an ML-DSA-87 key takes only the ml-dsa-87= form', () => {
  const headers = createSigner({ pqSecretKey: K87.secretKey, pqKid: KID87 }).sign(BODY)
  const hex = headers['X-KXCO-PQ-Signature'].slice('ml-dsa-87='.length)
  const v = pqVerifier(K87.publicKey, KID87)
  assert.equal(v.verify({ ...headers, 'X-KXCO-PQ-Signature': hex }, BODY).reason, 'pq_invalid')
  assert.equal(v.verify({ ...headers, 'X-KXCO-PQ-Signature': 'ml-dsa-65=' + hex }, BODY).reason, 'pq_invalid')
  assert.equal(v.verify(headers, BODY + ' ').reason, 'pq_invalid')
})

test('an ML-DSA-87 delivery outside the window fails on the timestamp, as ML-DSA-65 does', () => {
  // Signed an hour ago, so the signature itself is good and only the window refuses it.
  const realNow = Date.now
  Date.now = () => realNow() - 3600 * 1000
  let stale
  try {
    stale = createSigner({ pqSecretKey: K87.secretKey, pqKid: KID87 }).sign(BODY)
  } finally {
    Date.now = realNow
  }
  const r = pqVerifier(K87.publicKey, KID87).verify(stale, BODY)
  assert.deepEqual([r.ok, r.reason, r.pqOk], [false, 'timestamp_skew', false])
  // The same delivery inside a wide enough window verifies, so it was the window.
  assert.equal(pqVerifier(K87.publicKey, KID87, { windowSeconds: 7200 }).verify(stale, BODY).pqOk, true)
})

test('pinnedKids spanning both sets verifies each delivery under its own key', () => {
  const v = createVerifier({
    required: 'pq',
    pinnedKids: [
      { kid: KID65, publicKey: K65.publicKey, algorithm: 'ml-dsa-65' },
      { kid: KID87, publicKey: Buffer.from(K87.publicKey).toString('hex'), algorithm: 'ml-dsa-87' },
    ],
  })
  for (const [kp, kid] of [[K65, KID65], [K87, KID87]]) {
    const r = v.verify(createSigner({ pqSecretKey: kp.secretKey, pqKid: kid }).sign(BODY), BODY)
    assert.equal(r.ok, true, kid)
    assert.equal(r.resolvedKid, kid)
  }
})

test("the contract's algorithm field is checked against the key", () => {
  assert.equal(pqVerifier(K87.publicKey, KID87, { pqAlgorithm: 'ml-dsa-87' }).required, 'pq')
  assert.throws(() => pqVerifier(K87.publicKey, KID87, { pqAlgorithm: 'ml-dsa-65' }),
    /pqAlgorithm is ml-dsa-65 but pqPublicKey is an ml-dsa-87 key/)
  assert.throws(() => pqVerifier(K65.publicKey, KID65, { pqAlgorithm: 'ML-DSA-65' }),
    /pqAlgorithm must be 'ml-dsa-65' or 'ml-dsa-87'/)
  assert.throws(() => createVerifier({ hmacSecret: HMAC, required: 'hmac', pqAlgorithm: 'ml-dsa-87' }),
    /pqAlgorithm describes pqPublicKey/)
  assert.throws(() => createVerifier({
    required: 'pq', pinnedKids: [{ kid: KID65, publicKey: K65.publicKey, algorithm: 'ml-dsa-87' }],
  }), /pinnedKids\[[0-9a-f]+\]\.algorithm is ml-dsa-87 but pinnedKids\[[0-9a-f]+\]\.publicKey is an ml-dsa-65 key/)
})

test('key sizes: both public key lengths are accepted, anything else is refused', () => {
  assert.doesNotThrow(() => pqVerifier(Buffer.from(K87.publicKey).toString('hex'), KID87))
  assert.throws(() => pqVerifier(Buffer.alloc(2593), KID87), /1952 bytes \(ML-DSA-65\) or 2592 bytes \(ML-DSA-87\)/)
  assert.throws(() => pqVerifier('ab'.repeat(2593), KID87), /3904 chars \(ML-DSA-65\) or 5184 chars \(ML-DSA-87\)/)
  assert.throws(() => createSigner({ pqSecretKey: Buffer.alloc(4900), pqKid: KID87 }),
    /ML-DSA-65 \(4032-byte\) or ML-DSA-87 \(4896-byte\)/)
})

test('JWS: an ML-DSA-87 key signs ML-DSA-87, and only an ML-DSA-87 key verifies it', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: K87.secretKey, kid: KID87, event: 'payment.settled' })
  const header = JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString())
  assert.equal(header.alg, 'ML-DSA-87')
  const ok = verifyBodyJws({ token, rawBody: BODY, publicKey: K87.publicKey, pinnedKid: KID87 })
  assert.equal(ok.valid, true)
  assert.equal(ok.alg, 'ML-DSA-87')
  const cross = verifyBodyJws({ token, rawBody: BODY, publicKey: K65.publicKey })
  assert.equal(cross.valid, false)
  assert.match(cross.reason, /alg mismatch: expected 'ML-DSA-65', token declares 'ML-DSA-87'/)
})

test('JWS: an ML-DSA-65 key still signs ML-DSA-65, and an ML-DSA-87 key refuses it', () => {
  const token = signBodyJws({ rawBody: BODY, secretKey: K65.secretKey, kid: KID65 })
  assert.equal(JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString()).alg, 'ML-DSA-65')
  assert.equal(verifyBodyJws({ token, rawBody: BODY, publicKey: K65.publicKey }).alg, 'ML-DSA-65')
  assert.match(verifyBodyJws({ token, rawBody: BODY, publicKey: K87.publicKey }).reason, /alg mismatch/)
  assert.throws(() => signBodyJws({ rawBody: BODY, secretKey: Buffer.alloc(100), kid: KID65 }), /4032-byte\) or ML-DSA-87/)
})

test('a delivery signed by 1.2.6, before ML-DSA-87, still verifies, headers and JWS', () => {
  const pub = Buffer.from(LEGACY.publicKey, 'hex')
  assert.ok(LEGACY.headers['X-KXCO-PQ-Signature'].startsWith('ml-dsa-65='))
  const r = createVerifier({
    hmacSecret: LEGACY.hmacSecret, pqPublicKey: pub, pinnedKid: LEGACY.kid, required: 'both', windowSeconds: 1e10,
  }).verify(LEGACY.headers, LEGACY.rawBody)
  assert.deepEqual([r.ok, r.hmacOk, r.pqOk], [true, true, true])
  const j = verifyBodyJws({ token: LEGACY.jws, rawBody: LEGACY.rawBody, publicKey: pub, pinnedKid: LEGACY.kid, windowSeconds: 1e10 })
  assert.equal(j.valid, true)
  assert.equal(j.alg, 'ML-DSA-65')
})
