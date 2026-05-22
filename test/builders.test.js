// Builders test — sender / verifier roundtrip + the required-policy matrix.

import { test }   from 'node:test'
import assert     from 'node:assert/strict'
import crypto     from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'

// Deterministic test keypair from a fixed master so every test run sees the
// same bytes (and so we can pin the kid in fixtures if needed).
const TEST_MASTER = Buffer.from('00'.repeat(32), 'hex')  // 32-byte all-zero master is fine for tests
const KP   = mlDsa.keypairFromMaster(TEST_MASTER, 'kxco-webhook-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

// ─────────────────────────────────────────────────────────────────────────────
// createSigner: argument validation
// ─────────────────────────────────────────────────────────────────────────────

test('createSigner throws when called without an opts object', () => {
  assert.throws(() => createSigner(), /opts must be an object/)
  assert.throws(() => createSigner(null), /opts must be an object/)
})

test('createSigner throws when neither hmacSecret nor pqSecretKey is provided', () => {
  assert.throws(() => createSigner({}), /at least one of/)
})

test('createSigner throws when pqSecretKey is provided without pqKid', () => {
  assert.throws(() => createSigner({ pqSecretKey: KP.secretKey }), /pqKid is required/)
})

test('createSigner accepts hmacSecret only', () => {
  const s = createSigner({ hmacSecret: HMAC })
  assert.equal(s.pqKid, undefined)
})

test('createSigner accepts pqSecretKey + pqKid only', () => {
  const s = createSigner({ pqSecretKey: KP.secretKey, pqKid: KID })
  assert.equal(s.pqKid, KID)
})

test('createSigner accepts both HMAC + PQ', () => {
  const s = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  assert.equal(s.pqKid, KID)
})

// ─────────────────────────────────────────────────────────────────────────────
// signer.sign: produces the expected header set
// ─────────────────────────────────────────────────────────────────────────────

test('signer.sign produces all expected headers when both HMAC + PQ configured', () => {
  const s = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const headers = s.sign('{"a":1}')
  assert.equal(headers['Content-Type'], 'application/json')
  assert.ok(headers['X-KXCO-Timestamp'])
  assert.ok(headers['X-KXCO-Signature']?.startsWith('sha256='))
  assert.ok(headers['X-KXCO-PQ-Signature']?.startsWith('ml-dsa-65='))
  assert.equal(headers['X-KXCO-PQ-Kid'], KID)
})

test('signer.sign attaches X-KXCO-Event and X-KXCO-Delivery when provided', () => {
  const s = createSigner({ hmacSecret: HMAC })
  const headers = s.sign('{"a":1}', { event: 'invoice.paid', deliveryId: 'dlv_123' })
  assert.equal(headers['X-KXCO-Event'], 'invoice.paid')
  assert.equal(headers['X-KXCO-Delivery'], 'dlv_123')
})

test('signer.sign throws if rawBody is missing', () => {
  const s = createSigner({ hmacSecret: HMAC })
  assert.throws(() => s.sign(), /rawBody is required/)
  assert.throws(() => s.sign(null), /rawBody is required/)
})

// ─────────────────────────────────────────────────────────────────────────────
// createVerifier: argument validation
// ─────────────────────────────────────────────────────────────────────────────

test('createVerifier rejects bad opts', () => {
  assert.throws(() => createVerifier(),       /opts must be an object/)
  assert.throws(() => createVerifier({}),     /at least one of/)
  assert.throws(() => createVerifier({ required: 'whatever', hmacSecret: HMAC }), /required must be one of/)
})

test('createVerifier rejects pqPublicKey without pinnedKid', () => {
  assert.throws(
    () => createVerifier({ pqPublicKey: KP.publicKey }),
    /pinnedKid is required/,
  )
})

test('createVerifier rejects required="both" without both secrets', () => {
  assert.throws(
    () => createVerifier({ hmacSecret: HMAC, required: 'both' }),
    /required="both"/,
  )
})

test('createVerifier rejects wrong-length pqPublicKey', () => {
  assert.throws(
    () => createVerifier({ pqPublicKey: Buffer.alloc(100), pinnedKid: KID, required: 'pq' }),
    /pqPublicKey must be 1952 bytes/,
  )
})

test('createVerifier accepts pqPublicKey as hex string', () => {
  const v = createVerifier({ pqPublicKey: KP.publicKey.toString('hex'), pinnedKid: KID, required: 'pq' })
  assert.equal(v.required, 'pq')
})

test('createVerifier rejects malformed hex pubkey', () => {
  assert.throws(
    () => createVerifier({ pqPublicKey: 'not-hex', pinnedKid: KID, required: 'pq' }),
    /pqPublicKey hex/,
  )
})

// ─────────────────────────────────────────────────────────────────────────────
// Sign / verify roundtrip
// ─────────────────────────────────────────────────────────────────────────────

function roundtrip(required) {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required })
  const body     = '{"hello":"world","n":42}'
  const headers  = signer.sign(body)
  return verifier.verify(headers, body)
}

for (const req of ['hmac', 'pq', 'both', 'either']) {
  test(`roundtrip ok=true under required="${req}"`, () => {
    const r = roundtrip(req)
    assert.equal(r.ok, true, JSON.stringify(r))
    assert.equal(r.hmacOk, true)
    assert.equal(r.pqOk, true)
    assert.equal(r.timestampOk, true)
    assert.equal(r.kidOk, true)
  })
}

test('tampered body fails the signatures', () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })
  const headers  = signer.sign('{"a":1}')
  const r = verifier.verify(headers, '{"a":2}')
  assert.equal(r.ok, false)
  assert.equal(r.hmacOk, false)
  assert.equal(r.pqOk, false)
  // First failure surfaced: HMAC, since it's the cheapest check
  assert.equal(r.reason, 'hmac_invalid')
})

test('wrong kid header → kid_mismatch', () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: 'ffffffffffffffff', required: 'both' })
  const headers  = signer.sign('{"a":1}')
  const r = verifier.verify(headers, '{"a":1}')
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'kid_mismatch')
})

test('stale timestamp → timestamp_skew', () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both', windowSeconds: 0 })
  const headers  = signer.sign('{"a":1}')
  // Sleep a hair so timestampOk fails — but easier: clobber the timestamp.
  headers['X-KXCO-Timestamp'] = String(Math.floor(Date.now() / 1000) - 86400)
  const r = verifier.verify(headers, '{"a":1}')
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'timestamp_skew')
})

test('missing HMAC header under required="hmac" → missing_hmac', () => {
  const signer = createSigner({ pqSecretKey: KP.secretKey, pqKid: KID })
  const headers = signer.sign('{"a":1}')
  const verifier = createVerifier({ hmacSecret: HMAC, required: 'hmac' })
  const r = verifier.verify(headers, '{"a":1}')
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'missing_hmac')
})

test('missing PQ header under required="pq" → missing_pq', () => {
  const signer = createSigner({ hmacSecret: HMAC })
  const headers = signer.sign('{"a":1}')
  const verifier = createVerifier({ pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'pq' })
  const r = verifier.verify(headers, '{"a":1}')
  assert.equal(r.ok, false)
  assert.equal(r.reason, 'missing_pq')
})

test('required="either" passes when only HMAC matches', () => {
  const signer = createSigner({ hmacSecret: HMAC })
  const headers = signer.sign('{"a":1}')
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'either' })
  const r = verifier.verify(headers, '{"a":1}')
  assert.equal(r.ok, true)
  assert.equal(r.hmacOk, true)
  assert.equal(r.pqOk, false)
})

test('verifier accepts fetch-style Headers as input', () => {
  const signer   = createSigner({ hmacSecret: HMAC })
  const headers  = signer.sign('{"a":1}')
  const verifier = createVerifier({ hmacSecret: HMAC, required: 'hmac' })
  const fetchHeaders = new Headers()
  for (const [k, v] of Object.entries(headers)) fetchHeaders.set(k, v)
  const r = verifier.verify(fetchHeaders, '{"a":1}')
  assert.equal(r.ok, true)
})
