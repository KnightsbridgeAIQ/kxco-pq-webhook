// Property-based tests with fast-check.
//
// The example tests pin particular deliveries. These ask the general question
// of createSigner and createVerifier instead: for ANY body, event and delivery
// id, does a dual-signed delivery verify; does changing the body, the
// timestamp or a signature header make it fail; does the timestamp window
// hold; does each `required` policy pass exactly the deliveries the README
// says it passes; and does key rotation with pinnedKids name the key that
// verified? The compact JWS path gets the same round trip and tamper checks.
// fast-check generates the inputs and, when a property breaks, shrinks the
// failing case to the smallest one that still breaks it, so a failure arrives
// as a minimal reproduction.
//
// Everything runs in process: signing and verification are local, and nothing
// here sends a request.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fc from 'fast-check'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { createSigner, createVerifier, signBodyJws, verifyBodyJws, webhook } from '../src/index.js'

// Every case signs with ML-DSA-65 and verifies several times, so a modest run
// count keeps the file fast on the JavaScript backend.
const SIGNING = { numRuns: 20 }

function key(info) {
  const k = mlDsa.keypairFromMaster(new Uint8Array(32).fill(7), info)
  return { ...k, kid: fingerprint(k.publicKey) }
}
const K1 = key('kxco-pq-webhook-property-key-1')
const K2 = key('kxco-pq-webhook-property-key-2')
const K3 = key('kxco-pq-webhook-property-key-3')

const POLICIES = ['both', 'pq', 'hmac', 'either']
const REASONS = ['timestamp_skew', 'kid_mismatch', 'missing_hmac', 'missing_pq', 'hmac_invalid', 'pq_invalid']

function verifiers(hmacSecret) {
  return {
    both: createVerifier({ hmacSecret, pqPublicKey: K1.publicKey, pinnedKid: K1.kid, required: 'both' }),
    pq: createVerifier({ pqPublicKey: K1.publicKey, pinnedKid: K1.kid, required: 'pq' }),
    hmac: createVerifier({ hmacSecret, required: 'hmac' }),
    either: createVerifier({ hmacSecret, pqPublicKey: K1.publicKey, pinnedKid: K1.kid, required: 'either' }),
  }
}

// ── generators ──────────────────────────────────────────────────────────────

const body = fc.oneof(
  fc.string({ unit: 'grapheme', maxLength: 150 }),
  fc.string({ unit: 'binary-ascii', maxLength: 300 }),
  fc.json({ maxDepth: 3 }),
  fc.uint8Array({ maxLength: 300 }).map((b) => Buffer.from(b)),
  fc.uint8Array({ maxLength: 300 }),
)
const secret = fc.oneof(
  fc.string({ minLength: 1, maxLength: 40 }),
  fc.uint8Array({ minLength: 1, maxLength: 64 }).map((b) => Buffer.from(b)),
)
// Header-safe, so the same delivery can also go through a fetch Headers object.
const token = fc.option(fc.stringMatching(/^[A-Za-z0-9._:-]{1,30}$/), { nil: undefined })

const bytesOf = (b) => Buffer.from(typeof b === 'string' ? Buffer.from(b, 'utf8') : b)
const flipHex = (c) => (parseInt(c, 16) ^ 1).toString(16)

// A body with different bytes: one byte flipped, one byte added, or one taken off.
function changedBody(b, how, at) {
  const bytes = bytesOf(b)
  if (how === 'add' || bytes.length === 0) return Buffer.concat([bytes, Buffer.from([at & 0xff])])
  if (how === 'drop') return bytes.subarray(0, bytes.length - 1)
  const out = Buffer.from(bytes)
  out[at % out.length] ^= 0x01
  return out
}

// Change one hex digit after the scheme prefix of a signature header.
function changedSignature(value, prefix, at) {
  const hex = value.slice(prefix.length)
  const i = at % hex.length
  return prefix + hex.slice(0, i) + flipHex(hex[i]) + hex.slice(i + 1)
}

// ── properties ──────────────────────────────────────────────────────────────

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('a dual-signed delivery of any body verifies under every policy, however the headers arrive', () => {
  fc.assert(fc.property(body, secret, token, token, (b, s, event, deliveryId) => {
    const headers = createSigner({ hmacSecret: s, pqSecretKey: K1.secretKey, pqKid: K1.kid }).sign(b, { event, deliveryId })
    if (event !== undefined && headers['X-KXCO-Event'] !== event) return false
    if (deliveryId !== undefined && headers['X-KXCO-Delivery'] !== deliveryId) return false
    const v = verifiers(s)

    for (const policy of POLICIES) {
      if (v[policy].verify(headers, b).ok !== true) return false
    }
    // Node lower-cases header names, fetch hands over a Headers object, and the
    // body may arrive as a Buffer: all the same delivery.
    const lower = Object.fromEntries(Object.entries(headers).map(([k, x]) => [k.toLowerCase(), x]))
    for (const [h, raw] of [[lower, b], [new Headers(headers), b], [headers, bytesOf(b)]]) {
      const r = v.both.verify(h, raw)
      if (!(r.ok && r.hmacOk && r.pqOk && r.timestampOk && r.kidOk)) return false
    }
    return true
  }), SIGNING)
})

test('a delivery whose body has changed fails every policy', () => {
  fc.assert(fc.property(body, secret, fc.constantFrom('flip', 'add', 'drop'), fc.nat(), (b, s, how, at) => {
    const headers = createSigner({ hmacSecret: s, pqSecretKey: K1.secretKey, pqKid: K1.kid }).sign(b)
    const other = changedBody(b, how, at)
    fc.pre(!other.equals(bytesOf(b)))
    const v = verifiers(s)
    return POLICIES.every((policy) => {
      const r = v[policy].verify(headers, other)
      return r.ok === false && r.hmacOk === false && r.pqOk === false && REASONS.includes(r.reason)
    })
  }), SIGNING)
})

test('a delivery whose timestamp has changed fails every policy, with the body untouched', () => {
  const change = fc.oneof(
    fc.integer({ min: -300, max: 300 }).filter((k) => k !== 0).map((k) => (ts) => String(Number(ts) + k)),
    fc.constantFrom((ts) => `0${ts}`, (ts) => `${ts} `, (ts) => ` ${ts}`, (ts) => `${ts}.0`, (ts) => `${ts}.`),
    fc.string({ maxLength: 20 }).map((x) => (ts) => `${ts}.${x}`),
    fc.string({ maxLength: 20 }).map((x) => (ts) => (x === ts ? `${x}0` : x)),
  )
  fc.assert(fc.property(body, secret, change, (b, s, f) => {
    const headers = createSigner({ hmacSecret: s, pqSecretKey: K1.secretKey, pqKid: K1.kid }).sign(b)
    const ts = headers['X-KXCO-Timestamp']
    const moved = { ...headers, 'X-KXCO-Timestamp': f(ts) }
    if (moved['X-KXCO-Timestamp'] === ts) return false
    const v = verifiers(s)
    return POLICIES.every((policy) => v[policy].verify(moved, b).ok === false)
  }), SIGNING)
})

test('a timestamp header that is not all digits is refused as timestamp_skew under every policy, however it was signed', () => {
  const text = fc.string({ maxLength: 20, size: 'max' })
  const malformed = fc.oneof(
    text.map((x) => (ts) => `${ts}.${x}`),
    fc.tuple(fc.oneof(fc.constantFrom('', ' ', '+', '-'), text), text).map(([pre, post]) => (ts) => `${pre}${ts}${post}`),
  )
  fc.assert(fc.property(body, secret, malformed, (b, s, f) => {
    const ts = f(String(Math.floor(Date.now() / 1000)))
    fc.pre(!/^[0-9]+$/.test(ts))
    const headers = {
      'X-KXCO-Timestamp': ts,
      'X-KXCO-Signature': `sha256=${webhook.hmacHex(s, ts, b)}`,
      'X-KXCO-PQ-Signature': webhook.pqSign(K1.secretKey, ts, b),
      'X-KXCO-PQ-Kid': K1.kid,
    }
    const v = verifiers(s)
    return POLICIES.every((policy) => {
      const r = v[policy].verify(headers, b)
      return r.ok === false && r.reason === 'timestamp_skew'
    })
  }), SIGNING)
})

test('moving the start of a body into the timestamp header, up to any dot, fails every policy as timestamp_skew', () => {
  const parts = fc.array(fc.string({ maxLength: 30, size: 'max' }), { minLength: 2, maxLength: 6, size: 'max' })
  fc.assert(fc.property(parts, secret, fc.nat(), (p, s, at) => {
    const signed = createSigner({ hmacSecret: s, pqSecretKey: K1.secretKey, pqKid: K1.kid }).sign(p.join('.'))
    const i = 1 + (at % (p.length - 1))
    const moved = { ...signed, 'X-KXCO-Timestamp': `${signed['X-KXCO-Timestamp']}.${p.slice(0, i).join('.')}` }
    const v = verifiers(s)
    return POLICIES.every((policy) => {
      const r = v[policy].verify(moved, p.slice(i).join('.'))
      return r.ok === false && r.reason === 'timestamp_skew'
    })
  }), SIGNING)
})

test('the timestamp window decides: a correctly signed delivery verifies inside windowSeconds and is refused as timestamp_skew outside it', () => {
  fc.assert(fc.property(body, secret, fc.integer({ min: 0, max: 3600 }), fc.nat({ max: 10_000_000 }), fc.boolean(), (b, s, windowSeconds, offset, ahead) => {
    // Clear of the boundary by two seconds either way, so the clock moving
    // during the case cannot change the answer.
    fc.pre(offset <= windowSeconds - 2 || offset >= windowSeconds + 2)
    const now = Math.floor(Date.now() / 1000)
    const ts = String(ahead ? now + offset : now - offset)
    const headers = {
      'X-KXCO-Timestamp': ts,
      'X-KXCO-Signature': `sha256=${webhook.hmacHex(s, ts, b)}`,
      'X-KXCO-PQ-Signature': webhook.pqSign(K1.secretKey, ts, b),
      'X-KXCO-PQ-Kid': K1.kid,
    }
    const inside = offset <= windowSeconds - 2
    const v = createVerifier({ hmacSecret: s, pqPublicKey: K1.publicKey, pinnedKid: K1.kid, required: 'both', windowSeconds })
    const r = v.verify(headers, b)
    return inside ? r.ok === true : r.ok === false && r.reason === 'timestamp_skew'
  }), SIGNING)
})

test('each required policy passes exactly the deliveries its rule allows', () => {
  const STATES = ['intact', 'changed', 'removed']
  fc.assert(fc.property(body, secret, fc.nat(), (b, s, at) => {
    const signed = createSigner({ hmacSecret: s, pqSecretKey: K1.secretKey, pqKid: K1.kid }).sign(b)
    const v = verifiers(s)
    // Every combination of the three signature headers being intact, changed
    // or removed, against every policy.
    for (const hmac of STATES) {
      for (const pq of STATES) {
        for (const kid of STATES) {
          const headers = { ...signed }
          if (hmac === 'changed') headers['X-KXCO-Signature'] = changedSignature(signed['X-KXCO-Signature'], 'sha256=', at)
          if (hmac === 'removed') delete headers['X-KXCO-Signature']
          if (pq === 'changed') headers['X-KXCO-PQ-Signature'] = changedSignature(signed['X-KXCO-PQ-Signature'], 'ml-dsa-65=', at)
          if (pq === 'removed') delete headers['X-KXCO-PQ-Signature']
          if (kid === 'changed') headers['X-KXCO-PQ-Kid'] = K2.kid
          if (kid === 'removed') delete headers['X-KXCO-PQ-Kid']

          // The README's table: HMAC passes when its signature is intact;
          // ML-DSA-65 passes when its signature is intact and names the pinned key.
          const hmacGood = hmac === 'intact'
          const pqGood = pq === 'intact' && kid === 'intact'
          const expected = { both: hmacGood && pqGood, pq: pqGood, hmac: hmacGood, either: hmacGood || pqGood }
          for (const policy of POLICIES) {
            const r = v[policy].verify(headers, b)
            if (r.ok !== expected[policy] || (!r.ok && !REASONS.includes(r.reason))) return false
          }
        }
      }
    }
    return true
  }), { numRuns: 8 })
})

test('key rotation: a delivery from any listed key verifies and resolvedKid names it; an unlisted key is refused', () => {
  const hex = (u8) => Buffer.from(u8).toString('hex')
  fc.assert(fc.property(body, fc.constantFrom(0, 1, 2), fc.boolean(), fc.boolean(), (b, who, swap, asHex) => {
    const sender = [K1, K2, K3][who]
    const listed = swap ? [K2, K1] : [K1, K2]
    const v = createVerifier({
      pinnedKids: listed.map((k) => ({ kid: k.kid, publicKey: asHex ? hex(k.publicKey) : k.publicKey })),
      required: 'pq',
    })
    const headers = createSigner({ pqSecretKey: sender.secretKey, pqKid: sender.kid }).sign(b)
    const r = v.verify(headers, b)
    if (who === 2) {
      if (!(r.ok === false && r.reason === 'kid_mismatch' && r.resolvedKid === undefined)) return false
    } else if (!(r.ok === true && r.resolvedKid === sender.kid)) {
      return false
    }
    // Signed by one listed key but naming the other: the named key is tried, and fails.
    const relabelled = { ...headers, 'X-KXCO-PQ-Kid': sender === K1 ? K2.kid : K1.kid }
    const x = v.verify(relabelled, b)
    return x.ok === false && x.reason === 'pq_invalid'
  }), SIGNING)
})

test('compact JWS: any body round-trips with its claims; a changed body, another key, another audience or a stale iat is refused', () => {
  const audience = fc.option(fc.oneof(
    fc.stringMatching(/^https:\/\/[a-z0-9-]{1,20}\.example\/[a-z0-9/-]{0,20}$/),
    fc.string({ minLength: 1, maxLength: 40 }),
  ), { nil: undefined })
  // An iat more than the default 300 seconds either side of now.
  const skewArb = fc.integer({ min: 302, max: 10_000_000 }).chain((k) => fc.constantFrom(k, -k))
  fc.assert(fc.property(body, token, token, audience, fc.boolean(), skewArb, (b, event, deliveryId, aud, derive, skew) => {
    const jws = signBodyJws({
      rawBody: b, secretKey: K1.secretKey, ...(derive ? { publicKey: K1.publicKey } : { kid: K1.kid }),
      event, deliveryId, audience: aud,
    })
    const ok = verifyBodyJws({ token: jws, rawBody: b, publicKey: K1.publicKey, pinnedKid: K1.kid, audience: aud })
    const digest = createHash('sha256').update(bytesOf(b)).digest('hex')
    if (!(ok.valid === true && ok.kid === K1.kid && ok.claims.body_sha256 === digest &&
      Number.isInteger(ok.claims.iat) && ok.claims.event === event && ok.claims.jti === deliveryId && ok.claims.aud === aud)) {
      return false
    }
    const stale = signBodyJws({ rawBody: b, secretKey: K1.secretKey, kid: K1.kid, timestamp: Math.floor(Date.now() / 1000) + skew })
    const late = verifyBodyJws({ token: stale, rawBody: b, publicKey: K1.publicKey })
    const changed = verifyBodyJws({ token: jws, rawBody: changedBody(b, 'add', 0), publicKey: K1.publicKey })
    const otherKey = verifyBodyJws({ token: jws, rawBody: b, publicKey: K2.publicKey })
    const otherKid = verifyBodyJws({ token: jws, rawBody: b, publicKey: K1.publicKey, pinnedKid: K2.kid })
    const otherAud = verifyBodyJws({ token: jws, rawBody: b, publicKey: K1.publicKey, audience: `${aud ?? 'https://receiver.example'}/other` })
    return late.valid === false && late.reason === 'timestamp_outside_window' &&
      changed.valid === false && changed.reason === 'body_mismatch' &&
      otherKey.valid === false && otherKid.valid === false &&
      otherAud.valid === false && otherAud.reason === 'audience_mismatch'
  }), SIGNING)
})

test('compact JWS: verifyBodyJws never throws and never passes a token it did not issue', () => {
  const rawBody = '{"event":"invoice.paid","amount":12500}'
  const real = signBodyJws({ rawBody, secretKey: K1.secretKey, kid: K1.kid })
  const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
  const oneCharChanged = fc.tuple(fc.nat(), fc.constantFrom(...B64URL.split(''))).map(([at, c]) => {
    const i = at % real.length
    return real[i] === '.' || real[i] === c ? `${real}${c}` : real.slice(0, i) + c + real.slice(i + 1)
  })
  const segment = fc.oneof(fc.base64String({ maxLength: 40 }), fc.string({ maxLength: 40 }))
  const tokenArb = fc.oneof(
    fc.string({ maxLength: 200 }),
    fc.tuple(segment, segment, segment).map((parts) => parts.join('.')),
    oneCharChanged,
    fc.anything(),
  )
  fc.assert(fc.property(tokenArb, (t) => {
    const r = verifyBodyJws({ token: t, rawBody, publicKey: K1.publicKey })
    return r.valid === false && typeof r.reason === 'string'
  }), { numRuns: 300 })
})

test('verify never throws and never passes arbitrary signature headers', () => {
  const now = () => String(Math.floor(Date.now() / 1000))
  const value = fc.oneof(
    fc.string({ maxLength: 80 }),
    fc.stringMatching(/^[0-9a-f]{64}$/).map((h) => `sha256=${h}`),
    fc.uint8Array({ minLength: 3309, maxLength: 3309 }).map((u) => `ml-dsa-65=${Buffer.from(u).toString('hex')}`),
    fc.constantFrom(K1.kid, K2.kid),
    fc.array(fc.string({ maxLength: 20 }), { minLength: 1, maxLength: 2 }),
  )
  const headers = fc.record({
    'x-kxco-timestamp': fc.oneof({ weight: 3, arbitrary: fc.constant(null).map(() => now()) }, { weight: 1, arbitrary: value }),
    'x-kxco-signature': value,
    'x-kxco-pq-signature': value,
    'x-kxco-pq-kid': fc.oneof({ weight: 3, arbitrary: fc.constant(K1.kid) }, { weight: 1, arbitrary: value }),
  }, { requiredKeys: [] })
  fc.assert(fc.property(headers, body, secret, (h, b, s) => {
    const v = verifiers(s)
    return POLICIES.every((policy) => {
      const r = v[policy].verify(h, b)
      return r.ok === false && REASONS.includes(r.reason)
    })
  }), { numRuns: 150 })
})
