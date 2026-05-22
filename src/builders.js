// Opinionated builders for webhook senders and receivers.
//
// Wraps the low-level helpers from `kxco-post-quantum/webhook` (`signDelivery`
// + `verifyDelivery`) so callers get a small object they can hold a reference
// to instead of threading config through every call. Adds two things the
// low-level API does NOT have:
//
//   1. A `required` policy on the verifier — the caller declares whether
//      they want HMAC, PQ, both, or either. The result includes a boolean
//      `ok` computed against that policy so middleware doesn't have to
//      re-implement the decision logic.
//
//   2. Up-front argument validation. Missing kid, wrong-length pubkey,
//      empty secret — all caught at builder time, not on the hot path.
//
// Both builders are pure JS, no I/O, no globals — suitable for use inside
// Workers / serverless / edge runtimes.

import { webhook } from 'kxco-post-quantum'

const { signDelivery, verifyDelivery, hmacHex, pqSign } = webhook

const ML_DSA_65_PUBKEY_BYTES = 1952

/**
 * @typedef {Object} SignerOpts
 * @property {string|Buffer}     [hmacSecret]   — shared HMAC-SHA-256 secret
 * @property {Buffer|Uint8Array} [pqSecretKey]  — raw ML-DSA-65 secret key (4032 bytes)
 * @property {string}            [pqKid]        — fingerprint of the matching pubkey; required iff pqSecretKey
 *
 * @typedef {Object} Signer
 * @property {(rawBody: string|Buffer, opts?: { event?: string, deliveryId?: string }) => Record<string,string>} sign
 * @property {string|undefined} pqKid
 */

/**
 * Build a webhook signer. At least one of hmacSecret / pqSecretKey is required.
 *
 * @param {SignerOpts} opts
 * @returns {Signer}
 */
export function createSigner(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError('createSigner: opts must be an object')
  }
  const { hmacSecret, pqSecretKey, pqKid } = opts
  if (!hmacSecret && !pqSecretKey) {
    throw new TypeError('createSigner: at least one of { hmacSecret, pqSecretKey } is required')
  }
  if (pqSecretKey && !pqKid) {
    throw new TypeError('createSigner: pqKid is required when pqSecretKey is provided')
  }
  if (pqKid && typeof pqKid !== 'string') {
    throw new TypeError('createSigner: pqKid must be a string')
  }
  return {
    pqKid,
    sign(rawBody, { event, deliveryId } = {}) {
      if (rawBody === undefined || rawBody === null) {
        throw new TypeError('signer.sign: rawBody is required')
      }
      // Upstream `signDelivery` always calls pqSign(), so it crashes when no
      // pqSecretKey is configured. Use it only in the dual-sig case; otherwise
      // build the headers here from the lower-level helpers.
      if (hmacSecret && pqSecretKey) {
        return signDelivery({ rawBody, hmacSecret, pqSecretKey, pqKid, event, deliveryId })
      }
      const ts = Math.floor(Date.now() / 1000).toString()
      const headers = {
        'Content-Type':     'application/json',
        'X-KXCO-Timestamp': ts,
      }
      if (hmacSecret)  headers['X-KXCO-Signature']    = 'sha256=' + hmacHex(hmacSecret, ts, rawBody)
      if (pqSecretKey) {
        headers['X-KXCO-PQ-Signature'] = pqSign(pqSecretKey, ts, rawBody)
        headers['X-KXCO-PQ-Kid']       = pqKid
      }
      if (event)      headers['X-KXCO-Event']    = event
      if (deliveryId) headers['X-KXCO-Delivery'] = deliveryId
      return headers
    },
  }
}

/**
 * @typedef {'hmac'|'pq'|'both'|'either'} RequiredPolicy
 *
 * @typedef {Object} VerifierOpts
 * @property {string|Buffer}     [hmacSecret]   — shared HMAC-SHA-256 secret
 * @property {Buffer|Uint8Array|string} [pqPublicKey] — raw ML-DSA-65 public key (1952 bytes) or hex string
 * @property {string}            [pinnedKid]    — required iff pqPublicKey; rejects deliveries with a different kid header
 * @property {number}            [windowSeconds=300] — max acceptable clock skew on X-KXCO-Timestamp
 * @property {RequiredPolicy}    [required='both']   — what counts as "verified": hmac only / pq only / both / either
 *
 * @typedef {Object} VerifyResult
 * @property {boolean} ok            — overall verdict, computed against `required` policy
 * @property {boolean} hmacOk        — HMAC signature matched
 * @property {boolean} pqOk          — ML-DSA-65 signature matched
 * @property {boolean} timestampOk   — X-KXCO-Timestamp within windowSeconds of now
 * @property {boolean} kidOk         — X-KXCO-PQ-Kid header matched pinnedKid (true when no pubkey is configured)
 * @property {string=} reason        — when !ok, a short reason code: missing_pq | missing_hmac | timestamp_skew | kid_mismatch | hmac_invalid | pq_invalid
 *
 * @typedef {Object} Verifier
 * @property {(headers: Record<string,string|undefined>, rawBody: string|Buffer) => VerifyResult} verify
 * @property {RequiredPolicy} required
 */

/**
 * Build a webhook verifier.
 *
 * @param {VerifierOpts} opts
 * @returns {Verifier}
 */
export function createVerifier(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError('createVerifier: opts must be an object')
  }
  const {
    hmacSecret,
    pqPublicKey,
    pinnedKid,
    windowSeconds = 300,
    required = 'both',
  } = opts

  if (!['hmac', 'pq', 'both', 'either'].includes(required)) {
    throw new TypeError(`createVerifier: required must be one of 'hmac' | 'pq' | 'both' | 'either' (got ${JSON.stringify(required)})`)
  }
  if (!hmacSecret && !pqPublicKey) {
    throw new TypeError('createVerifier: at least one of { hmacSecret, pqPublicKey } is required')
  }
  if (pqPublicKey && !pinnedKid) {
    throw new TypeError('createVerifier: pinnedKid is required when pqPublicKey is provided')
  }
  if (required === 'hmac' && !hmacSecret) {
    throw new TypeError('createVerifier: required="hmac" but no hmacSecret provided')
  }
  if (required === 'pq' && !pqPublicKey) {
    throw new TypeError('createVerifier: required="pq" but no pqPublicKey provided')
  }
  if (required === 'both' && (!hmacSecret || !pqPublicKey)) {
    throw new TypeError('createVerifier: required="both" needs both hmacSecret AND pqPublicKey')
  }
  if (typeof windowSeconds !== 'number' || windowSeconds < 0) {
    throw new TypeError('createVerifier: windowSeconds must be a non-negative number')
  }

  // Normalise pubkey: accept hex string OR raw bytes; verifyDelivery wants bytes.
  let pqPublicKeyBytes
  if (pqPublicKey) {
    if (typeof pqPublicKey === 'string') {
      if (!/^[0-9a-f]+$/i.test(pqPublicKey) || pqPublicKey.length !== ML_DSA_65_PUBKEY_BYTES * 2) {
        throw new TypeError(`createVerifier: pqPublicKey hex must be ${ML_DSA_65_PUBKEY_BYTES * 2} chars (got ${pqPublicKey.length})`)
      }
      pqPublicKeyBytes = Buffer.from(pqPublicKey, 'hex')
    } else if (pqPublicKey instanceof Uint8Array || Buffer.isBuffer(pqPublicKey)) {
      if (pqPublicKey.length !== ML_DSA_65_PUBKEY_BYTES) {
        throw new TypeError(`createVerifier: pqPublicKey must be ${ML_DSA_65_PUBKEY_BYTES} bytes (got ${pqPublicKey.length})`)
      }
      pqPublicKeyBytes = pqPublicKey
    } else {
      throw new TypeError('createVerifier: pqPublicKey must be a hex string, Buffer, or Uint8Array')
    }
  }

  return {
    required,
    verify(headers, rawBody) {
      const lower = normaliseHeaders_(headers)
      const r = verifyDelivery({
        headers:      lower,
        rawBody,
        hmacSecret,
        pqPublicKey:  pqPublicKeyBytes,
        pinnedKid,
        windowSeconds,
      })
      const verdict = applyPolicy_(r, required, lower)
      return { ...r, ...verdict }
    },
  }
}

function applyPolicy_(r, required, headers) {
  const hasHmac = !!headers['x-kxco-signature']
  const hasPq   = !!headers['x-kxco-pq-signature']

  // Timestamp is checked before everything else — without a fresh timestamp
  // both signatures are over a different envelope than the one we computed,
  // so subsequent checks would mislead.
  if (!r.timestampOk) return { ok: false, reason: 'timestamp_skew' }

  switch (required) {
    case 'hmac':
      if (!hasHmac)      return { ok: false, reason: 'missing_hmac' }
      if (!r.hmacOk)     return { ok: false, reason: 'hmac_invalid' }
      return { ok: true }

    case 'pq':
      if (!hasPq)        return { ok: false, reason: 'missing_pq' }
      if (!r.kidOk)      return { ok: false, reason: 'kid_mismatch' }
      if (!r.pqOk)       return { ok: false, reason: 'pq_invalid' }
      return { ok: true }

    case 'both':
      if (!hasHmac)      return { ok: false, reason: 'missing_hmac' }
      if (!r.hmacOk)     return { ok: false, reason: 'hmac_invalid' }
      if (!hasPq)        return { ok: false, reason: 'missing_pq' }
      if (!r.kidOk)      return { ok: false, reason: 'kid_mismatch' }
      if (!r.pqOk)       return { ok: false, reason: 'pq_invalid' }
      return { ok: true }

    case 'either':
      // Defense in depth — either signature passing is enough.
      if (r.hmacOk)                            return { ok: true }
      if (hasPq && r.kidOk && r.pqOk)          return { ok: true }
      if (!hasHmac && !hasPq)                  return { ok: false, reason: 'missing_pq' }
      // Tried whichever signatures were present, none passed.
      return { ok: false, reason: hasHmac ? 'hmac_invalid' : 'pq_invalid' }
  }
}

/**
 * Header normalisation. Accepts a plain object, a Headers instance, or
 * Node's IncomingHttpHeaders. Returns a flat lowercase-key object.
 */
function normaliseHeaders_(headers) {
  if (!headers) return {}
  if (typeof headers.get === 'function') {
    // Fetch-style Headers
    const out = {}
    for (const [k, v] of headers.entries()) out[k.toLowerCase()] = v
    return out
  }
  const out = {}
  for (const [k, v] of Object.entries(headers)) {
    if (v === undefined) continue
    out[k.toLowerCase()] = Array.isArray(v) ? v[0] : v
  }
  return out
}
