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

import { webhook, mlDsa87 } from 'kxco-post-quantum'

const { signDelivery, verifyDelivery, hmacHex, pqSign, envelope } = webhook

// The two ML-DSA parameter sets a PQ key can be, named as the contract's
// `algorithm` field names them. The KEY decides: its length says which set it
// is, and the set decides the header form. An ML-DSA-65 key signs and verifies
// `ml-dsa-65=<hex>` through kxco-post-quantum's webhook helpers exactly as
// before. An ML-DSA-87 key signs and verifies `ml-dsa-87=<hex>` over the same
// `timestamp.body` envelope, and only that form: a header whose prefix names
// the other set, or bare hex, fails. That is the rule kxco-post-quantum's own
// webhook module applies from the release that adds ML-DSA-87.
const PQ_SETS = Object.freeze({
  'ml-dsa-65': Object.freeze({ publicKeyBytes: 1952, secretKeyBytes: 4032 }),
  'ml-dsa-87': Object.freeze({ publicKeyBytes: 2592, secretKeyBytes: 4896 }),
})
const ML_DSA_87_PREFIX = 'ml-dsa-87='

function pqSetOf(key, field) {
  for (const [name, set] of Object.entries(PQ_SETS)) if (key?.length === set[field]) return name
  return null
}

function pqSign87(secretKey, timestamp, rawBody) {
  return ML_DSA_87_PREFIX + mlDsa87.sign(secretKey, envelope(timestamp, rawBody))
}

function verifyPq87(publicKey, timestamp, rawBody, sigHeader) {
  if (typeof sigHeader !== 'string' || !sigHeader.startsWith(ML_DSA_87_PREFIX)) return false
  return mlDsa87.verify(publicKey, envelope(timestamp, rawBody), sigHeader.slice(ML_DSA_87_PREFIX.length))
}

/**
 * @typedef {Object} SignerOpts
 * @property {string|Buffer}     [hmacSecret]   — shared HMAC-SHA-256 secret
 * @property {Buffer|Uint8Array} [pqSecretKey]  raw ML-DSA-65 (4032-byte) or ML-DSA-87 (4896-byte) secret key; its length decides the header form
 * @property {string}            [pqKid]        — fingerprint of the matching pubkey; required iff pqSecretKey
 *
 * @typedef {Object} Signer
 * @property {(rawBody: string|Buffer, opts?: { event?: string, deliveryId?: string }) => Record<string,string>} sign
 * @property {string|undefined} pqKid
 * @property {'ml-dsa-65'|'ml-dsa-87'|undefined} pqAlgorithm  the PQ key's parameter set
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
  const pqAlgorithm = pqSecretKey ? pqSetOf(pqSecretKey, 'secretKeyBytes') : undefined
  if (pqSecretKey && pqAlgorithm === null) {
    throw new TypeError(
      `createSigner: pqSecretKey must be an ML-DSA-65 (4032-byte) or ML-DSA-87 (4896-byte) secret key (got ${pqSecretKey.length})`,
    )
  }
  return {
    pqKid,
    pqAlgorithm,
    sign(rawBody, { event, deliveryId } = {}) {
      if (rawBody === undefined || rawBody === null) {
        throw new TypeError('signer.sign: rawBody is required')
      }
      // Upstream `signDelivery` always calls pqSign(), so it crashes when no
      // pqSecretKey is configured. Use it only in the dual-sig case; otherwise
      // build the headers here from the lower-level helpers. Its pqSign is
      // ML-DSA-65 only, so an ML-DSA-87 key always takes the second path.
      if (hmacSecret && pqSecretKey && pqAlgorithm === 'ml-dsa-65') {
        return signDelivery({ rawBody, hmacSecret, pqSecretKey, pqKid, event, deliveryId })
      }
      const ts = Math.floor(Date.now() / 1000).toString()
      const headers = {
        'Content-Type':     'application/json',
        'X-KXCO-Timestamp': ts,
      }
      if (hmacSecret)  headers['X-KXCO-Signature']    = 'sha256=' + hmacHex(hmacSecret, ts, rawBody)
      if (pqSecretKey) {
        headers['X-KXCO-PQ-Signature'] = pqAlgorithm === 'ml-dsa-87'
          ? pqSign87(pqSecretKey, ts, rawBody)
          : pqSign(pqSecretKey, ts, rawBody)
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
 * @typedef {Object} PinnedKidEntry
 * @property {string}                   kid       — 16 hex chars
 * @property {Buffer|Uint8Array|string} publicKey — raw ML-DSA-65 (1952-byte) or ML-DSA-87 (2592-byte) pubkey, or hex
 * @property {'ml-dsa-65'|'ml-dsa-87'}  [algorithm] — the contract's `algorithm` for this key, if the publisher states one; refused if it disagrees with the key
 *
 * @typedef {Object} VerifierOpts
 * @property {string|Buffer}     [hmacSecret]   — shared HMAC-SHA-256 secret
 * @property {Buffer|Uint8Array|string} [pqPublicKey] — raw ML-DSA-65 (1952-byte) or ML-DSA-87 (2592-byte) public key, or hex
 * @property {'ml-dsa-65'|'ml-dsa-87'} [pqAlgorithm] — the contract's `algorithm` for pqPublicKey, if known; refused if it disagrees with the key
 * @property {string}            [pinnedKid]    — required iff pqPublicKey; rejects deliveries with a different kid header
 * @property {PinnedKidEntry[]}  [pinnedKids]   — accept any kid in this set; mutually exclusive with pinnedKid/pqPublicKey
 * @property {number}            [windowSeconds=300] — max acceptable clock skew on X-KXCO-Timestamp
 * @property {RequiredPolicy}    [required='both']   — what counts as "verified": hmac only / pq only / both / either
 *
 * @typedef {Object} VerifyResult
 * @property {boolean} ok            — overall verdict, computed against `required` policy
 * @property {boolean} hmacOk        — HMAC signature matched
 * @property {boolean} pqOk          — ML-DSA signature matched, in the set the key belongs to
 * @property {boolean} timestampOk   — X-KXCO-Timestamp within windowSeconds of now
 * @property {boolean} kidOk         — X-KXCO-PQ-Kid header matched pinnedKid (true when no pubkey is configured)
 * @property {string=} reason        — when !ok, a short reason code: missing_pq | missing_hmac | timestamp_skew | kid_mismatch | hmac_invalid | pq_invalid
 * @property {string=} resolvedKid   — when pinnedKids[] is used and matched: the kid that was selected for verification
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
    pinnedKids,
    pqAlgorithm,
    windowSeconds = 300,
    required = 'both',
  } = opts

  if (!['hmac', 'pq', 'both', 'either'].includes(required)) {
    throw new TypeError(`createVerifier: required must be one of 'hmac' | 'pq' | 'both' | 'either' (got ${JSON.stringify(required)})`)
  }
  if (pinnedKids && (pinnedKid || pqPublicKey)) {
    throw new TypeError('createVerifier: pinnedKids is mutually exclusive with pinnedKid/pqPublicKey — pick one shape')
  }
  const hasPqConfig = !!(pqPublicKey || pinnedKids)
  if (!hmacSecret && !hasPqConfig) {
    throw new TypeError('createVerifier: at least one of { hmacSecret, pqPublicKey, pinnedKids } is required')
  }
  if (pqPublicKey && !pinnedKid) {
    throw new TypeError('createVerifier: pinnedKid is required when pqPublicKey is provided')
  }
  if (required === 'hmac' && !hmacSecret) {
    throw new TypeError('createVerifier: required="hmac" but no hmacSecret provided')
  }
  if (required === 'pq' && !hasPqConfig) {
    throw new TypeError('createVerifier: required="pq" but no pqPublicKey/pinnedKids provided')
  }
  if (required === 'both' && (!hmacSecret || !hasPqConfig)) {
    throw new TypeError('createVerifier: required="both" needs hmacSecret AND a PQ key configuration')
  }
  if (typeof windowSeconds !== 'number' || windowSeconds < 0) {
    throw new TypeError('createVerifier: windowSeconds must be a non-negative number')
  }

  if (pqAlgorithm !== undefined && !pqPublicKey) {
    throw new TypeError('createVerifier: pqAlgorithm describes pqPublicKey, which was not provided')
  }

  // Normalise the single-key form.
  const pqPublicKeyBytes = pqPublicKey ? normalisePubKey_(pqPublicKey, 'pqPublicKey') : undefined
  const pqPublicKeySet = pqPublicKeyBytes
    ? checkAlgorithm_(pqAlgorithm, pqPublicKeyBytes, 'pqAlgorithm', 'pqPublicKey')
    : undefined

  // Build the multi-key keystore if pinnedKids[] was provided. Map<kid, bytes>.
  let pqKeystore
  let firstKidEntry
  if (pinnedKids) {
    if (!Array.isArray(pinnedKids) || pinnedKids.length === 0) {
      throw new TypeError('createVerifier: pinnedKids must be a non-empty array')
    }
    pqKeystore = new Map()
    for (const entry of pinnedKids) {
      if (!entry || typeof entry !== 'object' || typeof entry.kid !== 'string' || !entry.publicKey) {
        throw new TypeError('createVerifier: each pinnedKids entry must be { kid: string, publicKey: hex|Buffer|Uint8Array }')
      }
      if (pqKeystore.has(entry.kid)) {
        throw new TypeError(`createVerifier: pinnedKids contains duplicate kid ${entry.kid}`)
      }
      const bytes = normalisePubKey_(entry.publicKey, `pinnedKids[${entry.kid}].publicKey`)
      const set = checkAlgorithm_(entry.algorithm, bytes, `pinnedKids[${entry.kid}].algorithm`, `pinnedKids[${entry.kid}].publicKey`)
      pqKeystore.set(entry.kid, { bytes, set })
    }
    firstKidEntry = { kid: pinnedKids[0].kid, ...pqKeystore.get(pinnedKids[0].kid) }
  }

  return {
    required,
    verify(headers, rawBody) {
      const lower = normaliseHeaders_(headers)

      // Resolve which PQ key (if any) to verify against this delivery.
      let effPubKey   = pqPublicKeyBytes
      let effSet      = pqPublicKeySet
      let effPinned   = pinnedKid
      let resolvedKid
      if (pqKeystore) {
        const headerKid = lower['x-kxco-pq-kid']
        const match     = headerKid && pqKeystore.get(headerKid)
        if (match) {
          effPubKey   = match.bytes
          effSet      = match.set
          effPinned   = headerKid
          resolvedKid = headerKid
        } else {
          // No match — verifyDelivery still runs but with a pinnedKid that
          // won't match the header, so kidOk=false and policy returns
          // kid_mismatch. Use the first entry just to give verifyDelivery
          // a valid pubkey to call into (it won't be the one that matches).
          effPubKey = firstKidEntry.bytes
          effSet    = firstKidEntry.set
          effPinned = firstKidEntry.kid
        }
      }

      // The upstream verifier checks the HMAC, the timestamp and the kid, and
      // the ML-DSA-65 signature. An ML-DSA-87 key is kept away from its
      // ML-DSA-65 check and verified here, under the same conditions.
      const is87 = effSet === 'ml-dsa-87'
      const r = verifyDelivery({
        headers:      lower,
        rawBody,
        hmacSecret,
        pqPublicKey:  is87 ? undefined : effPubKey,
        pinnedKid:    effPinned,
        windowSeconds,
      })
      if (is87) {
        const sigPq = lower['x-kxco-pq-signature']
        r.pqOk = Boolean(sigPq && r.timestampOk && r.kidOk) &&
          verifyPq87(effPubKey, lower['x-kxco-timestamp'], rawBody, sigPq)
      }
      const verdict = applyPolicy_(r, required, lower)
      const out = { ...r, ...verdict }
      if (resolvedKid) out.resolvedKid = resolvedKid
      return out
    },
  }
}

function normalisePubKey_(pubKey, fieldName) {
  const sizes = (unit, scale) =>
    `${PQ_SETS['ml-dsa-65'].publicKeyBytes * scale} ${unit} (ML-DSA-65) or ${PQ_SETS['ml-dsa-87'].publicKeyBytes * scale} ${unit} (ML-DSA-87)`
  if (typeof pubKey === 'string') {
    if (!/^[0-9a-f]+$/i.test(pubKey) || pqSetOf({ length: pubKey.length / 2 }, 'publicKeyBytes') === null) {
      throw new TypeError(`createVerifier: ${fieldName} hex must be ${sizes('chars', 2)} (got ${pubKey.length})`)
    }
    return Buffer.from(pubKey, 'hex')
  }
  if (pubKey instanceof Uint8Array || Buffer.isBuffer(pubKey)) {
    if (pqSetOf(pubKey, 'publicKeyBytes') === null) {
      throw new TypeError(`createVerifier: ${fieldName} must be ${sizes('bytes', 1)} (got ${pubKey.length})`)
    }
    return pubKey
  }
  throw new TypeError(`createVerifier: ${fieldName} must be a hex string, Buffer, or Uint8Array`)
}

// The key decides its set. A stated `algorithm`, the contract's field, is
// checked against it and refused if it names the other set or neither.
function checkAlgorithm_(stated, keyBytes, algField, keyField) {
  const set = pqSetOf(keyBytes, 'publicKeyBytes')
  if (stated === undefined) return set
  if (!Object.hasOwn(PQ_SETS, stated)) {
    throw new TypeError(`createVerifier: ${algField} must be 'ml-dsa-65' or 'ml-dsa-87' (got ${JSON.stringify(stated)})`)
  }
  if (stated !== set) {
    throw new TypeError(`createVerifier: ${algField} is ${stated} but ${keyField} is an ${set} key`)
  }
  return set
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
