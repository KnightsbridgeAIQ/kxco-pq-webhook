// A second proof path: a compact JWS over the delivery, alongside the existing
// X-KXCO-* headers.
//
// The header scheme is not going anywhere. It is what every existing receiver
// parses, it is smaller on the wire, and it is what the docs describe. This is
// an alternative for receivers whose stack already speaks JWS — a gateway, an
// IdP, a partner's verifier — because for them "add a JWS header" is a config
// change and "parse three bespoke headers" is a project.
//
// The payload is DETACHED: the JWS carries a SHA-256 of the body rather than
// the body itself. Duplicating a webhook body into a header would double the
// bytes on the wire and give a lazy verifier two copies to disagree about. The
// hash binds the signature to exactly one body and to nothing else.
//
// The claims cover the same envelope the header scheme signs — timestamp and
// body — plus the event and delivery id, so a delivery cannot be replayed
// under a different event name.

import { jws as compactJws, fingerprint } from 'kxco-post-quantum'
import { createHash } from 'node:crypto'

/** The header this module reads and writes. */
export const JWS_HEADER = 'X-KXCO-JWS'

const enc = new TextEncoder()

// The key decides the JWS `alg`: an ML-DSA-65 key signs and verifies
// 'ML-DSA-65', an ML-DSA-87 key 'ML-DSA-87'. A token naming the other set from
// the verifying key is refused by the alg check, not tried.
function jwsAlgForSecretKey(secretKey) {
  if (secretKey?.length === 4896) return 'ML-DSA-87'
  if (secretKey?.length === 4032) return 'ML-DSA-65'
  return null
}

function jwsAlgForPublicKey(publicKey) {
  return publicKey?.length === 2592 ? 'ML-DSA-87' : 'ML-DSA-65'
}

function sha256Hex(input) {
  const bytes = typeof input === 'string' ? enc.encode(input) : new Uint8Array(input)
  return createHash('sha256').update(bytes).digest('hex')
}

/**
 * Sign a delivery into a compact JWS.
 *
 * @param {object} opts
 * @param {string|Uint8Array} opts.rawBody
 * @param {Uint8Array|Buffer} opts.secretKey  ML-DSA-65 (4032 bytes) or ML-DSA-87 (4896 bytes); its set is the token's alg
 * @param {string} [opts.kid]        — defaults to the fingerprint of `publicKey`
 * @param {Uint8Array} [opts.publicKey] — used only to derive `kid` when omitted
 * @param {number} [opts.timestamp]  — unix seconds. Defaults to now.
 * @param {string} [opts.event]
 * @param {string} [opts.deliveryId]
 * @param {string} [opts.audience]   — the receiving endpoint, if you pin one
 * @returns {string} compact JWS
 */
export function signBodyJws({
  rawBody, secretKey, kid, publicKey, timestamp, event, deliveryId, audience,
}) {
  if (rawBody === undefined || rawBody === null) {
    throw new TypeError('signBodyJws: rawBody is required')
  }
  if (!secretKey) throw new TypeError('signBodyJws: secretKey is required')
  const alg = jwsAlgForSecretKey(secretKey)
  if (alg === null) {
    throw new TypeError('signBodyJws: secretKey must be an ML-DSA-65 (4032-byte) or ML-DSA-87 (4896-byte) secret key')
  }

  const resolvedKid = kid ?? (publicKey ? fingerprint(publicKey) : undefined)
  if (!resolvedKid) {
    throw new TypeError('signBodyJws: pass kid, or publicKey so the kid can be derived')
  }

  const iat = timestamp ?? Math.floor(Date.now() / 1000)
  const claims = {
    iat,
    // Detached payload: the digest, not the body.
    body_sha256: sha256Hex(rawBody),
    ...(event ? { event } : {}),
    ...(deliveryId ? { jti: deliveryId } : {}),
    ...(audience ? { aud: audience } : {}),
  }

  return compactJws.signJws(claims, secretKey, {
    alg,
    kid: resolvedKid,
    typ: 'kxco-webhook+jws',
  })
}

/**
 * Verify a compact JWS against a body.
 *
 * Fails closed and never throws on bad input, matching `verifyDelivery`.
 *
 * @param {object} opts
 * @param {string} opts.token
 * @param {string|Uint8Array} opts.rawBody
 * @param {Uint8Array|Buffer} opts.publicKey  ML-DSA-65 or ML-DSA-87; a token whose alg names the other set is refused
 * @param {string} [opts.pinnedKid]     — reject a token naming a different key
 * @param {number} [opts.windowSeconds] — clock skew allowed on `iat`. Default 300.
 * @param {string} [opts.audience]      — require this `aud` claim
 * @returns {{ valid: boolean, reason?: string, claims?: object, kid?: string, alg?: string }}
 */
export function verifyBodyJws({
  token, rawBody, publicKey, pinnedKid, windowSeconds = 300, audience,
}) {
  if (typeof token !== 'string' || token.length === 0) {
    return { valid: false, reason: 'missing_jws' }
  }
  if (rawBody === undefined || rawBody === null) {
    return { valid: false, reason: 'missing_body' }
  }

  // The kid is checked before the signature so a receiver holding several keys
  // can reject a token for a key it does not serve without doing the maths.
  const result = compactJws.verifyJws(token, publicKey, {
    alg: jwsAlgForPublicKey(publicKey),
    ...(pinnedKid ? { kid: pinnedKid } : {}),
  })
  if (!result.valid) {
    return { valid: false, reason: result.error }
  }

  let claims
  try {
    claims = JSON.parse(result.text)
  } catch {
    return { valid: false, reason: 'claims_not_json' }
  }

  // The signature is valid, so the body hash is the signer's own statement
  // about which body this token belongs to. A mismatch means the token was
  // lifted from a different delivery.
  if (typeof claims.body_sha256 !== 'string' || !constantTimeHexEquals(claims.body_sha256, sha256Hex(rawBody))) {
    return { valid: false, reason: 'body_mismatch' }
  }

  if (!Number.isFinite(claims.iat)) {
    return { valid: false, reason: 'missing_iat' }
  }
  if (Math.abs(Math.floor(Date.now() / 1000) - claims.iat) > windowSeconds) {
    return { valid: false, reason: 'timestamp_outside_window' }
  }

  if (audience !== undefined && claims.aud !== audience) {
    return { valid: false, reason: 'audience_mismatch' }
  }

  return { valid: true, claims, kid: result.header.kid, alg: result.header.alg }
}

function constantTimeHexEquals(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
