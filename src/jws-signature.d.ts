/// <reference types="node" />

/** The header this module reads and writes. */
export const JWS_HEADER: 'X-KXCO-JWS'

export interface SignBodyJwsOptions {
  rawBody: string | Uint8Array
  /** ML-DSA-65 (4032 bytes) or ML-DSA-87 (4896 bytes) secret key. Its set is the token's `alg`. */
  secretKey: Uint8Array | Buffer
  /** Defaults to the fingerprint of `publicKey`. One of the two is required. */
  kid?: string
  publicKey?: Uint8Array | Buffer
  /** Unix seconds. Defaults to now. */
  timestamp?: number
  event?: string
  deliveryId?: string
  /** The receiving endpoint, if you pin one. */
  audience?: string
}

/**
 * Sign a delivery into a compact JWS.
 *
 * The payload is DETACHED: the claims carry a SHA-256 of the body, not the
 * body itself, so the header does not duplicate the delivery on the wire.
 */
export function signBodyJws(opts: SignBodyJwsOptions): string

export interface VerifyBodyJwsOptions {
  token: string
  rawBody: string | Uint8Array
  /** ML-DSA-65 or ML-DSA-87. A token whose `alg` names the other set is refused. */
  publicKey: Uint8Array | Buffer
  /** Reject a token naming a different key. */
  pinnedKid?: string
  /** Clock skew allowed on `iat`. Default 300. */
  windowSeconds?: number
  /** Require this `aud` claim. */
  audience?: string
}

export interface VerifyBodyJwsResult {
  valid: boolean
  /** Present when invalid: missing_jws, body_mismatch, timestamp_outside_window, … */
  reason?: string
  claims?: Record<string, unknown>
  kid?: string
  /** The token's `alg`, 'ML-DSA-65' or 'ML-DSA-87', when valid. */
  alg?: string
}

/** Verify a compact JWS against a body. Fails closed; never throws on bad input. */
export function verifyBodyJws(opts: VerifyBodyJwsOptions): VerifyBodyJwsResult
