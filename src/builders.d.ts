export interface SignerOpts {
  hmacSecret?: string | Buffer
  pqSecretKey?: Buffer | Uint8Array
  pqKid?: string
}

export interface SignOpts {
  event?: string
  deliveryId?: string
}

export interface Signer {
  pqKid?: string
  sign(rawBody: string | Buffer, opts?: SignOpts): Record<string, string>
}

export function createSigner(opts: SignerOpts): Signer

export type RequiredPolicy = 'hmac' | 'pq' | 'both' | 'either'

export interface VerifierOpts {
  hmacSecret?: string | Buffer
  pqPublicKey?: Buffer | Uint8Array | string
  pinnedKid?: string
  windowSeconds?: number
  required?: RequiredPolicy
}

export interface VerifyResult {
  ok: boolean
  hmacOk: boolean
  pqOk: boolean
  timestampOk: boolean
  kidOk: boolean
  reason?: 'missing_pq' | 'missing_hmac' | 'timestamp_skew' | 'kid_mismatch' | 'hmac_invalid' | 'pq_invalid'
}

export interface Verifier {
  required: RequiredPolicy
  verify(
    headers: Record<string, string | string[] | undefined> | Headers,
    rawBody: string | Buffer,
  ): VerifyResult
}

export function createVerifier(opts: VerifierOpts): Verifier
