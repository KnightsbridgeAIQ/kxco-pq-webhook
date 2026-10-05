/** The ML-DSA parameter sets, as the contract's `algorithm` field names them. */
export type PqAlgorithm = 'ml-dsa-65' | 'ml-dsa-87'

export interface SignerOpts {
  hmacSecret?: string | Buffer
  /** ML-DSA-65 (4032 bytes) or ML-DSA-87 (4896 bytes). Its length decides the header form. */
  pqSecretKey?: Buffer | Uint8Array
  pqKid?: string
}

export interface SignOpts {
  event?: string
  deliveryId?: string
}

export interface Signer {
  pqKid?: string
  /** The PQ key's parameter set, when one is configured. */
  pqAlgorithm?: PqAlgorithm
  sign(rawBody: string | Buffer, opts?: SignOpts): Record<string, string>
}

export function createSigner(opts: SignerOpts): Signer

export type RequiredPolicy = 'hmac' | 'pq' | 'both' | 'either'

export interface PinnedKidEntry {
  kid: string
  /** ML-DSA-65 (1952 bytes) or ML-DSA-87 (2592 bytes), raw or hex. */
  publicKey: Buffer | Uint8Array | string
  /** The publisher's stated `algorithm` for this key. Refused if it disagrees with the key. */
  algorithm?: PqAlgorithm
}

export interface VerifierOpts {
  hmacSecret?: string | Buffer
  pqPublicKey?: Buffer | Uint8Array | string
  /** The publisher's stated `algorithm` for pqPublicKey. Refused if it disagrees with the key. */
  pqAlgorithm?: PqAlgorithm
  pinnedKid?: string
  pinnedKids?: PinnedKidEntry[]
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
  resolvedKid?: string
}

export interface Verifier {
  required: RequiredPolicy
  verify(
    headers: Record<string, string | string[] | undefined> | Headers,
    rawBody: string | Buffer,
  ): VerifyResult
}

export function createVerifier(opts: VerifierOpts): Verifier
