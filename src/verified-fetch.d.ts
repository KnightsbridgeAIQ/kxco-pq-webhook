import type { Verifier, VerifyResult } from './builders.js'

export class KxcoResponseError extends Error {
  code: 'kxco_response_unverified'
  kxcoResponse: VerifyResult
  response: Response
  constructor(message: string, kxcoResponse: VerifyResult, response: Response)
}

export interface VerifiedFetchOpts {
  verifier: Verifier
  /** If true, do NOT throw on bad signature; return the result for inspection. */
  permissive?: boolean
  fetchImpl?: typeof fetch
}

export interface VerifiedFetchResult {
  response: Response
  kxcoResponse: VerifyResult
}

export function verifiedFetch(
  url: string | URL | Request,
  init: RequestInit | undefined,
  opts: VerifiedFetchOpts,
): Promise<VerifiedFetchResult>
