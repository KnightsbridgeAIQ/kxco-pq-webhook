import type { Signer } from './builders.js'

export interface SignedFetchOpts {
  signer: Signer
  body?: unknown
  event?: string
  deliveryId?: string
  headers?: Record<string, string>
  method?: string
  fetchImpl?: typeof fetch
}

export function signedFetch(url: string, opts: SignedFetchOpts): Promise<Response>

export interface SignedEnvelopeOpts {
  event?: string
  deliveryId?: string
}

export interface SignedEnvelope {
  rawBody: string | Buffer
  headers: Record<string, string>
}

export function signedEnvelope(
  signer: Signer,
  body: unknown,
  opts?: SignedEnvelopeOpts,
): SignedEnvelope
