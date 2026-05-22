import type { Signer } from './builders.js'

export interface ResponseSignerOpts {
  signer: Signer
  event?: string
  /** When true, throw when a response cannot be signed (streaming, missing body). Default false: skip silently. */
  strict?: boolean
}

export function signResponse(
  signer: Signer,
  body: string | Buffer | Uint8Array | unknown,
  opts?: { event?: string; deliveryId?: string },
): Record<string, string>

export function isStreamingBody(body: unknown): boolean
