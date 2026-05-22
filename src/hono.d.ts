import type { Verifier, VerifyResult } from './builders.js'

export interface HonoMiddlewareOpts {
  throwOnFail?: boolean
}

export function pqWebhook(verifier: Verifier, opts?: HonoMiddlewareOpts): any

import type { Signer } from './builders.js'

export interface HonoResponseSignerOpts {
  signer: Signer
  event?: string
  /** When true, throw on streaming bodies. Default false: skip signing. */
  strict?: boolean
}

export function pqResponseSigner(opts: HonoResponseSignerOpts): any
