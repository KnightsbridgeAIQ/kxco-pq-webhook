import type { Verifier, VerifyResult } from './builders.js'

export interface HonoMiddlewareOpts {
  throwOnFail?: boolean
}

export function pqWebhook(verifier: Verifier, opts?: HonoMiddlewareOpts): any
