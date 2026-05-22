import type { Verifier, VerifyResult } from './builders.js'

export interface ExpressMiddlewareOpts {
  /** When true, do not 401 on failure; pass control to next() with req.kxcoWebhook set. */
  throwOnFail?: boolean
}

/** Type augmentation for Express's Request — add this to your tsconfig types. */
declare global {
  namespace Express {
    interface Request {
      kxcoWebhook?: VerifyResult
    }
  }
}

export function pqWebhook(
  verifier: Verifier,
  opts?: ExpressMiddlewareOpts,
): (req: any, res: any, next: (err?: any) => void) => void

import type { Signer } from './builders.js'

export interface ExpressResponseSignerOpts {
  signer: Signer
  event?: string
  /** When true, throw on streaming bodies. Default false: send unsigned. */
  strict?: boolean
}

export function pqResponseSigner(
  opts: ExpressResponseSignerOpts,
): (req: any, res: any, next: (err?: any) => void) => void
