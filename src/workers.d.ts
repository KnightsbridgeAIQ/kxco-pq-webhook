import type { Verifier, VerifyResult } from './builders.js'

export function verifyRequest(
  verifier: Verifier,
  request: Request,
): Promise<{ result: VerifyResult; rawBody: string }>

export function withPqWebhook(
  verifier: Verifier,
  handler: (request: Request, env?: any, ctx?: any, result?: VerifyResult) => Response | Promise<Response>,
  opts?: { throwOnFail?: boolean },
): (request: Request, env?: any, ctx?: any) => Promise<Response>

import type { Signer } from './builders.js'

export function withPqResponseSigning(
  signer: Signer,
  handler: (request: Request, env?: any, ctx?: any) => Response | Promise<Response>,
  opts?: { event?: string; strict?: boolean },
): (request: Request, env?: any, ctx?: any) => Promise<Response>
