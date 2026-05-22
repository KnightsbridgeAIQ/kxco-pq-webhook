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
