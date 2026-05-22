import type { Verifier, VerifyResult } from './builders.js'

export function nodePqWebhook(
  verifier: Verifier,
  handler: (req: any, res: any) => any | Promise<any>,
  opts?: { throwOnFail?: boolean },
): (req: any, res: any) => Promise<void>

import type { Signer } from './builders.js'

export function pqResponseSigner(
  opts: { signer: Signer; event?: string; strict?: boolean },
): (handler: (req: any, res: any) => any | Promise<any>) => (req: any, res: any) => Promise<void>
