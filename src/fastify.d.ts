import type { Verifier, VerifyResult } from './builders.js'

export interface FastifyPluginOpts {
  verifier: Verifier
  prefix?: string
  /** When true, do not 401; let your handler decide. */
  throwOnFail?: boolean
}

declare module 'fastify' {
  interface FastifyRequest {
    kxcoWebhook?: VerifyResult
  }
}

declare const pqWebhookPlugin: (fastify: any, opts: FastifyPluginOpts) => Promise<void>
export default pqWebhookPlugin
