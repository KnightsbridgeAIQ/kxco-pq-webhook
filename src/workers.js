// Cloudflare Workers / web-standard fetch-handler adapter.
//
// Two flavours:
//
// 1. `verifyRequest(verifier, request)` — pure function. Takes a Fetch
//    Request, returns the verify result + the raw body string. Use this
//    when you're hand-rolling your Worker.
//
// 2. `withPqWebhook(verifier, handler)` — wraps your existing fetch handler.
//    If the signature fails, returns a 401 Response; otherwise calls your
//    handler with the original request and an extra `result` argument.
//
// USAGE:
//
//   import { createVerifier }              from 'kxco-post-quantum-webhook'
//   import { withPqWebhook, verifyRequest } from 'kxco-post-quantum-webhook/workers'
//
//   export default {
//     fetch: withPqWebhook(verifier, async (request, env, ctx, result) => {
//       const body = await request.text()  // safe — withPqWebhook re-cloned
//       return new Response(JSON.stringify({ ok: true, event: body }))
//     })
//   }
//
// Same module works in any Fetch-API environment: Cloudflare Workers, Deno,
// Bun, Vercel Edge Functions, browser service workers, etc.

/**
 * @typedef {import('./builders.js').Verifier}      Verifier
 * @typedef {import('./builders.js').VerifyResult}  VerifyResult
 */

/**
 * Verify a Fetch Request directly. The Request body is consumed; callers
 * who need the body downstream should pass a clone OR use withPqWebhook.
 *
 * @param {Verifier} verifier
 * @param {Request}  request
 * @returns {Promise<{ result: VerifyResult, rawBody: string }>}
 */
export async function verifyRequest(verifier, request) {
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('verifyRequest: verifier must be a built verifier (use createVerifier)')
  }
  const rawBody = await request.text()
  const result  = verifier.verify(request.headers, rawBody)
  return { result, rawBody }
}

/**
 * Wrap a fetch handler with verification. On failure, returns a 401 Response
 * with a structured JSON body. On success, calls handler with the original
 * Request (cloned, so it can still be read), the result, and any
 * Workers-style env/ctx args.
 *
 * @param {Verifier} verifier
 * @param {(request: Request, env?: any, ctx?: any, result?: VerifyResult) => Response|Promise<Response>} handler
 * @param {{ throwOnFail?: boolean }} [opts]
 */
export function withPqWebhook(verifier, handler, opts = {}) {
  if (!verifier || typeof verifier.verify !== 'function') {
    throw new TypeError('withPqWebhook: verifier must be a built verifier (use createVerifier)')
  }
  if (typeof handler !== 'function') {
    throw new TypeError('withPqWebhook: handler must be a function')
  }
  const throwOnFail = !!opts.throwOnFail

  return async function kxcoWebhookFetch(request, env, ctx) {
    // Clone so we can read the body for verification and still let the
    // handler read it from the original request.
    const cloned = request.clone()
    const { result } = await verifyRequest(verifier, cloned)
    if (!result.ok && !throwOnFail) {
      return new Response(JSON.stringify({
        error:  'webhook signature verification failed',
        code:   'kxco_webhook_unverified',
        reason: result.reason,
      }), {
        status:  401,
        headers: { 'Content-Type': 'application/json' },
      })
    }
    return handler(request, env, ctx, result)
  }
}
