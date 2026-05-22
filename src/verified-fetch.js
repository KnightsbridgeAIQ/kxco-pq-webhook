// verifiedFetch — client SDK for receiving + verifying signed API responses.
//
// Wraps `fetch()`. After the response arrives, runs the configured verifier
// against the response body (which is buffered before being exposed to the
// caller). Returns `{ response, kxcoResponse }`. When the verification policy
// is strict (default), throws KxcoResponseError BEFORE the caller can read
// the body, so unverified bytes cannot leak into downstream application
// logic by accident.
//
// USAGE:
//
//   import { createVerifier }   from 'kxco-post-quantum-webhook'
//   import { verifiedFetch }    from 'kxco-post-quantum-webhook/verified-fetch'
//
//   const verifier = createVerifier({
//     pqPublicKey: KXCO_PUBLIC_KEY_HEX,
//     pinnedKid:   KXCO_PUBLIC_KEY_KID,
//     required:    'pq',
//   })
//
//   const { response, kxcoResponse } = await verifiedFetch(
//     'https://api.example.com/order/123',
//     {},
//     { verifier }
//   )
//   const data = await response.json()    // safe: signature has been verified
//   console.log(kxcoResponse)             // { ok: true, hmacOk: false, pqOk: true, ... }

/**
 * @typedef {import('./builders.js').Verifier}     Verifier
 * @typedef {import('./builders.js').VerifyResult} VerifyResult
 */

export class KxcoResponseError extends Error {
  /**
   * @param {string} message
   * @param {VerifyResult} kxcoResponse
   * @param {Response}     response
   */
  constructor(message, kxcoResponse, response) {
    super(message)
    this.name           = 'KxcoResponseError'
    this.code           = 'kxco_response_unverified'
    this.kxcoResponse   = kxcoResponse
    this.response       = response
  }
}

/**
 * @typedef {Object} VerifiedFetchOpts
 * @property {Verifier} verifier      — built via createVerifier
 * @property {boolean}  [permissive=false]  — if true, do NOT throw on bad signature; return the result for inspection
 * @property {typeof fetch} [fetchImpl] — defaults to globalThis.fetch
 */

/**
 * @typedef {Object} VerifiedFetchResult
 * @property {Response}     response       — the fetch Response, with body buffered so it can be re-read
 * @property {VerifyResult} kxcoResponse   — the verifier verdict
 */

/**
 * fetch + verify in one call.
 *
 * @param {string|URL|Request} url
 * @param {RequestInit}        [init]
 * @param {VerifiedFetchOpts}  opts
 * @returns {Promise<VerifiedFetchResult>}
 */
export async function verifiedFetch(url, init, opts) {
  if (!opts || !opts.verifier || typeof opts.verifier.verify !== 'function') {
    throw new TypeError('verifiedFetch: opts.verifier is required (use createVerifier)')
  }
  const f = opts.fetchImpl || globalThis.fetch
  if (typeof f !== 'function') {
    throw new TypeError('verifiedFetch: no fetch implementation available; pass opts.fetchImpl')
  }

  const res = await f(url, init)

  // Buffer the body BEFORE the caller can read it — verification needs the
  // exact bytes, and we want to be able to hand back a Response the caller
  // can still call .json() / .text() on.
  const rawBody = await res.text()

  const kxcoResponse = opts.verifier.verify(res.headers, rawBody)

  if (!kxcoResponse.ok && !opts.permissive) {
    throw new KxcoResponseError(
      `response signature verification failed: ${kxcoResponse.reason || 'unknown'}`,
      kxcoResponse,
      // Hand the unverified bytes to the error rather than the response we'll return —
      // forces the caller to opt into seeing them via .response on the error.
      new Response(rawBody, { status: res.status, statusText: res.statusText, headers: res.headers }),
    )
  }

  // Re-wrap as a fresh Response so the caller can .text()/.json() it.
  const replayedResponse = new Response(rawBody, {
    status:     res.status,
    statusText: res.statusText,
    headers:    res.headers,
  })

  return { response: replayedResponse, kxcoResponse }
}
