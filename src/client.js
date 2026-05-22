// Outbound signing helpers.
//
// `signedFetch` is the one-liner the brief asked for: hand it a URL + body +
// a signer (from `createSigner`), it does the canonical JSON-stringify,
// computes both signatures, and POSTs the result. Equivalent to fetch with
// the right headers attached — no special semantics.

/**
 * @typedef {import('./builders.js').Signer} Signer
 *
 * @typedef {Object} SignedFetchOpts
 * @property {Signer} signer                      — built via createSigner()
 * @property {any}    [body]                      — JSON-serialised if not already a string/Buffer
 * @property {string} [event]                     — optional X-KXCO-Event header
 * @property {string} [deliveryId]                — optional X-KXCO-Delivery idempotency id
 * @property {Record<string,string>} [headers]    — extra headers (merged after signing; cannot overwrite signing headers)
 * @property {string} [method='POST']
 * @property {typeof fetch} [fetchImpl]           — defaults to globalThis.fetch (for testing / Workers)
 */

/**
 * POST a body to a URL with hybrid HMAC + ML-DSA-65 signing headers attached.
 * Returns the Response object — does NOT throw on non-2xx; treat like
 * a normal fetch.
 *
 * @param {string} url
 * @param {SignedFetchOpts} opts
 * @returns {Promise<Response>}
 */
export async function signedFetch(url, opts) {
  if (!opts || !opts.signer) {
    throw new TypeError('signedFetch: opts.signer is required (use createSigner)')
  }
  const f = opts.fetchImpl || globalThis.fetch
  if (typeof f !== 'function') {
    throw new TypeError('signedFetch: no fetch implementation available; pass opts.fetchImpl')
  }
  if (typeof url !== 'string' || (!url.startsWith('http://') && !url.startsWith('https://'))) {
    throw new TypeError('signedFetch: url must be an absolute http(s) URL')
  }

  const rawBody = canonicaliseBody_(opts.body)
  const signed  = opts.signer.sign(rawBody, { event: opts.event, deliveryId: opts.deliveryId })
  const headers = { ...(opts.headers || {}), ...signed }  // signing headers win
  const method  = opts.method || 'POST'

  return f(url, { method, body: rawBody, headers })
}

/**
 * Lower-level helper: produce the headers + body without making the request.
 * Useful when you already have a fetch-like client (axios, undici with retry,
 * etc.) and just want the canonical signed envelope.
 *
 * @param {Signer} signer
 * @param {any}    body
 * @param {{ event?: string, deliveryId?: string }} [opts]
 * @returns {{ rawBody: string|Buffer, headers: Record<string,string> }}
 */
export function signedEnvelope(signer, body, opts = {}) {
  if (!signer || typeof signer.sign !== 'function') {
    throw new TypeError('signedEnvelope: signer must be a built signer (use createSigner)')
  }
  const rawBody = canonicaliseBody_(body)
  const headers = signer.sign(rawBody, opts)
  return { rawBody, headers }
}

/**
 * Canonical body shape: pass strings/Buffers through unchanged; JSON-stringify
 * everything else. This is deliberately simple — the rule is "the receiver
 * must see the EXACT bytes the sender signed", so the caller is responsible
 * for not mutating the body between signing and sending.
 */
function canonicaliseBody_(body) {
  if (body === undefined || body === null) return ''
  if (typeof body === 'string') return body
  if (Buffer.isBuffer(body) || body instanceof Uint8Array) return body
  return JSON.stringify(body)
}
