// Core helpers used by every response-signing adapter.
//
// Reuses the existing `createSigner` builder — same wire format as outbound
// webhook signing. The signed envelope is `${timestamp}.${responseBody}`,
// matching the canonical webhook contract verbatim. A receiver who can verify
// an inbound webhook from this platform can verify a signed API response from
// the same platform with no code change.
//
// IMPORTANT: response signing requires the full body to be known before the
// envelope can be produced. STREAMING / SSE / chunked-transfer responses
// cannot be signed by this middleware. Adapters detect streaming patterns and
// either skip signing or surface an error per the configured strictness.

/**
 * @typedef {import('./builders.js').Signer} Signer
 *
 * @typedef {Object} ResponseSignerOpts
 * @property {Signer}   signer       — built via createSigner (must have at least pqSecretKey or hmacSecret)
 * @property {string}   [event]      — optional X-KXCO-Event header attached to every signed response
 * @property {boolean}  [strict=false] — if true, throw when a response cannot be signed (streaming, missing body). Default false: skip silently.
 */

/**
 * Compute the signing headers for a given response body. Returns the same
 * shape `createSigner.sign()` produces; adapters merge these into the
 * outgoing response headers.
 *
 * @param {Signer} signer
 * @param {string|Buffer|Uint8Array} body
 * @param {{ event?: string, deliveryId?: string }} [opts]
 * @returns {Record<string,string>}
 */
export function signResponse(signer, body, opts = {}) {
  if (!signer || typeof signer.sign !== 'function') {
    throw new TypeError('signResponse: signer must be a built signer (use createSigner)')
  }
  const normalised = body === undefined || body === null
    ? ''
    : (typeof body === 'string' || Buffer.isBuffer(body) || body instanceof Uint8Array)
      ? body
      : JSON.stringify(body)
  return signer.sign(normalised, opts)
}

/**
 * Decide whether a value looks like a streaming/chunked body the adapter
 * cannot capture in time to sign. Used by every adapter that wants to opt
 * out of signing in those cases.
 */
export function isStreamingBody(body) {
  if (body == null) return false
  if (typeof body === 'string') return false
  if (Buffer.isBuffer(body) || body instanceof Uint8Array) return false
  if (typeof body === 'object' && body.readable !== undefined && typeof body.pipe === 'function') {
    // Node.js Readable stream
    return true
  }
  if (typeof body === 'object' && typeof body.getReader === 'function') {
    // Web ReadableStream
    return true
  }
  return false
}
