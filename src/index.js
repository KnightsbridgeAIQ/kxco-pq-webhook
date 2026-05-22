// kxco-post-quantum-webhook — public entry point.
//
// What this package adds on top of `kxco-post-quantum`:
//
//   - createSigner(opts)   — opinionated builder for outbound webhook signers
//   - createVerifier(opts) — opinionated builder for inbound webhook verifiers,
//                            with a `required` policy (hmac / pq / both / either)
//                            and structured failure reasons
//   - signedFetch(url, opts) — POST a body with HMAC + ML-DSA-65 headers
//                              attached, in one call
//
//   - Framework adapters (separately importable):
//       ./express   — Express middleware
//       ./fastify   — Fastify plugin
//       ./hono      — Hono middleware
//       ./workers   — Cloudflare Workers handler factory
//       ./vercel    — Vercel Functions handler factory
//
// The signing primitives themselves live upstream in `kxco-post-quantum`
// (its `webhook` namespace). This package is opinionated wrappers + glue;
// it deliberately exposes the raw helpers below for callers who want to
// drop down past the builders.

export { createSigner, createVerifier }      from './builders.js'
export { signedFetch, signedEnvelope }       from './client.js'
export { signResponse, isStreamingBody }     from './response-core.js'
export { verifiedFetch, KxcoResponseError }  from './verified-fetch.js'

// Re-export the canonical low-level webhook helpers from kxco-post-quantum
// for callers that want the original API surface.
export { webhook }                           from 'kxco-post-quantum'
