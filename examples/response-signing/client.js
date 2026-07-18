// verifiedFetch client (Phase 3 — kxco-post-quantum-webhook ≥ 0.2.0).
//
// Wraps fetch, verifies the response's X-KXCO-* signature against a pinned
// PQ pubkey, and only hands the body to the caller AFTER verification.
// Throws KxcoResponseError on bad signature (strict default) so unverified
// bytes can't leak into application logic by accident.
//
// Setup:
//   npm install kxco-post-quantum-webhook
//   KXCO_REMOTE_URL=https://api.example.com/api/quote
//   KXCO_PQ_KID=... KXCO_PQ_PUBKEY_HEX=...
//   node client.js

import { createVerifier }                  from 'kxco-post-quantum-webhook'
import { verifiedFetch, KxcoResponseError } from 'kxco-post-quantum-webhook/verified-fetch'

const verifier = createVerifier({
  pqPublicKey: process.env.KXCO_PQ_PUBKEY_HEX,
  pinnedKid:   process.env.KXCO_PQ_KID,
  required:    'pq',
})

try {
  const { response, kxcoResponse } = await verifiedFetch(
    process.env.KXCO_REMOTE_URL,
    { method: 'GET' },
    { verifier },
  )

  // Body is safe to read here — signature has been verified.
  const quote = await response.json()
  console.log('verified:', JSON.stringify(kxcoResponse))
  console.log('body:    ', quote)
} catch (err) {
  if (err instanceof KxcoResponseError) {
    console.error('signature failed:', err.kxcoResponse.reason)
    // Unverified bytes accessible via err.response if you really want them
    // — e.g., to log forensic context. Never trust them.
    process.exit(1)
  }
  throw err
}
