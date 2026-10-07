// Example: outbound webhook sender.
//
//   node examples/sender.js
//
// Set up:
//   - hmacSecret:  shared secret you've exchanged with the receiver
//   - pqSecretKey: your ML-DSA-87 secret key (4896 bytes; produced via
//                  `mlDsa87.keypairFromMaster(KXCO_KEY_MASTER, 'my-app-87-v1')`)
//   - pqKid:       fingerprint of the matching pubkey; receivers pin against this

import { mlDsa87, fingerprint } from 'kxco-post-quantum'
import { createSigner, signedFetch } from 'kxco-post-quantum-webhook'

// Derive a deterministic keypair (same KEY_MASTER → same keys every time).
const kp = mlDsa87.keypairFromMaster(process.env.MY_APP_KEY_MASTER, 'my-app-87-v1')
const kid = fingerprint(kp.publicKey)

const signer = createSigner({
  hmacSecret:  process.env.WEBHOOK_HMAC_SECRET,
  pqSecretKey: kp.secretKey,
  pqKid:       kid,
})

// One-liner: signedFetch attaches HMAC + ML-DSA-87 headers and POSTs.
const res = await signedFetch('https://receiver.example.com/webhooks/kxco', {
  signer,
  body: {
    event: 'invoice.paid',
    invoiceId: 'inv_abc123',
    amount: 12500,
    currency: 'USD',
    paidAt: new Date().toISOString(),
  },
  event:      'invoice.paid',
  deliveryId: `dlv_${crypto.randomUUID()}`,
})
console.log(res.status, await res.text())
