// Response signing (Phase 3 — kxco-post-quantum-webhook ≥ 0.2.0).
//
// Same wire format as webhook signing, applied to outbound API responses.
// A client verifying webhooks from your platform can verify your API
// responses with zero additional code.
//
// Setup:
//   npm install express kxco-post-quantum-webhook
//   KXCO_PQ_SECRET_HEX=... KXCO_PQ_KID=...
//   PORT=4001 node server.js
//
// What this demonstrates:
//   - pqResponseSigner is mounted per-route, opt-in. The middleware patches
//     the response object for THIS request only — it does NOT monkeypatch
//     res.send for the entire app. Routes you don't mount it on are unsigned.
//   - The signing headers attach to whatever the handler emits: res.json,
//     res.send, res.end with a string. Streaming bodies are NOT supported
//     (see the streaming caveat below).

import express                  from 'express'
import { createSigner }         from 'kxco-post-quantum-webhook'
import { pqResponseSigner }     from 'kxco-post-quantum-webhook/express'

const app = express()

const signer = createSigner({
  pqSecretKey: Buffer.from(process.env.KXCO_PQ_SECRET_HEX, 'hex'),
  pqKid:       process.env.KXCO_PQ_KID,
})

// Signed route — every response carries X-KXCO-* headers.
app.get('/api/quote',
  pqResponseSigner({ signer, event: 'quote.snapshot' }),
  (_req, res) => {
    res.json({ pair: 'BTC/USD', mid: 67890.12, ts: Date.now() })
  },
)

// Unsigned route — no middleware, response goes out untouched.
app.get('/health', (_req, res) => res.json({ ok: true }))

const port = process.env.PORT || 4001
app.listen(port, () => console.log(`response-signing listening on ${port}`))
