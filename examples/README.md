# Examples

Drop-in webhook receiver templates verifying KXCO hybrid HMAC + ML-DSA-65 signatures across common platforms. Every example is **copy-paste runnable** with two environment variables.

## Reference receivers (Phase 2 — webhook verification)

These use the low-level `kxco-post-quantum` package directly. Stable across all 0.x and 1.x of the wire contract.

| Example                       | Path                              | What it shows |
|-------------------------------|-----------------------------------|---------------|
| Express (Node.js)             | [`./express/`](./express)         | The reference Node.js receiver with raw-body capture |
| Next.js (App Router)          | [`./nextjs/`](./nextjs)           | Route handler with `Request.text()` for raw body |
| AWS Lambda (Node.js)          | [`./aws-lambda/`](./aws-lambda)   | API Gateway proxy event verifier |
| Cloudflare Workers            | [`./cloudflare-worker/`](./cloudflare-worker) | Edge worker verifier |
| Vercel Edge Function          | [`./vercel-edge/`](./vercel-edge) | Edge runtime verifier |
| GitHub Actions step           | [`./github-action/`](./github-action) | Verify webhook payloads relayed into a workflow |

## Advanced patterns

These use the higher-level [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) builders. Require version 0.3.0+ on the package.

| Example | Path | What it shows |
|---|---|---|
| **Rotation receiver** | [`./rotation-receiver/`](./rotation-receiver) | `createVerifier({ pinnedKids: [...] })` accepting both old + new kid during a publisher's key-rotation window. Reads `resolvedKid` on the result to monitor cutover progress. |
| **Response signing + verifiedFetch** | [`./response-signing/`](./response-signing) | Server signing outbound API responses with `pqResponseSigner` (per-route, opt-in); client verifying those responses with `verifiedFetch` (throws `KxcoResponseError` *before* body access on bad signature). Same wire format as webhook signing — receivers verifying your webhooks can verify your API responses with zero code change. |

## Required environment variables

The reference receivers read:

```
KXCO_PUBLIC_KID=648b1e9b142ce625
KXCO_PUBLIC_KEY_HEX=648b1e9b142ce625697fcd4d906f2ff0a7...   # 3904 hex chars
KXCO_WEBHOOK_SECRET=your-per-receiver-shared-secret         # optional, for HMAC
```

The advanced patterns read their own variables — see comments in each example.

Fetch the current platform values once from `https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey` and pin them.

These examples are covered by this repository’s Apache-2.0 license.
