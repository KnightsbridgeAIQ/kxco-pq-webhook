# KXCO Webhook Contract

The canonical wire format for webhooks signed by `kxco-post-quantum` and verified by `kxco-post-quantum-webhook`. Receivers in any language can re-implement this from the spec without depending on this library.

## Envelope

The signature covers the bytes:

```
${X-KXCO-Timestamp}.${raw request body}
```

`X-KXCO-Timestamp` is **Unix seconds, as a decimal string**. The body is the **exact bytes the sender transmitted** — no re-serialisation, no whitespace normalisation, no encoding conversion. Receivers that buffer and re-stringify JSON will see signatures fail. Always verify against the raw bytes off the wire.

## Headers sent

| Header | Required | Format | Notes |
|---|---|---|---|
| `Content-Type` | yes | `application/json` (typical) | Senders set this; receivers don't verify the value |
| `X-KXCO-Timestamp` | yes | Decimal Unix seconds | Receivers reject when more than `windowSeconds` (default 300) skew from current time |
| `X-KXCO-Signature` | optional* | `sha256=<64-hex-char>` | HMAC-SHA-256 over the envelope, hex-encoded, with mandatory `sha256=` prefix |
| `X-KXCO-PQ-Signature` | optional* | `ml-dsa-65=<6618-hex-char>` | ML-DSA-65 (NIST FIPS 204) signature over the envelope, hex-encoded, with mandatory `ml-dsa-65=` prefix |
| `X-KXCO-PQ-Kid` | yes-if-PQ | 16 hex chars | First 8 bytes of SHA-256(rawPublicKeyBytes). Receivers pin and reject mismatched kid |
| `X-KXCO-Event` | optional | string | Sender-defined event name, e.g. `invoice.paid` |
| `X-KXCO-Delivery` | optional | string | Idempotency id / trace id for the sender's outbound system |

\* At least one of `X-KXCO-Signature` / `X-KXCO-PQ-Signature` must be present. Receivers declare which they require via the `required` policy.

## Receiver policies

The `createVerifier({ required })` option determines what counts as verified:

| `required` | Verdict `ok = true` requires |
|---|---|
| `'hmac'` | Valid HMAC signature only. Receivers that don't yet hold a PQ public key for the sender. |
| `'pq'` | Valid ML-DSA-65 signature only. Receivers that want non-repudiation and don't share a symmetric secret with the sender. |
| `'both'` | Both signatures valid. **Default. Recommended for institutional integrations.** |
| `'either'` | Defense in depth — either signature passing is enough. Useful during a migration window from HMAC-only to dual-signed. |

All policies additionally require:
- Timestamp within `windowSeconds` of receiver's clock (default 300 s = 5 min)
- `X-KXCO-PQ-Kid` matches `pinnedKid` when a PQ public key is configured (`kidOk`)

## Failure reasons

When `ok: false`, the `reason` field carries one of:

| `reason` | Meaning |
|---|---|
| `timestamp_skew` | `X-KXCO-Timestamp` is too far from now, or malformed |
| `kid_mismatch` | `X-KXCO-PQ-Kid` doesn't match the receiver's pinned kid |
| `missing_hmac` | Policy requires HMAC but no `X-KXCO-Signature` header was sent |
| `missing_pq` | Policy requires PQ but no `X-KXCO-PQ-Signature` header was sent |
| `hmac_invalid` | HMAC signature failed verification |
| `pq_invalid` | ML-DSA-65 signature failed verification |

## Re-implementing the receiver in another language

The math is:

```
HMAC verification:
  expected = HMAC_SHA256(secret, bytes(`${timestamp}.${rawBody}`))
  given    = hex_decode(strip_prefix("sha256=", X-KXCO-Signature))
  return constant_time_equal(expected, given)

PQ verification:
  given   = hex_decode(strip_prefix("ml-dsa-65=", X-KXCO-PQ-Signature))
  return ML_DSA_65_VERIFY(pubKey, bytes(`${timestamp}.${rawBody}`), given)

kid:
  return hex(SHA256(pubKey)[:8]) == X-KXCO-PQ-Kid
```

Reference signers: `kxco-post-quantum/src/webhook.js`. Reference verifier: `kxco-verify` on npm, which can verify any envelope this contract emits.

## Wire-format compatibility

This contract is stable across `kxco-post-quantum` `1.x` and `kxco-post-quantum-webhook` `0.x` / `1.x`. Breaking changes (new mandatory headers, signature-prefix changes, envelope format changes) will only land in a major version bump on both sides and are out of scope until at least 2027.

A signature produced by `kxco-post-quantum` `1.0.3` and verified by any future verifier must continue to verify; the contract is forward-compatible by design.

## Symmetric usage — webhook AND API response signing

As of `kxco-post-quantum-webhook@0.2.0` this same wire format is used for **two** patterns:

1. **Outbound webhook signing** — sender produces an HTTP request with `X-KXCO-*` headers; receiver verifies before processing.
2. **Outbound API response signing** — server produces an HTTP response with the same `X-KXCO-*` headers; caller verifies before reading the body.

The envelope (`${X-KXCO-Timestamp}.${raw body}`), header set, kid system, signing primitive, and `required` policy are identical. A receiver that can verify a webhook delivery from a platform can verify the same platform's signed API responses with zero additional code — pass the same `Verifier` instance to both `verifyDelivery()` and `verifiedFetch()`.

The same `X-KXCO-PQ-Kid` resolves the same way in both contexts. Implementors in other languages building against this contract should ship one verifier that handles both, not two.
