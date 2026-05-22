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

---

## Key rotation and history (added 2026-05-22)

This section is **additive** to the contract above. A receiver that ignores everything in this section continues to verify deliveries from senders that don't rotate — there is no behaviour change for the single-key, single-kid path.

### The publisher's `.well-known/kxco-pq-pubkey` document

A publisher MAY host their current PQ public key at a well-known URL under their domain. The convention is:

```
https://<publisher-domain>/.well-known/kxco-pq-pubkey
```

The document is JSON. Two shapes are valid, and a receiver SHOULD accept either:

**Single-key (legacy, pre-rotation):**

```json
{
  "algorithm": "ml-dsa-65",
  "kid":       "1234abcd5678ef90",
  "publicKey": "<hex of raw ML-DSA-65 public key bytes>",
  "issuer":    "chain.kxco.ai"
}
```

**Multi-key with rotation history (preferred from this revision onward):**

```json
{
  "version":   "1.1",
  "algorithm": "ml-dsa-65",
  "issuer":    "chain.kxco.ai",
  "kid":       "1234abcd5678ef90",
  "publicKey": "<hex of current key>",
  "keys": [
    {
      "kid":         "1234abcd5678ef90",
      "publicKey":   "<hex>",
      "status":      "active",
      "activeFrom":  "2026-05-22T00:00:00Z",
      "activeUntil": null
    },
    {
      "kid":           "0000aaaa1111bbbb",
      "publicKey":     "<hex>",
      "status":        "retiring",
      "activeFrom":    "2025-11-01T00:00:00Z",
      "activeUntil":   "2026-05-22T00:00:00Z",
      "supersededBy":  "1234abcd5678ef90",
      "manifestUrl":   "https://chain.kxco.ai/.well-known/kxco-pq-rotation/1234abcd5678ef90.json"
    },
    {
      "kid":           "fffe9988aabbccdd",
      "publicKey":     "<hex>",
      "status":        "retired",
      "activeFrom":    "2024-08-15T00:00:00Z",
      "activeUntil":   "2025-11-01T00:00:00Z",
      "retiredAt":     "2025-12-01T00:00:00Z",
      "supersededBy":  "0000aaaa1111bbbb"
    }
  ]
}
```

The top-level `kid` and `publicKey` fields **always** describe the currently-active key — this preserves the legacy shape so receivers that ignore `keys[]` still work. The `keys[]` array is exhaustive for the publisher's history.

### `keys[].status` values

| `status`    | Meaning | Receiver behaviour |
|---|---|---|
| `active`    | The current preferred key. New signatures use this. Exactly one `active` entry at any time. | Accept. |
| `retiring`  | Still valid but new signatures use a newer `active` key. Used during a rotation window where receivers may still hold cached deliveries signed by this key. | Accept; optionally warn / record. |
| `retired`   | Historical record. Signatures with this kid from after `activeUntil` MUST NOT be accepted. Pre-`activeUntil` signatures verifying against this key are still valid in principle but most receivers will not retain them. | Reject by default. |
| `revoked`   | Reserved for future versions. Emergency revocation flow is **out of scope for this revision** — see "Out of scope" below. | Reject. |

### Rotation manifest

A rotation manifest is a JSON document **signed by the previous-active key** that attests to the new key. It bridges the trust chain across a rotation: a receiver that already trusts `previousKid` can verify the manifest's signature and learn the new `kid`'s public key without a second out-of-band exchange.

```json
{
  "version":       "1.0",
  "manifestType":  "rotation",
  "issuer":        "chain.kxco.ai",
  "previousKid":   "0000aaaa1111bbbb",
  "newKid":        "1234abcd5678ef90",
  "newPublicKey":  "<hex of new ML-DSA-65 public key>",
  "effectiveAt":   "2026-05-22T00:00:00Z",
  "signature": {
    "alg":   "ml-dsa-65",
    "kid":   "0000aaaa1111bbbb",
    "value": "<hex of ML-DSA-65 signature over canonical manifest bytes>"
  }
}
```

**Canonicalization for signing (deterministic across languages):**

1. Take the manifest document with `signature.value` set to the empty string `""` (all other `signature.*` fields populated).
2. Serialize as JSON with **RFC 8785 JSON Canonicalization Scheme (JCS)** — UTF-8, no whitespace, object keys in lexicographic order, numbers in shortest round-trippable form, strings minimally escaped.
3. The resulting UTF-8 byte sequence is the message signed by ML-DSA-65 with `previousKid`'s private key.

Reference implementation produces this in `kxco-post-quantum-webhook` ≥ `0.3.0`. Receivers re-implementing in another language MUST follow RFC 8785; ad-hoc serialization will not produce the same bytes and signatures will not verify.

### Verifier semantics for multiple pinned kids

Receivers MAY pin a set of acceptable kids during a rotation window:

```js
createVerifier({
  pinnedKids: [
    { kid: '1234abcd5678ef90', publicKey: '<hex of new key>' },
    { kid: '0000aaaa1111bbbb', publicKey: '<hex of old key>' }
  ],
  required: 'pq'
})
```

The matching pubkey is selected from the keystore by `X-KXCO-PQ-Kid`. If the kid doesn't match any pinned entry, the verifier returns `ok: false` with `reason: 'kid_mismatch'` (same reason code as the single-kid case — a kid that isn't in the pin set is, semantically, a mismatch).

Order of `pinnedKids` is not security-significant but a verifier MAY iterate in the order given for performance — typically the active key is listed first so the common path is the first comparison.

The singular `pinnedKid` + `pqPublicKey` form (pre-0.3.0) continues to work unchanged. Receivers SHOULD use the singular form when they don't yet hold history; they SHOULD migrate to `pinnedKids[]` before the publisher rotates.

### Out of scope for this revision

The following are deliberately deferred so the minimum-viable rotation flow can be exercised in production first:

- **Verifier auto-refresh of the well-known endpoint.** Today, receivers update `pinnedKids[]` manually (config change + redeploy). Auto-refresh re-introduces the publisher's TLS as a trust anchor and needs careful mitigation; deferred until manual rotation has been exercised end-to-end.
- **Revocation / compromise manifests.** A rotation is a scheduled event signed by the *outgoing* key. A revocation under compromise — where the outgoing key may itself be untrusted — needs a separate trust path (out-of-band emergency key, signed announcement on a second channel, etc.). Deferred.
- **Receiver identity attestation (mutual signing).** The current contract describes one-way identity (publisher signs to receiver). Two-way mutual identity is a different protocol; not addressed here.

### Forward compatibility

A receiver that implements this revision continues to verify deliveries from publishers that haven't rotated. A receiver that implements only the pre-rotation contract continues to verify deliveries from publishers that have rotated *if and only if* the receiver's `pinnedKid` is the publisher's currently-active kid. Receivers SHOULD upgrade to `pinnedKids[]` before consuming from publishers that intend to rotate.
