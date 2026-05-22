# Security policy

## Supported versions

Only the latest minor on the latest major is supported during the v0.x period.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Email `hello@kxco.ai` with subject line: `[kxco-post-quantum-webhook] SECURITY: <one-line summary>`

Acknowledgement within **2 business days**. Triage decision within **5 business days**.

## In-scope

- Bugs in the verifier logic that could cause a signature to be accepted when it should not (e.g. timing-oracle leaks, kid bypass, timestamp window bypass, the `required` policy accepting an unintended state).
- Resource exhaustion / DoS in any framework adapter via crafted requests.
- Body-tampering or signature-mutation that the canonical envelope should detect but the adapter discards (e.g. an adapter that trims trailing whitespace before verification).
- Header normalisation issues that let an attacker spoof a header by sending it in an unexpected case or with array-vs-scalar value.

## Out-of-scope

- Vulnerabilities in `kxco-post-quantum`, `@noble/post-quantum`, or any framework dependency — report those upstream.
- Side-channel attacks on the underlying ML-DSA-65 primitive (these are out of our control; we use audited noble bindings).
- The known upstream issue documented in [CHANGELOG.md](./CHANGELOG.md) (`signDelivery` calls `pqSign` even when no pqSecretKey is configured) — we work around it; upstream patch tracked separately.
- Misconfiguration where the receiver fails to install raw-body capture (e.g. forgets `express.raw()`) — that's a documentation / setup issue, not a library vulnerability.

## Bug bounty

No formal bounty programme yet. We commit to public acknowledgement on every confirmed fix, and to crediting reporters in the changelog unless they request anonymity. Cash bounties may be offered for critical findings at our discretion during this v0.x period.
