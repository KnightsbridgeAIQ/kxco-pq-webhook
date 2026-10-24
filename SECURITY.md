# Security policy

## Supported versions

Only the latest minor on the latest major is supported during the v0.x period.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Do not open a public GitHub issue for security reports.**

Email `john@knightsbridgelaw.com` with subject line: `[kxco-post-quantum-webhook] SECURITY: <one-line summary>`

Acknowledgement within **2 business days**. Triage decision within **5 business days**.
Coordinated disclosure with a **90-day** default window; sooner where the fix ships sooner.

Full policy: <https://kxco.ai/security>

## Safe harbour

If you make a good-faith effort to comply with this policy, we will treat your
research as authorised, and we will not pursue or support legal action against
you. Good faith means: do not access, modify, exfiltrate, or destroy data that
is not yours; use test accounts where possible; do not degrade service for
others; and stop and report as soon as you have established that a
vulnerability exists. This cannot bind third parties, and it does not cover
extortion, data sale, or public disclosure ahead of the window above.

## In-scope

- Bugs in the verifier logic that could cause a signature to be accepted when it should not (e.g. timing-oracle leaks, kid bypass, timestamp window bypass, the `required` policy accepting an unintended state).
- Resource exhaustion / DoS in any framework adapter via crafted requests.
- Body-tampering or signature-mutation that the canonical envelope should detect but the adapter discards (e.g. an adapter that trims trailing whitespace before verification).
- Header normalisation issues that let an attacker spoof a header by sending it in an unexpected case or with array-vs-scalar value.

## Out-of-scope

- Vulnerabilities in `kxco-post-quantum`, `@noble/post-quantum`, or any framework dependency — report those upstream.
- Side-channel attacks on the underlying ML-DSA-87 and ML-DSA-65 primitives (these are out of our control; we use audited noble bindings).
- The known upstream issue documented in [CHANGELOG.md](./CHANGELOG.md) (`signDelivery` calls `pqSign` even when no pqSecretKey is configured) — we work around it; upstream patch tracked separately.
- Misconfiguration where the receiver fails to install raw-body capture (e.g. forgets `express.raw()`) — that's a documentation / setup issue, not a library vulnerability.

## Bug bounty

No formal bounty programme yet. We commit to public acknowledgement on every confirmed fix, and to crediting reporters in the changelog unless they request anonymity. Cash bounties may be offered for critical findings at our discretion during this v0.x period.
