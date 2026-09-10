# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms and keys move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

Webhook signing and verification with two signatures over identical bytes:
HMAC-SHA-256 and ML-DSA-65, both covering `${timestamp}.${rawBody}`.

**Two signatures, two different guarantees.** HMAC is symmetric and
post-quantum secure as a MAC, so a receiver who shares the secret verifies with
no library at all. ML-DSA-65 adds non-repudiation: a receiver verifying only the
post-quantum signature can prove the delivery came from the holder of the
private key **even if the HMAC secret has leaked**. Shared-secret webhook
signing cannot make that statement, because either party could have produced the
signature.

**Both cover exactly the same bytes**, so a receiver checking only one cannot be
tricked into treating it as covering a different message. That is the failure
that makes dual-signature schemes dangerous when they are built casually, and it
is closed by construction here.

**The policy is explicit and enforced.** `createVerifier({ required })` takes
`both` (the default), `pq`, `hmac` or `either`, and `result.reason` names which
check failed — `timestamp_skew`, `kid_mismatch`, `missing_pq`, `pq_invalid` and
so on — rather than returning a bare false. A deployment that must not accept an
HMAC-only delivery says so in one word and gets a deterministic refusal.

**Key rotation has a drain window, and this is the family's reference
implementation of it.** The delivery carries `X-KXCO-PQ-Kid`, `pinnedKids`
accepts several keys at once, and `resolvedKid` reports which one verified. In
flight deliveries signed by the retiring key keep verifying while the new key
takes over, so a rotation is a window rather than a flag day.

**Migration off HMAC-only needs no flag day either.** `required: 'either'`
exists for exactly that: deploy verifiers that accept either, move signers to
dual signing, then tighten to `both` or `pq`. Add-then-remove, implemented as a
setting rather than described in a guide.

**The wire format is a specification.** `docs/webhook-contract.md` is
language-neutral, so a counterparty can implement a verifier in Rust, Go or
Python against the canonical mathematics rather than against this
implementation. A protocol that can be re-implemented independently is one a
counterparty can adopt without adopting a dependency on us.

**The payload is detached.** The claims carry `body_sha256`, not the body.
Duplicating the body into a header would double the bytes on the wire and give a
lazy verifier two copies to disagree about; the digest binds the signature to
exactly one body and to nothing else.

**No bundled cryptography.** `kxco-post-quantum` is a peer dependency rather
than a direct one, so this package never pulls a second copy of the primitives
into a tree that already has one.

## Scope

This package computes over headers and a raw body the caller supplies; delivery
is the caller's HTTP stack. That keeps the assessed surface exactly the
signature, the policy and the key selection.

A pinned kid is a key the verifier chose to trust. Resolving whether that key is
still trusted is
[`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network)'s job, against
a registry backed by
[`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain)'s `revokeKid()`,
and the kid on every delivery is the identifier it takes. Verification here stays
synchronous and offline; live key status is available where a caller wants it.

## Agility

**Inherited.** Parameter sets and the two interchangeable backends belong to
`kxco-post-quantum`.

**The algorithm is named on the wire.** `X-KXCO-PQ-Signature` carries an
`ml-dsa-65=` prefix, so a delivery states its algorithm and a second one is
introducible distinguishably. Alongside `required: 'either'` and `pinnedKids`,
this package has a working transition mechanism for all three of the things that
change: the algorithm, the key and the policy.

## Running it

**Release integrity.** Releases built in CI carry a SLSA provenance attestation
tying the tarball to the commit and workflow that built it, alongside a
CycloneDX SBOM as a GitHub Release asset at a permanent unauthenticated URL.
Seventeen of the twenty-one published versions carry an attestation, including
an unbroken run from 1.1.2 through 1.2.1; the exceptions are 1.0.6, 1.0.7, 1.1.0
and 1.2.2, so verify the version you install with
`npm audit signatures`.

1.2.2 was published outside CI because this package's npm trusted publisher
names the package rather than the repository, which is `kxco-pq-webhook`.
Correcting that entry returns publishing to CI and the attestation with it.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** One ML-DSA-65 verification per delivery: sub-millisecond on the
OpenSSL backend, a few milliseconds in JavaScript, with the figures in the
primitives package's `BENCHMARKS.md`. Node 24 and later run the OpenSSL backend.

**Framework adapters** for the common Node servers ship with the package, so
wiring is a few lines rather than a middleware exercise.

## Correcting this document

Every claim here is checkable against `src/` and `docs/webhook-contract.md`. If
one does not match, that is a defect worth reporting through the repository's
issues.
