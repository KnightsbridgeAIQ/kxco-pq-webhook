# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** A signer and a verifier for HTTP webhook
deliveries. It computes over headers and a raw body the caller supplies, and it
neither sends nor receives the request itself.

**Operate: the request is the caller's.** No socket is opened here. The
framework adapters take an already-received request. So the boundary is exact:
delivery is outside, signature and policy are inside.

**Two signatures over identical bytes, which is the point.** The envelope is
`${timestamp}.${rawBody}`, covered by HMAC-SHA-256 and by ML-DSA-65. HMAC is
symmetric and post-quantum secure as a MAC, and a receiver who shares the
secret can verify with no library at all. ML-DSA-65 adds non-repudiation: a
receiver verifying only the post-quantum signature can prove the delivery came
from the holder of the private key even if the HMAC secret has leaked.

Because both cover exactly the same bytes, a receiver that checks only one
cannot be tricked into treating it as covering a different message.

**Enforce policy, and this is the strongest example in the family.**
`createVerifier({ required })` is an explicit policy control with four settings:
`both` (the default), `pq`, `hmac`, and `either`. A deployment that must not
accept an HMAC-only delivery sets `pq` or `both` and gets a deterministic
refusal, and `result.reason` names which check failed rather than returning a
bare false.

**Retain history: this package solves what `kxco-pq-audit` does not.** The
delivery carries `X-KXCO-PQ-Kid`, and `createVerifier({ pinnedKids: [...] })`
accepts several keys at once, reporting `resolvedKid` for each verification. So
a rotation has a drain window in which in-flight deliveries signed by the
retiring key still verify.

That is per-delivery key selection, and it is the mechanism `kxco-pq-audit`
lacks, where a single `publicKey` is applied to a whole log. Anyone assessing
the family's long-term verification story should read this package as the
worked example and the audit log as the open item.

What is still absent, as everywhere in the stack, is validity: a pinned kid is
a key the verifier chose to trust, and nothing here records whether it was
trusted at the delivery timestamp, or revokes it.

**The wire format is language-neutral and specified.**
`docs/webhook-contract.md` is a canonical spec, so a counterparty can implement
a verifier in another language against the mathematics rather than against this
implementation. For an assessment that is a real property: it makes the
protocol checkable independently of the code.

**Start and update.** No release signing of its own, and **1.2.2 carries no
provenance attestation**, which makes it the exception in this family rather
than the rule.

Every other package here publishes from CI through npm Trusted Publishing and
ships a SLSA provenance statement. This one could not: its trusted publisher
entry was created with the package name, `kxco-post-quantum-webhook`, in the
repository field, while the workflow runs in `kxco-pq-webhook`. The GitHub
repository was renamed and the npm entry was not, so the OIDC claim never
matched and every CI publish failed with a 404 on PUT. 1.2.2 was published from
a workstation on 10 September 2026, and a workstation cannot mint provenance.

The fix is on the npm side and is one action: delete that trusted publisher and
create one naming the repository `kxco-pq-webhook`. Until then this package's
releases are the only ones in the family a buyer cannot verify by attestation,
and that is stated here rather than left to be discovered by checking
`npm view kxco-post-quantum-webhook`.

## Agility

**Inherited.** Primitives, backends and parameter sets belong to
`kxco-post-quantum`. See that package's `AGILITY.md`.

**The addition, and it is a genuine interoperable transition.** `required:
'either'` exists so a fleet can migrate from HMAC-only signing without a
flag day: deploy verifiers that accept either, move signers to dual signing,
then tighten to `both` or `pq`. That is add-then-remove, implemented as a
setting rather than described in a migration guide, and it is the clearest
instance of transition agility in this family.

`pinnedKids` gives the same shape for keys rather than algorithms.

**The limit: the algorithm is named in the header, not negotiated.**
`X-KXCO-PQ-Signature` carries an `ml-dsa-65=` prefix, so a delivery states its
algorithm and a second one could be introduced distinguishably. Nothing
negotiates: a verifier accepts what it implements, and implementing another
parameter set is a release of this package.

## Lifecycle

**Supported versions.** One line moving forward, matching the family.

**Pins.** `kxco-post-quantum` is declared `^1.6.0`, resolved to **1.6.0** in
the tree the evidence bundle was last built from, against a current primitives
release of 1.7.2. Range and resolution agreeing today is a fact about this
tree, not a guarantee. `02-primitives.json` records what was installed.

**Stale organisation references.** Some links in this repository still point at
the `JackKXCO` GitHub organisation, which the repositories moved away from to
`KnightsbridgeAIQ`. GitHub redirects renamed organisations, so the links
currently resolve. They are stale rather than broken, and a link that depends on
a redirect from a name we no longer hold is worth correcting rather than
relying on.

**Ceiling.** No hardware or runtime ceiling. Cost is one ML-DSA-65 verification
per delivery, which is sub-millisecond on the OpenSSL backend and a few
milliseconds in JavaScript; the figures are in the primitives package's
`BENCHMARKS.md`. High delivery rates on the JavaScript backend are the case
worth measuring before committing, and Node 24 or later removes most of it.

**Roadmap.** No external audit of this package, no bug bounty.

## Correcting this document

Every claim here is checkable against `src/` and `docs/webhook-contract.md`. If
one does not match, that is a defect worth reporting through the repository's
issues.
