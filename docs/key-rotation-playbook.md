# Key Rotation Playbook

How to rotate an ML-DSA-65 signing key under the [webhook contract](./webhook-contract.md) without dropping deliveries or breaking receivers.

This playbook covers two scenarios. They share the same artefact set but differ on timing and trust:

| Scenario | Trigger | SLA on rollout | Trust path |
|---|---|---|---|
| **Routine rotation** | Scheduled (e.g. annual) | Days–weeks | Manifest signed by the outgoing key |
| **Compromise rotation** | Incident response | Hours | Out-of-band (see §3) — outgoing key may itself be untrusted |

Phase 5 of this package ships full support for **routine rotation**. Compromise rotation requires an emergency-channel signal that is *not* fully spec'd in this revision; §3 describes the operational pattern but the trust path is out-of-scope until the spec adds revocation manifests.

---

## 1. Prerequisites

Before you rotate, confirm:

- [ ] Every receiver you publish to is on `kxco-post-quantum-webhook@0.3.0` or later, OR they use a verifier in another language that supports the multi-kid `.well-known/kxco-pq-pubkey` shape. Receivers on the singular-kid contract can still receive, but they'll need a config update on rotation day.
- [ ] You have the **master + info label** that derived the current (outgoing) keypair, OR you have its raw 4032-byte secret-key hex on disk. The CLI accepts either: `--old-secret @./secret-key.hex` or you can re-derive via `kxco-pq keygen` first.
- [ ] You have a **fresh 32-byte master** for the new key. Generate it with a CSPRNG (`openssl rand -hex 32` is fine) and store it in your secrets manager BEFORE you run rotation. **Losing this master means you cannot re-derive the new key.**
- [ ] You have publish access to the well-known URL `https://<your-domain>/.well-known/kxco-pq-pubkey`.
- [ ] You have a way to ping all your downstream receivers ahead of the cutover (Slack, email, status page — whichever they subscribe to).

---

## 2. Routine rotation — step by step

### 2.1 Generate the new keypair + signed manifest

On a hardened workstation (not a CI runner — these files are signing material):

```bash
npx kxco-pq rotate \
  --old-secret @./current-keys/secret-key.hex \
  --old-kid    <current-kid-from-kid.txt> \
  --new-master '<64 hex chars of fresh master>' \
  --info       'my-publisher-v2' \
  --issuer     'publisher.example.com' \
  --out-dir    ./rotated
```

You now have five files in `./rotated`:

- `secret-key.hex` — new key's secret material. **Move this into your secrets manager now**, before you do anything else.
- `public-key.hex`, `kid.txt` — new key's public + kid.
- `manifest.json` — signed by the OLD kid. Anyone who already trusts the old kid can verify this and learn the new kid.
- `well-known.json` — the updated multi-kid `.well-known` document.

### 2.2 Pre-flight: verify the manifest yourself

Before publishing anything, sanity-check that the manifest verifies with the *old* public key:

```bash
node -e "
import('./node_modules/kxco-pq-cli/src/manifest.js').then(({verifyRotationManifest}) => {
  const m = JSON.parse(require('fs').readFileSync('./rotated/manifest.json'))
  const oldPub = require('fs').readFileSync('./current-keys/public-key.hex', 'utf-8').trim()
  console.log(verifyRotationManifest(m, oldPub))
})
"
# Expected: { ok: true }
```

If this fails, **do not proceed**. Re-derive the old keypair from master + info and check that the public key file you're verifying against is actually the right one.

### 2.3 Notify receivers (ahead of cutover)

Send to each receiver an integration message that contains exactly:

```
New PQ signing key for <issuer>:
  kid:        <new-kid>
  pubkey:     <new-publicKey-hex>
  effective:  <new-effectiveAt>
  manifest:   https://<issuer>/.well-known/kxco-pq-rotation/<new-kid>.json
  well-known: https://<issuer>/.well-known/kxco-pq-pubkey

Action required before <cutover-date>:

  // Update your verifier from:
  createVerifier({ pinnedKid: '<old-kid>', pqPublicKey: '<old-pub>' })

  // ...to:
  createVerifier({
    pinnedKids: [
      { kid: '<new-kid>', publicKey: '<new-pub>' },
      { kid: '<old-kid>', publicKey: '<old-pub>' }
    ]
  })
```

The receiver is now ready to accept deliveries signed by either key. They don't *have* to do this before cutover — the manifest lets them learn the new key on demand — but doing it proactively avoids any failed deliveries during the cutover window.

### 2.4 Publish the well-known + manifest

```bash
# Atomically swap the well-known doc
scp ./rotated/well-known.json publisher:/var/www/.well-known/kxco-pq-pubkey.tmp
ssh publisher 'mv /var/www/.well-known/kxco-pq-pubkey.tmp /var/www/.well-known/kxco-pq-pubkey'

# Publish the rotation manifest
NEW_KID=$(cat ./rotated/kid.txt)
scp ./rotated/manifest.json publisher:/var/www/.well-known/kxco-pq-rotation/${NEW_KID}.json
```

Cache headers: serve the well-known with `Cache-Control: max-age=300` or shorter. Serve manifests with a long cache (`max-age=31536000, immutable`) — they're content-addressed by kid.

### 2.5 Cut over the signer

Roll out the new secret key to your signing infrastructure (whatever holds the signing identity — KMS, HSM, env vars, secrets manager). After the rollout, new outbound deliveries are signed with the new kid; receivers that updated their `pinnedKids[]` accept the new kid; receivers that didn't can still verify by fetching the manifest and learning the new key from the trust bridge.

### 2.6 Drain window

Set a drain duration based on how long deliveries can sit unprocessed in receiver queues. **Default: 14 days.** During the drain:

- New signatures use the new kid.
- Old in-flight deliveries (signed by the old kid before cutover, still being retried) are still valid.
- `keys[0].status` in well-known is `active` (new); `keys[1].status` is `retiring` (old).

### 2.7 Retire the old kid

After the drain window:

1. Edit `well-known.json`: change `keys[1].status` from `retiring` to `retired`, add `retiredAt: <now>`.
2. Re-publish.
3. **Securely discard the old secret key.** No more deliveries should be signed with it. Once retired, signatures with that kid that arrive after `activeUntil` MUST be rejected by spec-compliant receivers.

Receivers can now remove the old entry from `pinnedKids[]` at their leisure.

### 2.8 Update your docs

- Refresh any "current PQ key" badges or docs.
- If you publish to `verify.kxco.ai`, your entry will pick up the new kid automatically on the next refresh.

---

## 3. Compromise rotation (interim playbook)

If the outgoing key is *compromised* — adversary has the secret material — the spec-defined trust bridge (manifest signed by outgoing key) is **untrustworthy**. Until the next spec revision adds revocation manifests, treat compromise rotation as a side-channel event:

### 3.1 Operational pattern (today)

1. **Generate the new key** under §2.1 above (the manifest will still sign, but it is no longer the trust path — assume the attacker can forge one too).
2. **Announce the new kid over an out-of-band channel** the attacker doesn't control: signed status-page post, signed email from a separate signing identity, in-person handoff, your existing PKI'd customer portal. The receiver MUST learn the new pubkey through this channel, not through the manifest.
3. **Publish a `revocation` notice** in the well-known doc: change `keys[1].status` to `revoked` with a `revokedAt` timestamp.
4. **Burn the compromised secret.** If you suspect the attacker has been signing forgeries, audit your outbound delivery logs and reach out to receivers about deliveries during the suspected window.

### 3.2 Why this isn't fully spec'd yet

A revocation manifest signed by the *new* key creates a chicken-and-egg problem: receivers don't trust the new key yet, so they can't trust the revocation. The clean solutions are either:

- **A standing emergency key** held offline that only signs revocations.
- **A second signing channel** (DNS TXT records, transparency log, etc.) that's independently rooted.

Both are spec-able but both increase setup cost for every publisher. They are deferred to a future webhook-contract revision pending real-world experience with routine rotation. For now: out-of-band announcement + side-channel verification is the operational answer.

---

## 4. Checklist (copy this into your runbook)

**Routine rotation:**

- [ ] Master for new key generated via CSPRNG, stored in secrets manager
- [ ] `kxco-pq rotate` run on hardened workstation; outputs verified locally
- [ ] Receivers notified ≥7 days ahead with new kid + pubkey + manifest URL
- [ ] `well-known.json` published; serves with `Cache-Control: max-age=300`
- [ ] `manifest.json` published at `/.well-known/kxco-pq-rotation/<new-kid>.json`
- [ ] Signer rolled out with new secret
- [ ] Drain window scheduled (default 14 d) on calendar
- [ ] On drain expiry: `keys[1].status` → `retired`; old secret destroyed
- [ ] Docs / badges / `verify.kxco.ai` entry refreshed

**Compromise rotation (interim):**

- [ ] Out-of-band channel chosen and used to announce new kid + pubkey
- [ ] `keys[1].status` → `revoked` in well-known with `revokedAt`
- [ ] Suspected forgery window audited in outbound delivery logs
- [ ] Affected receivers contacted individually
- [ ] Compromised secret destroyed

---

## 5. Tooling reference

- **CLI:** [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) — `keygen`, `fingerprint`, `rotate`
- **Receiver library:** [`kxco-post-quantum-webhook@^0.3.0`](https://www.npmjs.com/package/kxco-post-quantum-webhook) — `createVerifier({ pinnedKids: [...] })`
- **Contract spec:** [`docs/webhook-contract.md`](./webhook-contract.md) §"Key rotation and history"
- **Verifier (browser):** [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) — supports the same multi-kid contract
