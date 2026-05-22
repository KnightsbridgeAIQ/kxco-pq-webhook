// verifiedFetch tests — wraps fetch, runs the verifier, throws before body
// access on bad signature.

import { test }   from 'node:test'
import assert     from 'node:assert/strict'
import crypto     from 'node:crypto'
import { mlDsa, fingerprint } from 'kxco-post-quantum'

import { createSigner, createVerifier } from '../src/builders.js'
import { signResponse }                  from '../src/response-core.js'
import { verifiedFetch, KxcoResponseError } from '../src/verified-fetch.js'

const KP   = mlDsa.keypairFromMaster(Buffer.from('00'.repeat(32), 'hex'), 'kxco-webhook-vfetch-test-v1')
const KID  = fingerprint(KP.publicKey)
const HMAC = crypto.randomBytes(32)

function signedResponse(bodyText, signer) {
  const headers = signResponse(signer, bodyText)
  return new Response(bodyText, { status: 200, headers })
}

test('verifiedFetch: returns { response, kxcoResponse } on valid sig', async () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })

  const fakeFetch = async () => signedResponse('{"ok":true}', signer)
  const { response, kxcoResponse } = await verifiedFetch('https://example.com/api/health', {}, { verifier, fetchImpl: fakeFetch })

  assert.equal(kxcoResponse.ok, true)
  assert.equal(response.status, 200)
  // Body still readable on the returned response
  assert.equal(await response.text(), '{"ok":true}')
})

test('verifiedFetch: throws KxcoResponseError on invalid sig (strict default)', async () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })

  const fakeFetch = async () => {
    // Sign the wrong body, then return a different body — verifier will reject
    const headers = signResponse(signer, '{"original":true}')
    return new Response('{"tampered":true}', { status: 200, headers })
  }

  try {
    await verifiedFetch('https://example.com/api/health', {}, { verifier, fetchImpl: fakeFetch })
    assert.fail('expected KxcoResponseError')
  } catch (err) {
    assert.ok(err instanceof KxcoResponseError)
    assert.equal(err.code, 'kxco_response_unverified')
    assert.equal(err.kxcoResponse.ok, false)
    assert.equal(err.kxcoResponse.reason, 'hmac_invalid')
    // The unverified body is still accessible via err.response IF the caller really wants it
    assert.equal(await err.response.text(), '{"tampered":true}')
  }
})

test('verifiedFetch: permissive mode returns the result instead of throwing', async () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })

  const fakeFetch = async () => {
    const headers = signResponse(signer, '{"original":true}')
    return new Response('{"tampered":true}', { status: 200, headers })
  }

  const { response, kxcoResponse } = await verifiedFetch(
    'https://example.com/api/health', {},
    { verifier, fetchImpl: fakeFetch, permissive: true },
  )
  assert.equal(kxcoResponse.ok, false)
  assert.equal(response.status, 200)
})

test('verifiedFetch: rejects missing verifier', async () => {
  await assert.rejects(
    verifiedFetch('https://x/', {}, {}),
    /verifier is required/,
  )
})

test('verifiedFetch: rejects when no fetch is available', async () => {
  const saved = globalThis.fetch
  delete globalThis.fetch
  try {
    await assert.rejects(
      verifiedFetch('https://x/', {}, { verifier: createVerifier({ hmacSecret: HMAC, required: 'hmac' }) }),
      /no fetch implementation/,
    )
  } finally {
    globalThis.fetch = saved
  }
})

test('verifiedFetch: response.json() works after verification (body buffered + replayed)', async () => {
  const signer   = createSigner({ hmacSecret: HMAC, pqSecretKey: KP.secretKey, pqKid: KID })
  const verifier = createVerifier({ hmacSecret: HMAC, pqPublicKey: KP.publicKey, pinnedKid: KID, required: 'both' })

  const fakeFetch = async () => signedResponse('{"data":[1,2,3]}', signer)
  const { response } = await verifiedFetch('https://example.com/api/data', {}, { verifier, fetchImpl: fakeFetch })
  const parsed = await response.json()
  assert.deepEqual(parsed, { data: [1, 2, 3] })
})
