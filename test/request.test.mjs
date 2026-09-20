/**
 * Private requests, tested against the two claims that make them worth having.
 *
 * The first: **every address is recoverable from the master keys alone.** A scheme that needed a
 * note kept per payment would lose money the first time a device did, and the test for that is
 * not "it runs" but "a wallet rebuilt from nothing produces the same addresses".
 *
 * The second: **the key derived alongside each address actually controls it.** An address you
 * cannot spend from is worse than no address, because it accepts money first.
 *
 * Plus the thing that must not be true: that two requests, or two wallets, ever collide.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'

import {
  generateStealthKeys,
  keysFromPrivate,
  deriveRequest,
  deriveRequests,
  requestEphemeralScalar,
  checkAnnouncement,
  publicKeyToAddress,
} from '../dist/index.js'

const SPENDING = Buffer.from('11'.repeat(32), 'hex')
const VIEWING = Buffer.from('22'.repeat(32), 'hex')
const keys = keysFromPrivate(SPENDING, VIEWING)

test('a wallet rebuilt from its keys alone produces the same addresses', () => {
  /* The whole recovery story. Nothing is stored between these two objects: the second knows only
   * what a seed phrase would carry. */
  const rebuilt = keysFromPrivate(SPENDING, VIEWING)
  for (let i = 0; i < 8; i += 1) {
    assert.equal(deriveRequest(rebuilt, i).stealthAddress, deriveRequest(keys, i).stealthAddress)
  }
})

test('the key it hands you controls the address it hands you', () => {
  for (const index of [0, 1, 7, 1000, 4_000_000]) {
    const request = deriveRequest(keys, index)
    const address = publicKeyToAddress(secp256k1.getPublicKey(request.privateKey, false))
    assert.equal(address, request.stealthAddress, `index ${index} produced a key for a different address`)
  }
})

test('no two requests share an address', () => {
  const requests = deriveRequests(keys, 200)
  assert.equal(new Set(requests.map((r) => r.stealthAddress)).size, 200)
  assert.equal(new Set(requests.map((r) => Buffer.from(r.ephemeralPublicKey).toString('hex'))).size, 200)
})

test('two wallets never collide, even at the same index', () => {
  /* If the ephemeral key were derived from the index alone, every wallet in the world would share
   * one series and the first address of each would be the same person's problem. */
  const other = generateStealthKeys()
  for (let i = 0; i < 5; i += 1) {
    assert.notEqual(deriveRequest(keys, i).stealthAddress, deriveRequest(other, i).stealthAddress)
  }
})

test('the ephemeral key is bound to the viewing key, not just the index', () => {
  const a = requestEphemeralScalar(VIEWING, 3)
  const b = requestEphemeralScalar(SPENDING, 3)
  assert.notEqual(a, b, 'a different key produced the same ephemeral scalar')
  assert.notEqual(a, requestEphemeralScalar(VIEWING, 4))
})

test('an index that is not a whole number is refused rather than coerced', () => {
  /* Coercing 1.5 to 1 would hand two different callers the same address and neither would know. */
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => deriveRequest(keys, bad), /index/)
  }
})

test('a request address is still an ordinary stealth address, so it can be announced later', () => {
  /* The construction is unchanged and only the choice of ephemeral key moved. This is what makes
   * announcing a request a choice rather than a migration: any scanner following the
   * specification recognises it from the ephemeral key and the view tag. */
  const request = deriveRequest(keys, 42)
  const match = checkAnnouncement(keys, {
    ephemeralPublicKey: request.ephemeralPublicKey,
    stealthAddress: request.stealthAddress,
    viewTag: request.viewTag,
  })
  assert.ok(match, 'an ordinary scanner did not recognise a request address')
  assert.equal(match.stealthAddress, request.stealthAddress)
})

test('nothing about a request address reveals the wallet it belongs to', () => {
  /* What a payer holds is an address. It is 20 bytes of hash output and it carries no structure a
   * second payer could compare against their own. This asserts the negative directly: no request
   * address contains the meta-address, the spending key or the viewing key in any form. */
  const request = deriveRequest(keys, 5)
  const address = request.stealthAddress.toLowerCase()
  for (const secret of [
    keys.metaAddress.toLowerCase(),
    Buffer.from(keys.spending.publicKey).toString('hex'),
    Buffer.from(keys.viewing.publicKey).toString('hex'),
  ]) {
    assert.ok(!secret.includes(address.slice(2)), 'the address appears inside the wallet material')
    assert.ok(!address.includes(secret.slice(0, 12)), 'wallet material appears inside the address')
  }
})

test('a run recovers from any starting point', () => {
  const all = deriveRequests(keys, 10)
  const tail = deriveRequests(keys, 4, 6)
  for (let i = 0; i < 4; i += 1) {
    assert.equal(tail[i].stealthAddress, all[6 + i].stealthAddress)
    assert.equal(tail[i].index, 6 + i)
  }
})
