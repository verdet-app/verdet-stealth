/**
 * Watch-only keys.
 *
 * The claim under test is a pair: a watcher sees exactly what the wallet sees, and holds nothing
 * that could move any of it. Both halves are checked, because either one failing alone would be
 * worse than not shipping the feature.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'

import {
  generateStealthKeys,
  keysFromPrivate,
  deriveRequests,
  watchKeysFrom,
  encodeWatchKey,
  decodeWatchKey,
  watchRequest,
  watchRequests,
} from '../dist/index.js'

const fixed = () =>
  keysFromPrivate(
    Uint8Array.from({ length: 32 }, (_, i) => i + 1),
    Uint8Array.from({ length: 32 }, (_, i) => 200 - i),
  )

test('a watcher derives the same addresses as the wallet', () => {
  const keys = fixed()
  const watched = watchRequests(watchKeysFrom(keys), 8)
  const owned = deriveRequests(keys, 8)

  assert.equal(watched.length, 8)
  for (let i = 0; i < 8; i += 1) {
    assert.equal(watched[i].stealthAddress, owned[i].stealthAddress)
    assert.equal(watched[i].viewTag, owned[i].viewTag)
    assert.deepEqual(watched[i].ephemeralPublicKey, owned[i].ephemeralPublicKey)
  }
})

test('a watch key holds nothing that spends', () => {
  const keys = fixed()
  const watch = decodeWatchKey(encodeWatchKey(watchKeysFrom(keys)))

  /* The only private scalar in the grant is the viewing one, and the address is a tweak of the
   * spending key. Signing would need the spending private key, which is not in these bytes. */
  assert.deepEqual(watch.viewingPrivateKey, keys.viewing.privateKey)
  assert.deepEqual(watch.spendingPublicKey, keys.spending.publicKey)
  assert.equal(Object.keys(watch).length, 2)
  assert.ok(!Object.values(watch).some((v) => v.length === 32 && equalBytes(v, keys.spending.privateKey)))
})

test('the spending private key is not recoverable from the grant', () => {
  const keys = fixed()
  const watch = watchKeysFrom(keys)
  /* Stated as the arithmetic rather than as a promise: the public key is a point, the private key
   * is its logarithm, and the grant carries only the point. */
  assert.deepEqual(secp256k1.getPublicKey(keys.spending.privateKey, true), watch.spendingPublicKey)
  assert.notDeepEqual(watch.viewingPrivateKey, keys.spending.privateKey)
})

test('a watch key round-trips through its string form', () => {
  for (let i = 0; i < 5; i += 1) {
    const keys = generateStealthKeys()
    const encoded = encodeWatchKey(watchKeysFrom(keys))
    assert.ok(encoded.startsWith('verdet:watch:0x'))
    const decoded = decodeWatchKey(encoded)
    assert.deepEqual(decoded.viewingPrivateKey, keys.viewing.privateKey)
    assert.deepEqual(decoded.spendingPublicKey, keys.spending.publicKey)
  }
})

test('a watch key survives surrounding whitespace and mixed case hex', () => {
  const encoded = encodeWatchKey(watchKeysFrom(fixed()))
  const upper = 'verdet:watch:0x' + encoded.slice('verdet:watch:0x'.length).toUpperCase()
  assert.deepEqual(decodeWatchKey(`  ${upper}\n`), decodeWatchKey(encoded))
})

test('one wrong character is refused rather than derived from', () => {
  /* The failure this prevents: a mistyped key derives valid addresses belonging to nobody, the
   * watcher sees an empty wallet, and reads that as "nothing arrived". */
  const encoded = encodeWatchKey(watchKeysFrom(fixed()))
  const at = encoded.length - 20
  const flipped = encoded.slice(0, at) + (encoded[at] === 'a' ? 'b' : 'a') + encoded.slice(at + 1)
  assert.notEqual(flipped, encoded)
  assert.throws(() => decodeWatchKey(flipped), /checksum/)
})

test('a truncated watch key is refused', () => {
  const encoded = encodeWatchKey(watchKeysFrom(fixed()))
  assert.throws(() => decodeWatchKey(encoded.slice(0, encoded.length - 2)), /70 bytes/)
})

test('a watch key of an unknown version is refused', () => {
  /* Version 2 is scoped and is read, so the unknown one to test against is 3. An earlier version
   * of this test used 2 and started passing for the wrong reason the day scopes shipped. */
  const encoded = encodeWatchKey(watchKeysFrom(fixed()))
  const body = encoded.slice('verdet:watch:0x'.length)
  assert.throws(() => decodeWatchKey(`verdet:watch:0x03${body.slice(2)}`), /version/)
  assert.throws(() => decodeWatchKey(`verdet:watch:0x00${body.slice(2)}`), /version/)
})

test('a meta-address is not a watch key and vice versa', () => {
  const keys = fixed()
  assert.throws(() => decodeWatchKey(keys.metaAddress), /starts with/)
  assert.ok(!encodeWatchKey(watchKeysFrom(keys)).startsWith('st:eth:'))
})

test('watching runs past the counter the same way the wallet does', () => {
  const watch = watchKeysFrom(fixed())
  const [tenth] = watchRequests(watch, 1, 10)
  assert.equal(tenth.stealthAddress, watchRequest(watch, 10).stealthAddress)
  assert.notEqual(tenth.stealthAddress, watchRequest(watch, 11).stealthAddress)
})

test('two wallets do not watch each other', () => {
  const a = watchRequests(watchKeysFrom(generateStealthKeys()), 4)
  const b = watchRequests(watchKeysFrom(generateStealthKeys()), 4)
  for (let i = 0; i < 4; i += 1) assert.notEqual(a[i].stealthAddress, b[i].stealthAddress)
})

function equalBytes(a, b) {
  return a.length === b.length && a.every((byte, i) => byte === b[i])
}
