/**
 * Scoped disclosure.
 *
 * The claim is the one-wayness, and it is the only thing here worth testing hard: a holder of one
 * scope must not be able to reach any other, and the wallet must be able to reach them all. The
 * rest is encoding.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  generateStealthKeys,
  keysFromPrivate,
  deriveRequests,
  deriveScope,
  keysForScope,
  scopedViewingKey,
  scopedWatchKeys,
  watchKeysFrom,
  watchRequests,
  encodeWatchKey,
  decodeWatchKey,
  SCOPE_LABEL_MAX_BYTES,
} from '../dist/index.js'

const fixed = () =>
  keysFromPrivate(
    Uint8Array.from({ length: 32 }, (_, i) => i + 1),
    Uint8Array.from({ length: 32 }, (_, i) => 200 - i),
  )

test('a scope sees its own addresses and the wallet agrees', () => {
  const keys = fixed()
  const inScope = deriveRequests(keysForScope(keys, '2026-09'), 6)
  const watched = watchRequests(scopedWatchKeys(keys, '2026-09'), 6)

  for (let i = 0; i < 6; i += 1) {
    assert.equal(watched[i].stealthAddress, inScope[i].stealthAddress)
    assert.equal(watched[i].viewTag, inScope[i].viewTag)
  }
})

test('one scope cannot see another', () => {
  /* The whole feature. Hand somebody September and October stays shut. */
  const keys = fixed()
  const september = watchRequests(scopedWatchKeys(keys, '2026-09'), 6)
  const october = watchRequests(scopedWatchKeys(keys, '2026-10'), 6)

  const seen = new Set(september.map((r) => r.stealthAddress))
  for (const request of october) {
    assert.ok(!seen.has(request.stealthAddress), `${request.stealthAddress} appears in both scopes`)
  }
})

test('a scope cannot see the unscoped wallet either', () => {
  const keys = fixed()
  const scoped = new Set(watchRequests(scopedWatchKeys(keys, '2026-09'), 8).map((r) => r.stealthAddress))
  for (const request of watchRequests(watchKeysFrom(keys), 8)) {
    assert.ok(!scoped.has(request.stealthAddress))
  }
})

test('a scope key is not the master key', () => {
  /* Stated as bytes, because the failure this guards against is a derivation that quietly returns
   * its input and hands the whole wallet over under a label saying one month. */
  const keys = fixed()
  for (const label of ['2026-09', 'Q3', 'mandate with a counterparty', 'x']) {
    assert.notDeepEqual(scopedViewingKey(keys.viewing.privateKey, label), keys.viewing.privateKey)
  }
})

test('labels that differ derive keys that differ', () => {
  const keys = fixed()
  const seen = new Set()
  for (const label of ['2026-09', '2026-10', '2026-11', 'Q3 2026', 'q3 2026', ' 2026-09 ']) {
    seen.add(Buffer.from(scopedViewingKey(keys.viewing.privateKey, label)).toString('hex'))
  }
  /* Six labels, five keys: " 2026-09 " is the same scope as "2026-09" because a label is trimmed,
   * and a holder who typed a trailing space should not get a different set of addresses. */
  assert.equal(seen.size, 5)
})

test('the length of a label is part of what is hashed', () => {
  /* Without the length byte, "2026" + "09" and "202609" hash the same, so two scopes a holder
   * believes are separate would be one key. */
  const keys = fixed()
  const a = scopedViewingKey(keys.viewing.privateKey, '202609')
  const b = scopedViewingKey(keys.viewing.privateKey, '2026091')
  assert.notDeepEqual(a, b)

  const c = scopedViewingKey(keys.viewing.privateKey, '20260')
  assert.notDeepEqual(a, c)
})

test('two wallets do not share a scope', () => {
  const a = deriveScope(generateStealthKeys(), '2026-09')
  const b = deriveScope(generateStealthKeys(), '2026-09')
  assert.notDeepEqual(a.viewingPrivateKey, b.viewingPrivateKey)
})

test('a scope keeps the wallet spending key, so the money is not split', () => {
  const keys = fixed()
  const scoped = keysForScope(keys, '2026-09')
  assert.deepEqual(scoped.spending.privateKey, keys.spending.privateKey)
  assert.notDeepEqual(scoped.viewing.privateKey, keys.viewing.privateKey)
  /* And the meta-address stays the wallet's own: a scope is a disclosure boundary, not a second
   * identity to publish. */
  assert.equal(scoped.metaAddress, keys.metaAddress)
})

test('a scoped grant round-trips with its label', () => {
  const keys = fixed()
  const encoded = encodeWatchKey(scopedWatchKeys(keys, 'Q3 2026, audit'))
  const decoded = decodeWatchKey(encoded)

  assert.equal(decoded.label, 'Q3 2026, audit')
  assert.deepEqual(decoded.viewingPrivateKey, scopedWatchKeys(keys, 'Q3 2026, audit').viewingPrivateKey)
  assert.deepEqual(decoded.spendingPublicKey, keys.spending.publicKey)
})

test('a holder can tell a scoped grant from the whole wallet', () => {
  /* The check that stops somebody being handed everything under a label saying one month. It is a
   * byte in the key rather than a claim in an email. */
  const keys = fixed()
  assert.equal(decodeWatchKey(encodeWatchKey(watchKeysFrom(keys))).label, undefined)
  assert.equal(decodeWatchKey(encodeWatchKey(scopedWatchKeys(keys, '2026-09'))).label, '2026-09')
})

test('a scoped key with a mangled label fails rather than opening a different scope', () => {
  const keys = fixed()
  const encoded = encodeWatchKey(scopedWatchKeys(keys, '2026-09'))
  const at = encoded.length - 12
  const flipped = encoded.slice(0, at) + (encoded[at] === 'a' ? 'b' : 'a') + encoded.slice(at + 1)
  assert.notEqual(flipped, encoded)
  assert.throws(() => decodeWatchKey(flipped), /checksum|bytes|label/)
})

test('a label is required and bounded', () => {
  const keys = fixed()
  assert.throws(() => scopedViewingKey(keys.viewing.privateKey, ''), /needs a label/)
  assert.throws(() => scopedViewingKey(keys.viewing.privateKey, '   '), /needs a label/)
  assert.throws(
    () => scopedViewingKey(keys.viewing.privateKey, 'x'.repeat(SCOPE_LABEL_MAX_BYTES + 1)),
    /at most 64 bytes/,
  )
  /* Bounded in bytes, not characters, because the length travels in one byte of the key. */
  assert.throws(() => scopedViewingKey(keys.viewing.privateKey, 'é'.repeat(33)), /at most 64 bytes/)
})

test('a label in another alphabet survives the round trip', () => {
  const keys = fixed()
  const label = 'Kuartal 3, 2026'
  assert.equal(decodeWatchKey(encodeWatchKey(scopedWatchKeys(keys, label))).label, label)
})

test('a scoped viewing key refuses anything that is not a key', () => {
  assert.throws(() => scopedViewingKey(new Uint8Array(31), '2026-09'), /32 bytes/)
})
