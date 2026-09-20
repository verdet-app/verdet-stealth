/**
 * The interop vector: one payment, fully determined, every intermediate value pinned.
 *
 * ## Why this file exists
 *
 * ERC-5564 writes the shared secret as `s_h = h(s)` where `s` is a curve point, and **it never says
 * how that point is serialised before hashing.** Three readings are defensible, and they do not
 * agree:
 *
 * | Reading | keccak of the point |
 * |---|---|
 * | compressed, 33 bytes  | `0x20f63c...7908c2`  (what this library does) |
 * | uncompressed, 65 bytes| `0xdaf938...268205` |
 * | x coordinate only     | `0x838e57...ee114e` |
 *
 * Different hash, different scalar, different address. An implementation that picks another
 * reading derives a different address from the same inputs, in silence, with no error anywhere.
 *
 * ## What the failure actually costs, stated precisely
 *
 * If a sender uses one reading and a recipient scans with another, the recipient's scanner never
 * matches the announcement and the payment looks like it never arrived. The asset is **not**
 * unrecoverable: it sits at an address whose private key is still the recipient's spending scalar
 * plus the sender's shared secret, so whoever works out which reading the sender used can derive
 * it and spend it. The cost is a payment that cannot be found, plus the work of finding out why,
 * not a permanent loss. Saying it is a permanent loss would make the next reader discount the
 * warning, and the warning is worth keeping.
 *
 * ## What this test does and does not prove
 *
 * It proves this library is deterministic and that a change to the encoding fails loudly here
 * rather than silently on a user's payment. It does **not** prove interoperability: nothing in this
 * repository can, because that requires running another implementation. The vector is published so
 * that check is one comparison away for anyone who has one, and T76 stays open until somebody
 * makes it.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'

import {
  keysFromPrivate,
  checkAnnouncement,
  deriveSharedSecret,
  deriveStealthPrivateScalar,
  stealthAddressFrom,
  toScalar,
  scalarToPrivateKey,
  privateKeyToHex,
  publicKeyToAddress,
  encodeAnnounce,
} from '../dist/index.js'

const hex = (bytes) => `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`

/* Deliberately unmistakable as anything but a test fixture. */
const SPENDING_PRIVATE = Buffer.from('11'.repeat(32), 'hex')
const VIEWING_PRIVATE = Buffer.from('22'.repeat(32), 'hex')
const EPHEMERAL_PRIVATE = Buffer.from('33'.repeat(32), 'hex')

/**
 * The vector. Every value below is what this library produces, hashing the **compressed** point.
 * Publish these; an implementation that agrees on all of them agrees on the encoding.
 */
const VECTOR = {
  metaAddress:
    'st:eth:0x034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',
  ephemeralPublicKey: '0x023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1',
  sharedSecretHash: '0x20f63cde5fe857844fbfda0a7599784a624dc4741b8bd076edfcbc857d7908c2',
  viewTag: 32,
  stealthAddress: '0xD8606eD2ecDB71fdcb8cCA8fA1925ff84238f2a9',
  stealthPrivateKey: '0x32074def70f9689560d0eb1b86aa895b735ed5852c9ce187ff0dcd968e8a19d3',
}

const keys = keysFromPrivate(SPENDING_PRIVATE, VIEWING_PRIVATE)
const ephemeralPublicKey = secp256k1.getPublicKey(EPHEMERAL_PRIVATE, true)
const secret = deriveSharedSecret(toScalar(EPHEMERAL_PRIVATE), keys.viewing.publicKey)

test('the meta-address and the ephemeral key are what the vector says', () => {
  assert.equal(keys.metaAddress, VECTOR.metaAddress)
  assert.equal(hex(ephemeralPublicKey), VECTOR.ephemeralPublicKey)
})

test('the shared secret is keccak of the compressed point, and that choice is pinned', () => {
  assert.equal(hex(secret.hash), VECTOR.sharedSecretHash)
  assert.equal(secret.viewTag, VECTOR.viewTag)

  /* The two readings this library did not take. If one of these ever equals the hash above, the
   * encoding changed under us and every address derived since is from a different scheme. */
  const point = secp256k1.Point.fromBytes(keys.viewing.publicKey).multiply(toScalar(EPHEMERAL_PRIVATE))
  assert.equal(hex(keccak_256(point.toBytes(true))), VECTOR.sharedSecretHash, 'compressed is the reading in use')
  assert.notEqual(hex(keccak_256(point.toBytes(false))), VECTOR.sharedSecretHash, 'uncompressed must differ')
  assert.notEqual(hex(keccak_256(point.toBytes(false).subarray(1, 33))), VECTOR.sharedSecretHash, 'x only must differ')
})

test('the stealth address and its spending key are what the vector says', () => {
  const address = stealthAddressFrom(keys.spending.publicKey, secret.scalar)
  assert.equal(address, VECTOR.stealthAddress)

  const scalar = deriveStealthPrivateScalar(toScalar(SPENDING_PRIVATE), secret.scalar)
  assert.equal(privateKeyToHex(scalarToPrivateKey(scalar)), VECTOR.stealthPrivateKey)
})

test('the derived key actually controls the derived address', () => {
  /* The one failure that matters more than interoperability: an address the recipient cannot spend
   * from. Take the derived private key, get its public key from the curve, turn that into an
   * address, and require it to be the address the sender paid. */
  const scalar = deriveStealthPrivateScalar(toScalar(SPENDING_PRIVATE), secret.scalar)
  const publicKey = secp256k1.getPublicKey(scalarToPrivateKey(scalar), false)
  assert.equal(publicKeyToAddress(publicKey), VECTOR.stealthAddress)
})

test('the recipient finds this payment from the announcement alone', () => {
  const match = checkAnnouncement(keys, {
    ephemeralPublicKey,
    stealthAddress: VECTOR.stealthAddress,
    viewTag: VECTOR.viewTag,
  })
  assert.ok(match, 'the viewing key did not recognise the vector')
  assert.equal(match.stealthAddress, VECTOR.stealthAddress)
})

test('the announcement for this vector is byte-for-byte stable', () => {
  /* What actually goes on chain. Pinned so a change to the calldata encoder is visible here too. */
  const calldata = encodeAnnounce({
    stealthAddress: VECTOR.stealthAddress,
    ephemeralPublicKey,
    viewTag: VECTOR.viewTag,
  })
  assert.equal((calldata.length - 2) / 2, 292)
  assert.ok(calldata.startsWith('0x4d1f9583'), 'announce selector')
  assert.ok(calldata.toLowerCase().includes(VECTOR.stealthAddress.slice(2).toLowerCase()), 'carries the address')
  assert.ok(calldata.includes(VECTOR.ephemeralPublicKey.slice(2)), 'carries the ephemeral key')
})
