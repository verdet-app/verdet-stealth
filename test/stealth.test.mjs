/**
 * Correctness checks for the stealth derivation.
 *
 * The one that matters most is spendability: a derived stealth address is worthless if the private
 * key the recipient computes does not control it. That check is not a formality, it is the whole
 * product.
 */

import test from 'node:test'
import assert from 'node:assert/strict'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { hexToBytes } from '@noble/curves/utils.js'

import {
  createStealthPayment,
  checkAnnouncement,
  keysFromPrivate,
  generateStealthKeys,
  encodeMetaAddress,
  decodeMetaAddress,
  publicKeyToAddress,
  toChecksumAddress,
  isChecksumValid,
  deriveSharedSecret,
  toScalar,
  SCHEME_ID,
} from '../dist/index.js'

const SPENDING = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111')
const VIEWING = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222')

test('meta-address round-trips', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  assert.ok(keys.metaAddress.startsWith('st:eth:0x'))
  assert.equal(keys.metaAddress.length, 'st:eth:0x'.length + 132)

  const decoded = decodeMetaAddress(keys.metaAddress)
  assert.deepEqual(decoded.spendingPublicKey, keys.spending.publicKey)
  assert.deepEqual(decoded.viewingPublicKey, keys.viewing.publicKey)
  assert.equal(encodeMetaAddress(decoded), keys.metaAddress)
})

test('meta-address rejects malformed input', () => {
  assert.throws(() => decodeMetaAddress('0xdeadbeef'), /must start with/)
  assert.throws(() => decodeMetaAddress('st:eth:0xzz'), /not hex/)
  assert.throws(() => decodeMetaAddress('st:eth:0xabcd'), /must be 66 bytes/)
})

test('a payment the recipient can find and spend', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  const payment = createStealthPayment(keys.metaAddress)

  assert.equal(payment.schemeId, SCHEME_ID)
  assert.equal(payment.ephemeralPublicKey.length, 33)
  assert.ok(payment.viewTag >= 0 && payment.viewTag <= 255)
  assert.ok(isChecksumValid(payment.stealthAddress))

  const match = checkAnnouncement(keys, {
    ephemeralPublicKey: payment.ephemeralPublicKey,
    stealthAddress: payment.stealthAddress,
    viewTag: payment.viewTag,
  })

  assert.ok(match, 'recipient must recognise their own payment')
  assert.equal(match.stealthAddress, payment.stealthAddress)

  // Spendability: the derived key must actually control the derived address.
  const derivedAddress = publicKeyToAddress(secp256k1.getPublicKey(match.privateKey, false))
  assert.equal(derivedAddress, payment.stealthAddress)
})

test('a different recipient never matches', () => {
  const mine = keysFromPrivate(SPENDING, VIEWING)
  const theirs = generateStealthKeys()
  const payment = createStealthPayment(theirs.metaAddress)

  const match = checkAnnouncement(mine, {
    ephemeralPublicKey: payment.ephemeralPublicKey,
    stealthAddress: payment.stealthAddress,
    viewTag: payment.viewTag,
  })
  assert.equal(match, null)
})

test('a wrong view tag rejects before any address is derived', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  const payment = createStealthPayment(keys.metaAddress)

  const wrongTag = (payment.viewTag + 1) % 256
  assert.equal(
    checkAnnouncement(keys, {
      ephemeralPublicKey: payment.ephemeralPublicKey,
      stealthAddress: payment.stealthAddress,
      viewTag: wrongTag,
    }),
    null,
  )
})

test('an omitted view tag still matches by full derivation', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  const payment = createStealthPayment(keys.metaAddress)

  const match = checkAnnouncement(keys, {
    ephemeralPublicKey: payment.ephemeralPublicKey,
    stealthAddress: payment.stealthAddress,
  })
  assert.ok(match)
})

test('a malformed ephemeral key is rejected, not thrown', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  assert.equal(
    checkAnnouncement(keys, {
      ephemeralPublicKey: new Uint8Array(33),
      stealthAddress: '0x0000000000000000000000000000000000000000',
      viewTag: 0,
    }),
    null,
  )
})

test('every payment to the same meta-address is a fresh address', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  const seen = new Set()
  for (let i = 0; i < 25; i += 1) {
    seen.add(createStealthPayment(keys.metaAddress).stealthAddress)
  }
  assert.equal(seen.size, 25)
})

test('the shared secret is symmetric across the exchange', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  const ephemeralPrivate = secp256k1.utils.randomSecretKey()
  const ephemeralPublic = secp256k1.getPublicKey(ephemeralPrivate, true)

  const senderSide = deriveSharedSecret(toScalar(ephemeralPrivate), keys.viewing.publicKey)
  const recipientSide = deriveSharedSecret(toScalar(keys.viewing.privateKey), ephemeralPublic)

  assert.deepEqual(senderSide.hash, recipientSide.hash)
  assert.equal(senderSide.viewTag, recipientSide.viewTag)
})

test('EIP-55 checksum matches the published vectors', () => {
  const vectors = [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]
  for (const expected of vectors) {
    assert.equal(toChecksumAddress(expected.toLowerCase()), expected)
    assert.ok(isChecksumValid(expected))
  }
  assert.equal(isChecksumValid('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'), false)
})

test('address derivation rejects a compressed key', () => {
  const keys = keysFromPrivate(SPENDING, VIEWING)
  assert.throws(() => publicKeyToAddress(keys.spending.publicKey), /uncompressed/)
})
