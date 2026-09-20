/**
 * Proofs of control and of a payment.
 *
 * The property a sigma protocol has to have is that everything the verifier checks is inside the
 * challenge. So most of these tests change one public value at a time and require the proof to
 * fail, because a value left out of the challenge is a value an attacker gets to choose afterwards.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'

import {
  proveControl,
  verifyControl,
  proveControlOfSet,
  verifyControlOfSet,
  provePayment,
  verifyPayment,
  generateStealthKeys,
} from '../dist/index.js'

const message = new TextEncoder().encode('settlement with a counterparty, 2026-09')
const other = new TextEncoder().encode('a different statement')

const key = () => {
  const secret = secp256k1.utils.randomSecretKey()
  return { secret, publicKey: secp256k1.getPublicKey(secret, true) }
}

test('a proof of control verifies for the holder', () => {
  const { secret, publicKey } = key()
  assert.ok(verifyControl(publicKey, message, proveControl(secret, message)))
})

test('a proof of control does not verify for another key', () => {
  const { secret } = key()
  const { publicKey } = key()
  assert.equal(verifyControl(publicKey, message, proveControl(secret, message)), false)
})

test('a proof of control is bound to its message', () => {
  /* The reason this is not a transaction signature: it proves one statement and nothing else. */
  const { secret, publicKey } = key()
  assert.equal(verifyControl(publicKey, other, proveControl(secret, message)), false)
})

test('a tampered response or commitment does not verify', () => {
  const { secret, publicKey } = key()
  const proof = proveControl(secret, message)

  assert.equal(verifyControl(publicKey, message, { ...proof, response: flip(proof.response) }), false)
  assert.equal(verifyControl(publicKey, message, { ...proof, commitment: flip(proof.commitment) }), false)
})

test('two proofs of the same statement differ', () => {
  /* A fresh nonce each time. A deterministic commitment here would leak the secret across two
   * proofs of different messages, which is the classic nonce-reuse failure. */
  const { secret } = key()
  const a = proveControl(secret, message)
  const b = proveControl(secret, message)
  assert.notDeepEqual(a.commitment, b.commitment)
  assert.notDeepEqual(a.response, b.response)
})

test('a set of addresses can be proved together', () => {
  const keys = Array.from({ length: 5 }, key)
  const proof = proveControlOfSet(keys.map((k) => k.secret), message)
  assert.ok(verifyControlOfSet(keys.map((k) => k.publicKey), message, proof))
})

test('a set proof cannot have a member removed', () => {
  /* One challenge over the whole set is what stops four of five addresses being lifted out and
   * shown somewhere else as a smaller claim. */
  const keys = Array.from({ length: 5 }, key)
  const proof = proveControlOfSet(keys.map((k) => k.secret), message)
  const fewer = keys.slice(0, 4).map((k) => k.publicKey)
  assert.equal(verifyControlOfSet(fewer, message, proof), false)
})

test('a set proof cannot have a member added or swapped', () => {
  const keys = Array.from({ length: 4 }, key)
  const proof = proveControlOfSet(keys.map((k) => k.secret), message)

  const added = [...keys.map((k) => k.publicKey), key().publicKey]
  assert.equal(verifyControlOfSet(added, message, proof), false)

  const swapped = keys.map((k) => k.publicKey)
  swapped[2] = key().publicKey
  assert.equal(verifyControlOfSet(swapped, message, proof), false)
})

test('the order of a set is part of what is proved', () => {
  const keys = Array.from({ length: 4 }, key)
  const proof = proveControlOfSet(keys.map((k) => k.secret), message)
  const publicKeys = keys.map((k) => k.publicKey)
  const reordered = [publicKeys[1], publicKeys[0], publicKeys[2], publicKeys[3]]
  assert.equal(verifyControlOfSet(reordered, message, proof), false)
})

test('an empty set is refused rather than trivially proved', () => {
  assert.throws(() => proveControlOfSet([], message), /nothing to prove/)
  assert.equal(verifyControlOfSet([], message, proveControl(key().secret, message)), false)
})

test('a payment proof verifies for the recipient', () => {
  const keys = generateStealthKeys()
  const ephemeral = secp256k1.utils.randomSecretKey()
  const R = secp256k1.getPublicKey(ephemeral, true)

  const proof = provePayment(keys.viewing.privateKey, R, message)
  assert.ok(verifyPayment(keys.viewing.publicKey, R, message, proof))
})

test('a payment proof reveals no viewing key', () => {
  /* The whole point: the alternative is handing over the viewing key, which hands over every
   * payment that will ever arrive rather than this one. */
  const keys = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  const proof = provePayment(keys.viewing.privateKey, R, message)

  const hex = (bytes) => Buffer.from(bytes).toString('hex')
  const flat = [proof.commitmentG, proof.commitmentR, proof.response, proof.shared].map(hex).join('')
  assert.ok(!flat.includes(hex(keys.viewing.privateKey)), 'the viewing key is in the proof')
})

test('a payment proof does not verify against another viewing key', () => {
  const mine = generateStealthKeys()
  const theirs = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)

  const proof = provePayment(mine.viewing.privateKey, R, message)
  assert.equal(verifyPayment(theirs.viewing.publicKey, R, message, proof), false)
})

test('a payment proof does not verify against another ephemeral key', () => {
  const keys = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  const otherR = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)

  const proof = provePayment(keys.viewing.privateKey, R, message)
  assert.equal(verifyPayment(keys.viewing.publicKey, otherR, message, proof), false)
})

test('a substituted shared point does not verify', () => {
  /* The shared secret is the thing being proved, so it has to be in the challenge. If it were
   * not, a prover could produce a proof and then claim it was about a different payment. */
  const keys = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  const proof = provePayment(keys.viewing.privateKey, R, message)

  const elsewhere = generateStealthKeys()
  const fake = provePayment(elsewhere.viewing.privateKey, R, message)
  assert.equal(verifyPayment(keys.viewing.publicKey, R, message, { ...proof, shared: fake.shared }), false)
})

test('a payment proof is bound to its message', () => {
  const keys = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  const proof = provePayment(keys.viewing.privateKey, R, message)
  assert.equal(verifyPayment(keys.viewing.publicKey, R, other, proof), false)
})

test('one relation alone is not enough', () => {
  /* Chaum-Pedersen ties two relations to one exponent. A proof carrying a good commitment on G
   * and a bad one on R must fail, or it proves nothing about the payment at all. */
  const keys = generateStealthKeys()
  const R = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  const proof = provePayment(keys.viewing.privateKey, R, message)

  assert.equal(verifyPayment(keys.viewing.publicKey, R, message, { ...proof, commitmentR: flip(proof.commitmentR) }), false)
  assert.equal(verifyPayment(keys.viewing.publicKey, R, message, { ...proof, commitmentG: flip(proof.commitmentG) }), false)
})

test('a zero secret is refused', () => {
  assert.throws(() => proveControl(new Uint8Array(32), message), /zero on this curve/)
})

function flip(bytes) {
  const out = Uint8Array.from(bytes)
  /* Flipping the leading byte of a compressed point makes it a different valid point or an
   * invalid one, and either answer from the verifier is "no". */
  out[out.length - 1] ^= 0x01
  return out
}
