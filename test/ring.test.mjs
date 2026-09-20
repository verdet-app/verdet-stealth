/**
 * Linkable ring signatures.
 *
 * Four properties matter and each one fails differently, so each gets its own test: it verifies
 * for a real member, it does not verify for anything else, it says nothing about which member
 * signed, and two signatures by the same member are linkable while two by different members are
 * not.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'

import { ringSign, ringVerify, ringKeyImage, sameSigner } from '../dist/index.js'

const message = new TextEncoder().encode('one claim per holder')

function makeRing(size) {
  const keys = Array.from({ length: size }, () => secp256k1.utils.randomSecretKey())
  return { keys, ring: keys.map((key) => secp256k1.getPublicKey(key, true)) }
}

test('a member can sign and any verifier can check it', () => {
  const { keys, ring } = makeRing(5)
  for (let i = 0; i < ring.length; i += 1) {
    const signature = ringSign(message, ring, keys[i], i)
    assert.ok(ringVerify(message, ring, signature), `member ${i} produced a signature that did not verify`)
  }
})

test('a ring of two works, and so does a large one', () => {
  for (const size of [2, 3, 16]) {
    const { keys, ring } = makeRing(size)
    const signature = ringSign(message, ring, keys[0], 0)
    assert.ok(ringVerify(message, ring, signature), `a ring of ${size} failed`)
  }
})

test('a different message does not verify', () => {
  const { keys, ring } = makeRing(4)
  const signature = ringSign(message, ring, keys[2], 2)
  assert.equal(ringVerify(new TextEncoder().encode('a different claim'), ring, signature), false)
})

test('a swapped decoy does not verify', () => {
  /* The mistake this guards against: without the ring inside the challenge, an attacker replaces
   * a member nobody signed with and the signature still passes, which would let a signature be
   * replayed against a set the signer never agreed to. */
  const { keys, ring } = makeRing(4)
  const signature = ringSign(message, ring, keys[1], 1)

  const tampered = [...ring]
  tampered[3] = secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), true)
  assert.equal(ringVerify(message, tampered, signature), false)
})

test('reordering the ring does not verify', () => {
  const { keys, ring } = makeRing(4)
  const signature = ringSign(message, ring, keys[0], 0)
  const reordered = [ring[1], ring[0], ring[2], ring[3]]
  assert.equal(ringVerify(message, reordered, signature), false)
})

test('a signature cannot be made without a member key', () => {
  const { ring } = makeRing(4)
  const outsider = secp256k1.utils.randomSecretKey()
  assert.throws(() => ringSign(message, ring, outsider, 0), /does not control/)
})

test('the right key at the wrong index is refused', () => {
  const { keys, ring } = makeRing(4)
  assert.throws(() => ringSign(message, ring, keys[2], 1), /does not control/)
})

test('a tampered response does not verify', () => {
  const { keys, ring } = makeRing(4)
  const signature = ringSign(message, ring, keys[1], 1)
  const broken = { ...signature, s: signature.s.map((value, i) => (i === 2 ? flip(value) : value)) }
  assert.equal(ringVerify(message, ring, broken), false)
})

test('a tampered key image does not verify', () => {
  const { keys, ring } = makeRing(4)
  const signature = ringSign(message, ring, keys[1], 1)
  const other = ringKeyImage(secp256k1.utils.randomSecretKey())
  assert.equal(ringVerify(message, ring, { ...signature, keyImage: other }), false)
})

test('the signature says nothing about which member signed', () => {
  /* The property the whole thing exists for, tested the only way a test can: the bytes of a
   * signature by member 0 and one by member 3 are the same shape, and nothing in the signature
   * equals or derives from the member's public key. */
  const { keys, ring } = makeRing(6)
  const first = ringSign(message, ring, keys[0], 0)
  const last = ringSign(message, ring, keys[5], 5)

  assert.equal(first.s.length, last.s.length)
  assert.equal(first.c0.length, last.c0.length)
  assert.equal(first.keyImage.length, last.keyImage.length)

  const hex = (bytes) => Buffer.from(bytes).toString('hex')
  const flat = [hex(first.c0), hex(first.keyImage), ...first.s.map(hex)].join('')
  for (const member of ring) {
    assert.ok(!flat.includes(hex(member)), 'a ring member appears verbatim in the signature')
  }
})

test('two signatures by the same member are linkable', () => {
  const { keys, ring } = makeRing(5)
  const a = ringSign(message, ring, keys[3], 3)
  const b = ringSign(new TextEncoder().encode('a second claim'), ring, keys[3], 3)
  assert.ok(sameSigner(a, b), 'the same signer produced two different key images')
})

test('two signatures by different members are not linkable', () => {
  const { keys, ring } = makeRing(5)
  const a = ringSign(message, ring, keys[1], 1)
  const b = ringSign(message, ring, keys[4], 4)
  assert.equal(sameSigner(a, b), false)
})

test('the image follows the signer across different rings', () => {
  /* This is what makes one-action-per-holder enforceable: change the decoys and the image is the
   * same, so a verifier counting images counts holders rather than rings. */
  const secret = secp256k1.utils.randomSecretKey()
  const mine = secp256k1.getPublicKey(secret, true)

  const ringA = [mine, ...makeRing(3).ring]
  const ringB = [...makeRing(4).ring, mine]

  const a = ringSign(message, ringA, secret, 0)
  const b = ringSign(message, ringB, secret, ringB.length - 1)

  assert.ok(ringVerify(message, ringA, a))
  assert.ok(ringVerify(message, ringB, b))
  assert.ok(sameSigner(a, b), 'the same holder produced different images in two rings')
})

test('the standalone image matches the one a signature carries', () => {
  const { keys, ring } = makeRing(3)
  const signature = ringSign(message, ring, keys[2], 2)
  assert.deepEqual(ringKeyImage(keys[2]), signature.keyImage)
})

test('a ring of one is refused', () => {
  const { keys, ring } = makeRing(2)
  assert.throws(() => ringSign(message, [ring[0]], keys[0], 0), /not a ring/)
})

test('a malformed member is refused', () => {
  const { keys, ring } = makeRing(3)
  const bad = [...ring]
  bad[1] = new Uint8Array(33)
  assert.throws(() => ringSign(message, bad, keys[0], 0), /compressed public key/)
})

function flip(bytes) {
  const out = Uint8Array.from(bytes)
  out[out.length - 1] ^= 0x01
  return out
}
