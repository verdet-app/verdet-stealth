/**
 * The sweep: one signature and two calls, checked the way a token checks them.
 *
 * The decisive test here is not that the code runs. It is that **the signature recovers to the
 * address that owns the asset**, because that is the single thing a token does with a permit. If
 * the v, r and s are assembled wrongly the call does not fail loudly: it recovers to some other
 * address, the token sees an owner who authorised nothing, and the revert says nothing useful.
 *
 * Two selectors are asserted against their published values rather than against this code, so a
 * typo in a signature string cannot pass by agreeing with itself.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'

import {
  generateStealthKeys,
  permitDigest,
  signPermit,
  encodeSweep,
  encodeNoncesCall,
  publicKeyToAddress,
} from '../dist/index.js'

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')

/* A key and the address it controls. Any key will do; the point is that they match. */
const KEY = keccak_256(new TextEncoder().encode('a stealth address spending key, for tests only'))
const OWNER = publicKeyToAddress(secp256k1.getPublicKey(KEY, false))

const SPENDER = '0x000000000000000000000000000000000000BEEF'
const DESTINATION = '0x000000000000000000000000000000000000dEaD'
const TOKEN = '0x1111111111111111111111111111111111111111'
const SEPARATOR = `0x${'ab'.repeat(32)}`

const terms = {
  owner: OWNER,
  spender: SPENDER,
  value: 1_000_000_000_000_000_000n,
  nonce: 0n,
  deadline: 1_800_000_000n,
  domainSeparator: SEPARATOR,
}

/* --- The selectors, against their published values -------------------------- */

test('the two selectors are the ones every token implements', () => {
  const signed = signPermit(permitDigest(terms), KEY, OWNER)
  const calls = encodeSweep(TOKEN, terms, signed, DESTINATION)

  /* EIP-2612's permit. Not DAI's, which takes different arguments and has its own selector. */
  assert.equal(calls.permit.slice(0, 10), '0xd505accf')
  /* ERC-20's transferFrom. */
  assert.equal(calls.transfer.slice(0, 10), '0x23b872dd')
})

test('nonces is the standard selector too', () => {
  assert.equal(encodeNoncesCall(OWNER).slice(0, 10), '0x7ecebe00')
})

/* --- The thing a token actually does ---------------------------------------- */

test('the signature recovers to the address that owns the asset', () => {
  const digest = permitDigest(terms)
  const signed = signPermit(digest, KEY, OWNER)

  /* Exactly what ecrecover does: rebuild the signature, recover the public key, take the address.
   * If v, r or s were assembled wrongly this lands somewhere else and the permit authorises
   * nobody. */
  const compact = new Uint8Array(64)
  compact.set(Buffer.from(signed.r.slice(2), 'hex'), 0)
  compact.set(Buffer.from(signed.s.slice(2), 'hex'), 32)

  const recovery = signed.v - 27
  assert.ok(recovery === 0 || recovery === 1, `recovery id ${recovery} is not 0 or 1`)

  const signature = secp256k1.Signature.fromBytes(compact, 'compact').addRecoveryBit(recovery)
  const recovered = signature.recoverPublicKey(digest).toBytes(false)

  assert.equal(publicKeyToAddress(recovered), OWNER)
})

test('signing with a key that does not own the address is refused', () => {
  /* Not a loud failure on chain: it recovers to a different address and the token rejects a
   * permit nobody understands. Cheaper to stop here, with a sentence. */
  const other = generateStealthKeys()
  assert.throws(
    () => signPermit(permitDigest(terms), other.spending.privateKey, OWNER),
    /not/,
  )
})

test('s is in the lower half, which Ethereum requires', () => {
  /* The other half of every signature pair is equally valid mathematically and many contracts
   * refuse it, because accepting both makes a signature malleable. */
  const half = BigInt('0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0')
  for (let i = 0; i < 12; i += 1) {
    const signed = signPermit(permitDigest({ ...terms, nonce: BigInt(i) }), KEY, OWNER)
    assert.ok(BigInt(signed.s) <= half, `s is in the upper half at nonce ${i}`)
  }
})

/* --- Replay protection, term by term ---------------------------------------- */

test('every term changes the digest, so none of them can be swapped after signing', () => {
  const base = hex(permitDigest(terms))
  const variants = {
    nonce: { ...terms, nonce: 1n },
    value: { ...terms, value: terms.value + 1n },
    deadline: { ...terms, deadline: terms.deadline + 1n },
    spender: { ...terms, spender: DESTINATION },
    owner: { ...terms, owner: SPENDER },
    domain: { ...terms, domainSeparator: `0x${'cd'.repeat(32)}` },
  }
  for (const [name, variant] of Object.entries(variants)) {
    assert.notEqual(hex(permitDigest(variant)), base, `${name} does not change the digest`)
  }
})

test('a domain separator of the wrong length is refused rather than padded', () => {
  /* Padding it would produce a signature bound to a token that does not exist. */
  assert.throws(() => permitDigest({ ...terms, domainSeparator: '0x1234' }), /32 bytes/)
})

/* --- Shape of the calls ------------------------------------------------------ */

test('the calldata is the length the argument lists say', () => {
  const signed = signPermit(permitDigest(terms), KEY, OWNER)
  const calls = encodeSweep(TOKEN, terms, signed, DESTINATION)

  /* permit takes seven arguments, all one word; transferFrom takes three. */
  assert.equal((calls.permit.length - 2) / 2, 4 + 7 * 32)
  assert.equal((calls.transfer.length - 2) / 2, 4 + 3 * 32)
  assert.equal(calls.to, TOKEN)
})

test('the transfer moves the asset to the destination, never to the spender', () => {
  /* The whole reason this shape has no custody: the asset goes from the owner to wherever the
   * holder chose, in one step, and the party paying the gas never appears as a recipient. */
  const signed = signPermit(permitDigest(terms), KEY, OWNER)
  const calls = encodeSweep(TOKEN, terms, signed, DESTINATION)
  const body = calls.transfer.slice(10).toLowerCase()

  assert.equal(body.slice(24, 64), OWNER.slice(2).toLowerCase(), 'the source is not the owner')
  assert.equal(body.slice(88, 128), DESTINATION.slice(2).toLowerCase(), 'the destination is wrong')
  assert.ok(!body.includes(SPENDER.slice(2).toLowerCase()), 'the spender appears in a transfer it must not receive')
})
