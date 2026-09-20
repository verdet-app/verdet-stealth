/**
 * Linkable ring signatures: proving you are one of them without saying which one.
 *
 * ## What this is for in this product
 *
 * Every other feature here hides which address received a payment. This hides **which holder is
 * acting**. Given a set of public keys, one holder can produce a signature that any verifier can
 * check against the whole set, and nothing in it says which member signed.
 *
 * The linkable part is what makes it useful rather than merely clever. Each signature carries a
 * key image derived from the signer's secret, and the same secret always produces the same image.
 * So a verifier can see that two signatures came from the same member **without ever learning
 * which member**, which is exactly what is needed to allow one action per holder: one claim, one
 * vote, one redemption, counted once, by nobody who can name you.
 *
 * ## The construction
 *
 * CryptoNote's form of LSAG, over secp256k1, which is the curve everything else here already uses.
 *
 * Each member has a point `H_i = hashToCurve(P_i)` that nobody knows the discrete log of relative
 * to `G`, so `I = x·H_signer` reveals nothing about `x` and cannot be forged by anybody who does
 * not hold it. The signature is a ring of challenges that only closes if one link was built with a
 * real secret, and the verifier walks the ring and checks that it closes.
 *
 * `hashToCurve` is RFC 9380, from the audited library, rather than try-and-increment. The naive
 * version leaks through timing and, worse, can be made to fail for chosen inputs.
 *
 * ## What it does not do
 *
 * **It does not hide amounts.** A ring signature is about identity within a set, and nothing else.
 * Confidential amounts are Pedersen commitments plus a range proof, and neither is built. The
 * assessment of what that would take, and why the range proof is the hard half rather than the
 * commitments, is in `internal/CRYPTO-PLAN.md`.
 *
 * **You are hidden among exactly as many people as the ring holds, and no more.** A ring of two
 * is a coin flip, and a ring whose other members are obviously not plausible signers is a ring of
 * one wearing a costume. Choosing the decoys well is the hard operational problem that no amount
 * of cryptography here solves for the caller.
 *
 * **It is not a spend authorisation on chain.** Nothing on chain 4663 verifies one of these. What
 * it can do today is authenticate an action to something we or anybody else runs off chain.
 */

import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, concatBytes } from '@noble/curves/utils.js'

import { CURVE_ORDER } from './derive.js'
import { scalarToPrivateKey, SECRET_KEY_BYTES } from './keys.js'

const Point = secp256k1.Point

const TAG = new TextEncoder().encode('verdet/ring/v1')

/** Every member's public key, compressed, in a fixed order. The order is part of what is signed. */
export type Ring = readonly Uint8Array[]

export interface RingSignature {
  /** The challenge the ring starts and must return to. */
  readonly c0: Uint8Array
  /** One response per member, in ring order. */
  readonly s: readonly Uint8Array[]
  /**
   * The key image. Constant for a given signer across every ring they ever sign in, and revealing
   * nothing about which member they are.
   */
  readonly keyImage: Uint8Array
}

/** A member's own point on the curve, which nobody knows the logarithm of against the generator. */
function memberPoint(publicKey: Uint8Array): InstanceType<typeof Point> {
  return secp256k1_hasher.hashToCurve(concatBytes(TAG, publicKey)) as InstanceType<typeof Point>
}

/**
 * The challenge for one link.
 *
 * The ring itself is hashed into a prefix once and carried into every step, so a signature made
 * over one set of members cannot be replayed against a different set with the same message. That
 * is the mistake worth being deliberate about: without the ring in the hash, an attacker swaps a
 * decoy and the signature still verifies.
 */
function challenge(prefix: Uint8Array, message: Uint8Array, left: Uint8Array, right: Uint8Array): bigint {
  const digest = keccak_256(concatBytes(prefix, message, left, right))
  return bytesToNumberBE(digest) % CURVE_ORDER
}

function ringPrefix(ring: Ring): Uint8Array {
  return keccak_256(concatBytes(TAG, ...ring))
}

const toScalarBytes = (value: bigint): Uint8Array => scalarToPrivateKey(value % CURVE_ORDER)

function assertRing(ring: Ring): void {
  if (ring.length < 2) throw new Error('A ring of one is not a ring')
  for (const member of ring) {
    if (member.length !== 33 || (member[0] !== 0x02 && member[0] !== 0x03)) {
      throw new Error('Every ring member is a 33 byte compressed public key')
    }
  }
}

/**
 * Sign as the member at `index`, without saying that it was that one.
 *
 * `secretKey` must be the key for `ring[index]`; a mismatch is refused here rather than producing
 * a signature that silently fails to verify, because a signature that does not verify is a
 * situation the caller can do nothing with and a wrong index is the ordinary way to get one.
 */
export function ringSign(
  message: Uint8Array,
  ring: Ring,
  secretKey: Uint8Array,
  index: number,
): RingSignature {
  assertRing(ring)
  if (!Number.isInteger(index) || index < 0 || index >= ring.length) {
    throw new Error('The signer index is not a member of this ring')
  }
  if (secretKey.length !== SECRET_KEY_BYTES) throw new Error(`A secret key is ${SECRET_KEY_BYTES} bytes`)

  const claimed = ring[index]
  const actual = secp256k1.getPublicKey(secretKey, true)
  if (!claimed || !actual.every((byte, i) => byte === claimed[i])) {
    throw new Error('That secret key does not control the member at that index')
  }

  const n = ring.length
  const x = bytesToNumberBE(secretKey) % CURVE_ORDER
  const points = ring.map((member) => Point.fromBytes(member))
  const hashes = ring.map((member) => memberPoint(member))

  const signerHash = hashes[index]
  if (!signerHash) throw new Error('The ring is malformed')
  const keyImage = signerHash.multiply(x)

  const prefix = ringPrefix(ring)
  const c = new Array<bigint>(n).fill(0n)
  const s = new Array<bigint>(n).fill(0n)

  /* The one honest link. Everything else in the ring is built backwards from its challenge. */
  const alpha = bytesToNumberBE(secp256k1.utils.randomSecretKey()) % CURVE_ORDER
  if (alpha === 0n) throw new Error('Drew a zero nonce, which cannot be used')

  let current = challenge(
    prefix,
    message,
    Point.BASE.multiply(alpha).toBytes(true),
    signerHash.multiply(alpha).toBytes(true),
  )
  c[(index + 1) % n] = current

  for (let step = 1; step < n; step += 1) {
    const i = (index + step) % n
    const point = points[i]
    const hash = hashes[i]
    if (!point || !hash) throw new Error('The ring is malformed')

    const response = bytesToNumberBE(secp256k1.utils.randomSecretKey()) % CURVE_ORDER
    s[i] = response

    /* L = sG + cP and R = sH + cI. With a random s these are just points; only the signer's link
     * is constrained, and that is what the closing step below fixes up. */
    const left = Point.BASE.multiply(response).add(point.multiply(current))
    const right = hash.multiply(response).add(keyImage.multiply(current))

    current = challenge(prefix, message, left.toBytes(true), right.toBytes(true))
    c[(i + 1) % n] = current
  }

  /* Close the ring: choose the signer's response so that its own challenge reproduces alpha. */
  const signerChallenge = c[index]
  if (signerChallenge === undefined) throw new Error('The ring did not close')
  s[index] = (alpha - ((signerChallenge * x) % CURVE_ORDER) + CURVE_ORDER * 2n) % CURVE_ORDER

  const c0 = c[0]
  if (c0 === undefined) throw new Error('The ring did not close')

  return {
    c0: toScalarBytes(c0),
    s: s.map(toScalarBytes),
    keyImage: keyImage.toBytes(true),
  }
}

/**
 * Does this signature close against this ring and this message?
 *
 * Returns a boolean rather than throwing on a bad signature, because an invalid signature is an
 * ordinary answer here and not an error: a verifier is asking a question, and "no" is one of the
 * two answers it is asking for.
 */
export function ringVerify(message: Uint8Array, ring: Ring, signature: RingSignature): boolean {
  try {
    assertRing(ring)
    if (signature.s.length !== ring.length) return false

    const points = ring.map((member) => Point.fromBytes(member))
    const hashes = ring.map((member) => memberPoint(member))
    const keyImage = Point.fromBytes(signature.keyImage)
    const prefix = ringPrefix(ring)
    const c0 = bytesToNumberBE(signature.c0) % CURVE_ORDER

    let current = c0
    for (let i = 0; i < ring.length; i += 1) {
      const point = points[i]
      const hash = hashes[i]
      const raw = signature.s[i]
      if (!point || !hash || !raw) return false

      const response = bytesToNumberBE(raw) % CURVE_ORDER
      const left = Point.BASE.multiply(response).add(point.multiply(current))
      const right = hash.multiply(response).add(keyImage.multiply(current))
      current = challenge(prefix, message, left.toBytes(true), right.toBytes(true))
    }

    return current === c0
  } catch {
    /* A malformed point, a bad length, anything: the answer is still no. */
    return false
  }
}

/**
 * The image for a secret, without signing anything.
 *
 * A verifier keeping a list of images it has already accepted needs to compare them; a holder
 * checking whether they have already acted needs to compute their own. Both want this without a
 * signature in hand.
 */
export function ringKeyImage(secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== SECRET_KEY_BYTES) throw new Error(`A secret key is ${SECRET_KEY_BYTES} bytes`)
  const publicKey = secp256k1.getPublicKey(secretKey, true)
  return memberPoint(publicKey).multiply(bytesToNumberBE(secretKey) % CURVE_ORDER).toBytes(true)
}

/** Two signatures from the same signer, whoever that is. */
export function sameSigner(a: RingSignature, b: RingSignature): boolean {
  return a.keyImage.length === b.keyImage.length && a.keyImage.every((byte, i) => byte === b.keyImage[i])
}
