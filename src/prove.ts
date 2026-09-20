/**
 * Proving things about your keys without handing them over.
 *
 * ## The two statements worth proving in this product
 *
 * **I control this address.** A Schnorr proof of knowledge of the private key. Close cousin of a
 * signature and deliberately not one: it is bound to a statement you chose rather than to a
 * transaction, so it cannot be replayed on any chain, and several addresses can be proved together
 * under one challenge rather than one signature each.
 *
 * **This payment was addressed to me.** The interesting one, and the one a signature cannot do.
 * A stealth payment carries an ephemeral public key `R`. Whoever holds the viewing key `v` can
 * compute the shared secret `S = vR`, and nobody else can. So proving knowledge of `v` such that
 * `V = vG` **and** `S = vR`, for a published `S`, proves the payment was derived for you, to
 * anybody, **without revealing `v`**.
 *
 * That second one matters because the alternative is handing over the viewing key, which hands over
 * every payment you will ever receive. This proves one payment and nothing else.
 *
 * ## What these are, precisely
 *
 * Sigma protocols made non-interactive with Fiat-Shamir. Schnorr for one base, Chaum-Pedersen for
 * two bases with a shared exponent. Both are textbook, both are a few dozen lines against the
 * curve already imported, and both are honest-verifier zero knowledge: the transcript can be
 * simulated without the secret, so it reveals nothing a simulator could not have produced. That is
 * the precise claim, and it is narrower than the phrase the marketing of this field usually
 * attaches to it, which is why `scripts/lint-copy.mjs` bans the hyphenated term by default.
 *
 * **These are not SNARKs and nothing here calls them one.** A general-purpose proof system needs a
 * circuit compiler, a proving system, and for Groth16 a trusted setup. Writing one from scratch is
 * not a week of work, and shipping somebody else's proving key into the path that touches a private
 * key is the trade `RULES.md` section 6 refuses. What a sigma protocol proves is narrow, and these
 * two statements happen to be exactly the narrow things this product needs.
 *
 * ## The one rule that makes Fiat-Shamir safe
 *
 * **Everything the verifier will check goes into the challenge.** Leave a public value out and the
 * proof can be forged by choosing that value after the fact. Every function here hashes the full
 * statement, including the generators, before the challenge, and the tests check that changing any
 * part of it breaks the proof.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, concatBytes } from '@noble/curves/utils.js'

import { CURVE_ORDER } from './derive.js'
import { scalarToPrivateKey, SECRET_KEY_BYTES } from './keys.js'

const Point = secp256k1.Point

const TAG_CONTROL = new TextEncoder().encode('verdet/prove/control/v1')
const TAG_PAYMENT = new TextEncoder().encode('verdet/prove/payment/v1')

/** A Schnorr proof: the commitment and the response. */
export interface ControlProof {
  /** Compressed commitment point. */
  readonly commitment: Uint8Array
  readonly response: Uint8Array
}

/** A Chaum-Pedersen proof: one commitment per base, one shared response. */
export interface PaymentProof {
  readonly commitmentG: Uint8Array
  readonly commitmentR: Uint8Array
  readonly response: Uint8Array
  /** The shared secret point the proof is about. Public: it is what is being proved. */
  readonly shared: Uint8Array
}

const randomScalar = (): bigint => {
  const value = bytesToNumberBE(secp256k1.utils.randomSecretKey()) % CURVE_ORDER
  if (value === 0n) throw new Error('Drew a zero nonce, which cannot be used')
  return value
}

const scalarBytes = (value: bigint): Uint8Array => scalarToPrivateKey(((value % CURVE_ORDER) + CURVE_ORDER) % CURVE_ORDER)

function assertSecret(secret: Uint8Array): bigint {
  if (secret.length !== SECRET_KEY_BYTES) throw new Error(`A secret key is ${SECRET_KEY_BYTES} bytes`)
  const value = bytesToNumberBE(secret) % CURVE_ORDER
  if (value === 0n) throw new Error('That secret is zero on this curve')
  return value
}

/* --- I control this address -------------------------------------------------- */

function controlChallenge(publicKeys: readonly Uint8Array[], commitment: Uint8Array, message: Uint8Array): bigint {
  return bytesToNumberBE(keccak_256(concatBytes(TAG_CONTROL, ...publicKeys, commitment, message))) % CURVE_ORDER
}

/**
 * Prove knowledge of the private key behind one public key.
 *
 * The message is yours to choose and it is bound into the proof, which is the whole reason this is
 * not a transaction signature: a proof made for "settlement with Halvorsen, 2026-09" proves
 * nothing anywhere else and authorises nothing anywhere at all.
 */
export function proveControl(secret: Uint8Array, message: Uint8Array): ControlProof {
  const x = assertSecret(secret)
  const publicKey = secp256k1.getPublicKey(secret, true)

  const nonce = randomScalar()
  const commitment = Point.BASE.multiply(nonce).toBytes(true)
  const c = controlChallenge([publicKey], commitment, message)

  return { commitment, response: scalarBytes(nonce + c * x) }
}

export function verifyControl(publicKey: Uint8Array, message: Uint8Array, proof: ControlProof): boolean {
  try {
    const point = Point.fromBytes(publicKey)
    const commitment = Point.fromBytes(proof.commitment)
    const s = bytesToNumberBE(proof.response) % CURVE_ORDER
    const c = controlChallenge([publicKey], proof.commitment, message)

    /* sG == commitment + cP */
    return Point.BASE.multiply(s).equals(commitment.add(point.multiply(c)))
  } catch {
    return false
  }
}

/**
 * Prove control of several addresses at once, under one challenge.
 *
 * Not the same as a proof each. One challenge over the whole set means the proofs cannot be
 * separated and re-presented individually, so a holder proving control of five addresses cannot
 * have four of them lifted out and shown somewhere else.
 */
export function proveControlOfSet(secrets: readonly Uint8Array[], message: Uint8Array): ControlProof {
  if (secrets.length === 0) throw new Error('There is nothing to prove control of')

  const values = secrets.map(assertSecret)
  const publicKeys = secrets.map((secret) => secp256k1.getPublicKey(secret, true))

  const nonce = randomScalar()
  const commitment = Point.BASE.multiply(nonce).toBytes(true)
  const c = controlChallenge(publicKeys, commitment, message)

  /* One response over the sum, with each key weighted by a power of the challenge, so no single
   * key's contribution can be isolated. */
  let response = nonce
  let weight = c
  for (const value of values) {
    response = (response + weight * value) % CURVE_ORDER
    weight = (weight * c) % CURVE_ORDER
  }

  return { commitment, response: scalarBytes(response) }
}

export function verifyControlOfSet(
  publicKeys: readonly Uint8Array[],
  message: Uint8Array,
  proof: ControlProof,
): boolean {
  try {
    if (publicKeys.length === 0) return false

    const commitment = Point.fromBytes(proof.commitment)
    const s = bytesToNumberBE(proof.response) % CURVE_ORDER
    const c = controlChallenge(publicKeys, proof.commitment, message)

    let expected = commitment
    let weight = c
    for (const key of publicKeys) {
      expected = expected.add(Point.fromBytes(key).multiply(weight))
      weight = (weight * c) % CURVE_ORDER
    }

    return Point.BASE.multiply(s).equals(expected)
  } catch {
    return false
  }
}

/* --- This payment was addressed to me ---------------------------------------- */

function paymentChallenge(
  viewingPublicKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  shared: Uint8Array,
  commitmentG: Uint8Array,
  commitmentR: Uint8Array,
  message: Uint8Array,
): bigint {
  return (
    bytesToNumberBE(
      keccak_256(
        concatBytes(TAG_PAYMENT, viewingPublicKey, ephemeralPublicKey, shared, commitmentG, commitmentR, message),
      ),
    ) % CURVE_ORDER
  )
}

/**
 * Prove that the shared secret of a stealth payment is yours, without revealing the viewing key.
 *
 * The statement is `V = vG` and `S = vR` for the same `v`. Only the holder of the viewing key can
 * produce `S`, so a proof that the same exponent relates both pairs is a proof that the payment
 * was derived for this viewing key.
 *
 * **What the verifier learns.** That this one payment belongs to the holder of `V`. Not the viewing
 * key, not any other payment, and nothing about the spending key. The alternative in every other
 * wallet is to hand over the viewing key, which hands over every payment that will ever arrive.
 */
export function provePayment(
  viewingSecret: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  message: Uint8Array,
): PaymentProof {
  const v = assertSecret(viewingSecret)
  const viewingPublicKey = secp256k1.getPublicKey(viewingSecret, true)
  const R = Point.fromBytes(ephemeralPublicKey)

  const shared = R.multiply(v).toBytes(true)
  const nonce = randomScalar()
  const commitmentG = Point.BASE.multiply(nonce).toBytes(true)
  const commitmentR = R.multiply(nonce).toBytes(true)

  const c = paymentChallenge(viewingPublicKey, ephemeralPublicKey, shared, commitmentG, commitmentR, message)

  return { commitmentG, commitmentR, response: scalarBytes(nonce + c * v), shared }
}

export function verifyPayment(
  viewingPublicKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  message: Uint8Array,
  proof: PaymentProof,
): boolean {
  try {
    const V = Point.fromBytes(viewingPublicKey)
    const R = Point.fromBytes(ephemeralPublicKey)
    const S = Point.fromBytes(proof.shared)
    const commitmentG = Point.fromBytes(proof.commitmentG)
    const commitmentR = Point.fromBytes(proof.commitmentR)
    const s = bytesToNumberBE(proof.response) % CURVE_ORDER

    const c = paymentChallenge(
      viewingPublicKey,
      ephemeralPublicKey,
      proof.shared,
      proof.commitmentG,
      proof.commitmentR,
      message,
    )

    /* Both relations must hold with the same response, which is what ties them to one exponent. */
    const left = Point.BASE.multiply(s).equals(commitmentG.add(V.multiply(c)))
    const right = R.multiply(s).equals(commitmentR.add(S.multiply(c)))
    return left && right
  } catch {
    return false
  }
}
