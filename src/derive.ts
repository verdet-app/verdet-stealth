/**
 * The shared derivation both sides of a stealth payment perform.
 *
 * Sender and recipient reach the same secret from opposite ends of an ECDH exchange, so this math
 * lives in one place. If it were duplicated, the two halves could drift and every payment derived
 * from the drifted half would be unspendable.
 *
 * All curve operations are delegated to an audited implementation. Nothing here reimplements
 * secp256k1.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'
import { publicKeyToAddress, type Address } from './address.js'

const { Point } = secp256k1
const CURVE_ORDER = Point.Fn.ORDER

export interface SharedSecret {
  /** keccak256 of the compressed ECDH point. */
  readonly hash: Uint8Array
  /** The hash reduced into the scalar field, ready to use as a key tweak. */
  readonly scalar: bigint
  /**
   * First byte of the hash.
   *
   * Published alongside the announcement so a scanner can reject about 255 of every 256 candidates
   * without going on to derive an address.
   *
   * **It does not avoid curve arithmetic, and an earlier version of this comment said it did.** The
   * tag is the first byte of the hash of the shared secret, so producing it requires the ECDH
   * multiply. What the tag saves is everything after: the second scalar multiplication, the point
   * addition and the keccak that `deriveStealthPublicKey` performs. Roughly half the per-candidate
   * work, avoided on all but one candidate in 256.
   *
   * It leaks one byte of the shared secret to anyone reading the chain, by design. That is the price
   * of scanning on a phone instead of on a server you would have to trust.
   */
  readonly viewTag: number
}

/**
 * ECDH, then hash.
 *
 * **The compressed encoding is hashed, and the specification does not say to.** ERC-5564 writes
 * `s_h = h(s)` where `s` is a curve point and never states how the point is serialised. Three
 * readings are defensible (compressed, uncompressed, x coordinate alone) and they produce three
 * different secrets, three different scalars and three different addresses, with no error
 * anywhere.
 *
 * This library takes the compressed reading. That choice is pinned by
 * `test/interop.test.mjs`, which publishes the whole vector so another implementation can be
 * compared against it in one step. Until somebody runs that comparison (T76), interoperability
 * with other wallets is **unverified**, and the site should not be presented as though it were.
 */
export function deriveSharedSecret(privateScalar: bigint, publicKey: Uint8Array): SharedSecret {
  const point = Point.fromBytes(publicKey).multiply(privateScalar)
  const hash = keccak_256(point.toBytes(true))

  const viewTag = hash[0]
  if (viewTag === undefined) throw new Error('Hash produced no bytes')

  /**
   * Reducing modulo the curve order is required, not cosmetic: a 256-bit hash can exceed the
   * order, and an unreduced tweak would land on a point neither side can reproduce.
   */
  const scalar = bytesToNumberBE(hash) % CURVE_ORDER
  if (scalar === 0n) throw new Error('Derived scalar is zero')

  return { hash, scalar, viewTag }
}

/** Tweak the recipient's spending key by the shared secret to reach the one-time public key. */
export function deriveStealthPublicKey(
  spendingPublicKey: Uint8Array,
  secretScalar: bigint,
): Uint8Array {
  const tweaked = Point.fromBytes(spendingPublicKey).add(Point.BASE.multiply(secretScalar))
  tweaked.assertValidity()
  return tweaked.toBytes(false)
}

export function stealthAddressFrom(
  spendingPublicKey: Uint8Array,
  secretScalar: bigint,
): Address {
  return publicKeyToAddress(deriveStealthPublicKey(spendingPublicKey, secretScalar))
}

/**
 * The spending key for a stealth address: the recipient's spending scalar plus the shared secret.
 *
 * This is the only value that can move the funds, and it never crosses a network boundary.
 */
export function deriveStealthPrivateScalar(spendingScalar: bigint, secretScalar: bigint): bigint {
  const combined = (spendingScalar + secretScalar) % CURVE_ORDER
  if (combined === 0n) throw new Error('Derived stealth private key is zero')
  return combined
}

export { CURVE_ORDER }
