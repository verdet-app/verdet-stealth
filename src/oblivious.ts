/**
 * Oblivious transfer: fetching one record without saying which one you wanted.
 *
 * ## The leak this closes, which this product publishes about itself
 *
 * `/data-flow` says plainly that the read proxy sees which addresses are being read. That is the
 * one honest hole in the whole design: the addresses are joined by nothing on chain, and then the
 * wallet asks one server about all of them. Splitting the queries helps and does not fix it.
 *
 * Oblivious transfer fixes the shape of the question. The server holds a record for each of N
 * addresses; the holder retrieves exactly one; **the server does not learn which**, and the holder
 * learns nothing about the other N-1. Neither side is trusted to behave.
 *
 * ## The protocol
 *
 * Chou-Orlandi 1-of-N, over secp256k1.
 *
 *     sender     picks y, publishes S = yG
 *     receiver   picks x and a choice c, sends R = cS + xG
 *     sender     derives k_j = H(y(R - jS)) for every j
 *     receiver   derives k_c = H(xS)
 *
 * The two agree because `y(R - cS) = y(cS + xG - cS) = xyG = x(yG) = xS`.
 *
 * **The sender learns nothing about `c`** because `R` is `xG` blinded by a uniformly random `x`,
 * so it is uniform whatever `c` was. **The receiver learns nothing about the other records**
 * because computing `k_j` for `j != c` would mean producing `y(R - jS)` without `y`, which is the
 * Diffie-Hellman problem.
 *
 * ## What this module does and does not do
 *
 * It does the key agreement and stops. Each side ends with keys; **encrypting the records with
 * them is the caller's job, with AES-GCM from the platform**, the same way `vault.ts` already
 * does it. A hand-written authenticated cipher in the path that carries somebody's balance is
 * exactly the trade `RULES.md` section 6 refuses, and the honest boundary is the one drawn here.
 *
 * ## What it still does not hide
 *
 * **How many times you asked, and when.** Traffic analysis survives this untouched: a server that
 * sees twenty oblivious queries knows you have twenty addresses, even though it learns nothing
 * about which record each query was for. Hiding that is padding and timing, not cryptography.
 *
 * And one more, which is the reason this is a primitive here rather than a shipped feature: **it
 * takes two parties.** Nothing is oblivious until a server speaks the other half of it. Until then
 * this is the client side of a conversation nobody is having yet.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE, concatBytes } from '@noble/curves/utils.js'

import { CURVE_ORDER } from './derive.js'
import { scalarToPrivateKey } from './keys.js'

const Point = secp256k1.Point

const TAG = new TextEncoder().encode('verdet/ot/v1')

export interface SenderSetup {
  /** Kept. Never sent. */
  readonly secret: Uint8Array
  /** Published to the receiver before it chooses. */
  readonly point: Uint8Array
}

export interface ReceiverRequest {
  /** Kept. Never sent. */
  readonly secret: Uint8Array
  /** Sent to the sender. Uniform, whatever the choice was. */
  readonly request: Uint8Array
  readonly choice: number
}

function randomScalar(): bigint {
  const value = bytesToNumberBE(secp256k1.utils.randomSecretKey()) % CURVE_ORDER
  if (value === 0n) throw new Error('Drew a zero scalar, which cannot be used')
  return value
}

/**
 * One key from one point.
 *
 * The index goes into the hash as well as the point. Without it, two branches that happened to
 * agree on a point would agree on a key, and the separation between records is the whole thing
 * being bought here.
 */
function keyFrom(point: InstanceType<typeof Point>, index: number, count: number): Uint8Array {
  const header = new Uint8Array(8)
  const view = new DataView(header.buffer)
  view.setUint32(0, index)
  view.setUint32(4, count)
  return keccak_256(concatBytes(TAG, header, point.toBytes(true)))
}

function assertCount(count: number): void {
  if (!Number.isInteger(count) || count < 2) throw new Error('An oblivious transfer needs at least two records')
  if (count > 4096) throw new Error('That many branches is a denial of service against the sender')
}

/** The sender's opening move, made before it knows anything about the request. */
export function otSenderBegin(): SenderSetup {
  const y = randomScalar()
  return { secret: scalarToPrivateKey(y), point: Point.BASE.multiply(y).toBytes(true) }
}

/**
 * The receiver picks, and the picking is what the sender never sees.
 *
 * `R = cS + xG`. The `xG` term is uniform and independent of `c`, so the sender's view of `R`
 * carries no information about the choice at all. That is not a difficulty assumption, it is an
 * information-theoretic statement about a uniform blind.
 */
export function otReceiverChoose(senderPoint: Uint8Array, choice: number, count: number): ReceiverRequest {
  assertCount(count)
  if (!Number.isInteger(choice) || choice < 0 || choice >= count) {
    throw new Error('That choice is not one of the records on offer')
  }

  const S = Point.fromBytes(senderPoint)
  const x = randomScalar()
  const request = S.multiply(BigInt(choice) === 0n ? 1n : BigInt(choice))

  /* `c = 0` is the case to be careful with: multiplying by zero gives the identity, which no
   * curve library will hand back as a point. The zero branch is simply `xG`, which is what
   * `cS + xG` reduces to, so it is written out rather than multiplied. */
  const blinded = choice === 0 ? Point.BASE.multiply(x) : request.add(Point.BASE.multiply(x))

  return { secret: scalarToPrivateKey(x), request: blinded.toBytes(true), choice }
}

/**
 * The sender derives one key per record, without learning which will be used.
 *
 * It computes all of them. That is the cost of the protocol and it is linear in the number of
 * records, which is why `assertCount` has a ceiling: a receiver who asks for a million branches is
 * not being oblivious, they are making the sender do a million point multiplications.
 */
export function otSenderKeys(setup: SenderSetup, request: Uint8Array, count: number): readonly Uint8Array[] {
  assertCount(count)

  const y = bytesToNumberBE(setup.secret) % CURVE_ORDER
  const R = Point.fromBytes(request)
  const S = Point.fromBytes(setup.point)
  const yR = R.multiply(y)

  return Array.from({ length: count }, (_, j) => {
    /* y(R - jS). For j = 0 that is yR, and the subtraction is skipped rather than multiplying a
     * point by zero. */
    const point = j === 0 ? yR : yR.subtract(S.multiply(BigInt(j) * y % CURVE_ORDER))
    return keyFrom(point, j, count)
  })
}

/** The receiver derives exactly one, and has no path to any of the others. */
export function otReceiverKey(receiver: ReceiverRequest, senderPoint: Uint8Array, count: number): Uint8Array {
  assertCount(count)
  const x = bytesToNumberBE(receiver.secret) % CURVE_ORDER
  const S = Point.fromBytes(senderPoint)
  return keyFrom(S.multiply(x), receiver.choice, count)
}
