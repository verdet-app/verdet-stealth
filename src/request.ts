/**
 * Private requests: being paid without handing anybody anything reusable.
 *
 * ## The leak this closes, which every stealth wallet has
 *
 * Payments to a meta-address are joined by nothing **on chain**, and the meta-address itself is a
 * persistent identifier **off it**. Give it
 * to ten payers and those ten can compare notes and know they are paying one person. Anyone
 * holding it can point at it and say whose it is. It is published once and it identifies you for
 * as long as it exists, which is the whole point of publishing it and also its weakness.
 *
 * A request closes that. The recipient derives the address themselves and hands over **one
 * address and nothing else**. The payer learns where to send this payment and learns nothing that
 * survives it: no identifier, no way to recognise another payment to the same person, nothing to
 * show anyone.
 *
 * ## And there is no announcement
 *
 * In the ordinary flow the payer picks the ephemeral key, so the recipient cannot find the payment
 * without an announcement, and that announcement is a public marker saying a stealth payment
 * happened here. Ours is not needed: **the recipient chose the ephemeral key, so they already
 * know the address.**
 *
 * What lands on chain is one ordinary transfer to one ordinary-looking address. No announcement,
 * no meta-address, no marker of any kind that a privacy tool was involved. That is the part that
 * is rare.
 *
 * ## Nothing extra to keep
 *
 * The ephemeral key is derived from the viewing key and an index, so **every address is
 * recoverable from the master keys alone**. Lose the device, restore the wallet, walk the indices
 * and every request address comes back. A scheme that required keeping a note per payment would
 * be a scheme that loses money.
 *
 * ## What it does not do
 *
 * The transfer is still public with a public amount and a public timestamp. The payer still knows
 * the one address they paid and can watch it forever. And a request is interactive: it has to be
 * handed over, which is why the published meta-address stays for the cases where it cannot be.
 * Both modes work and neither replaces the other.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'

import { CURVE_ORDER, deriveSharedSecret, deriveStealthPrivateScalar, stealthAddressFrom } from './derive.js'
import { scalarToPrivateKey, toScalar, type StealthKeys } from './keys.js'
import type { Address } from './address.js'

/**
 * Domain separation for the ephemeral key.
 *
 * The viewing key is used for two different things now, and a scheme that hashes it the same way
 * twice invites the two to collide. The tag costs nothing and removes the question.
 */
const TAG = new TextEncoder().encode('verdet/request/v1')

/**
 * The ephemeral scalar for one request, derived rather than random.
 *
 * Random would work and would have to be stored. Derived from the viewing key and an index, the
 * whole series regenerates from the master keys, which is the difference between a wallet you can
 * restore and a wallet you cannot.
 */
export function requestEphemeralScalar(viewingPrivateKey: Uint8Array, index: number): bigint {
  if (!Number.isInteger(index) || index < 0) throw new Error('A request index is a non-negative integer')

  const counter = new Uint8Array(8)
  new DataView(counter.buffer).setBigUint64(0, BigInt(index))

  const scalar = bytesToNumberBE(keccak_256(new Uint8Array([...TAG, ...viewingPrivateKey, ...counter]))) % CURVE_ORDER
  /* Astronomically unlikely and still checked, because a zero scalar produces the identity point
   * and an address nobody can spend from. */
  if (scalar === 0n) throw new Error('Derived a zero scalar, which cannot be used')
  return scalar
}

export interface PaymentRequest {
  readonly index: number
  /** Where the payer sends. The only thing they ever see. */
  readonly stealthAddress: Address
  /**
   * Published only if the recipient chooses to announce, which a request does not require.
   * Kept here so the same address can be found by an ordinary scanner if it ever needs to be.
   */
  readonly ephemeralPublicKey: Uint8Array
  /** The key that spends it. Derived, never stored, never sent. */
  readonly privateKey: Uint8Array
  /** The byte an ordinary scanner would filter on, if this were announced. */
  readonly viewTag: number
}

/**
 * One request address, fully determined by the wallet and the index.
 *
 * The construction is the ordinary stealth one and is deliberately unchanged: the shared secret is
 * the same ECDH point, the address is the same tweak of the spending key. Only **who picks the
 * ephemeral key** is different. That keeps every address here compatible with any scanner that
 * follows the specification, so announcing one later is a choice rather than a migration.
 */
export function deriveRequest(keys: StealthKeys, index: number): PaymentRequest {
  const ephemeralScalar = requestEphemeralScalar(keys.viewing.privateKey, index)
  const ephemeralPublicKey = secp256k1.getPublicKey(scalarToPrivateKey(ephemeralScalar), true)

  const secret = deriveSharedSecret(ephemeralScalar, keys.viewing.publicKey)
  const stealthAddress = stealthAddressFrom(keys.spending.publicKey, secret.scalar)
  const privateKey = scalarToPrivateKey(deriveStealthPrivateScalar(toScalar(keys.spending.privateKey), secret.scalar))

  return { index, stealthAddress, ephemeralPublicKey, privateKey, viewTag: secret.viewTag }
}

/**
 * Regenerate a run of requests, which is what recovery is.
 *
 * There is no state to restore and no file to have kept: the master keys and a count are enough.
 * A wallet restoring itself walks this and checks each address for a balance.
 */
export function deriveRequests(keys: StealthKeys, count: number, from = 0): readonly PaymentRequest[] {
  if (!Number.isInteger(count) || count < 0) throw new Error('A count is a non-negative integer')
  return Array.from({ length: count }, (_, i) => deriveRequest(keys, from + i))
}
