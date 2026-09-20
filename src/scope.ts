/**
 * Scoped disclosure: showing somebody one period and not the rest.
 *
 * ## The problem with the watch key, which is the problem with every wallet
 *
 * A watch key is all or nothing. Hand it to an accountant for last quarter and they have last
 * quarter, every quarter before it, and every quarter that will ever follow, permanently. Every
 * other wallet answers "let my auditor see this" the same way, and all-or-nothing is precisely
 * what stops an institution using any of it. A desk cannot hand its entire forward book to a
 * counterparty's compliance team to settle one trade.
 *
 * ## The construction
 *
 * One more derivation, in the one place that makes it work. The viewing key is what finds
 * payments, so a viewing key **per period** finds the payments of that period and no other:
 *
 *     vk(label) = keccak(tag || masterViewingKey || label) mod n
 *
 * Requests inside a scope use `vk(label)` everywhere the wallet used the master. The address is
 * still a tweak of the same spending key, so spending is unchanged and the money is not split
 * across scopes. What changes is who can find what.
 *
 * **The scoping is the one-wayness.** From `vk("2026-09")` there is no path back to the master and
 * therefore none to `vk("2026-10")`. That is a hash, not a policy, and it is the whole feature.
 *
 * ## What a label is
 *
 * A string the holder chooses: a month, a quarter, a mandate, a counterparty. Not a date type,
 * because the useful unit is whatever the disclosure is actually about, and a product that only
 * offered months would be a product that could not scope to one mandate.
 *
 * ## What a recipient of a scoped key can and cannot verify
 *
 * Said precisely, because the tempting overclaim here is large.
 *
 * They **can** tell a scoped key from an unscoped one: the format says so in its version byte, so
 * nobody can be handed the whole wallet under a label saying one month.
 *
 * They **cannot** verify that the key they hold is genuinely `vk(label)` derived from some master,
 * because checking that would need the master. What they can do is the check that actually
 * matters in practice: look for the payments they expect to see. A key covering less than it
 * claims shows up as a payment that is missing, against a chain anybody can read.
 *
 * ## What it does not do
 *
 * Nothing about the transfers themselves: amounts, timing and the counterparty stay public, as
 * they are for every address on any chain. And a scope cannot be revoked once handed over, any
 * more than a photograph can. It is bounded, which is the improvement, not recallable.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'

import { CURVE_ORDER } from './derive.js'
import { scalarToPrivateKey, SECRET_KEY_BYTES, type StealthKeys } from './keys.js'

const TAG = new TextEncoder().encode('verdet/scope/v1')

/**
 * Long enough for "Q3 2026, mandate with Halvorsen", short enough to travel in a key.
 *
 * The limit is in bytes rather than characters because the label is length-prefixed with a single
 * byte when it is encoded, and a limit expressed in characters would be a limit that moves with
 * the alphabet somebody writes in.
 */
export const SCOPE_LABEL_MAX_BYTES = 64

const encoder = new TextEncoder()

export interface Scope {
  readonly label: string
  /** Finds this period's payments and no other's. */
  readonly viewingPrivateKey: Uint8Array
  readonly viewingPublicKey: Uint8Array
}

export function scopeLabelBytes(label: string): Uint8Array {
  const trimmed = label.trim()
  if (trimmed.length === 0) throw new Error('A scope needs a label, or it scopes nothing')

  const bytes = encoder.encode(trimmed)
  if (bytes.length > SCOPE_LABEL_MAX_BYTES) {
    throw new Error(`A scope label is at most ${SCOPE_LABEL_MAX_BYTES} bytes, and this one is ${bytes.length}`)
  }
  return bytes
}

/**
 * The viewing key for one scope.
 *
 * The label's length goes into the hash before the label does. Without it, the labels "2026" and
 * "09" concatenated would hash the same as "202609", and two scopes a holder believes are separate
 * would be one key. That is the ordinary length-extension trap and it costs one byte to close.
 */
export function scopedViewingKey(masterViewingPrivateKey: Uint8Array, label: string): Uint8Array {
  if (masterViewingPrivateKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`A viewing key is ${SECRET_KEY_BYTES} bytes`)
  }
  const bytes = scopeLabelBytes(label)

  const scalar =
    bytesToNumberBE(
      keccak_256(new Uint8Array([...TAG, ...masterViewingPrivateKey, bytes.length, ...bytes])),
    ) % CURVE_ORDER

  /* Astronomically unlikely and still refused: a zero scalar has no public key to derive against. */
  if (scalar === 0n) throw new Error('That label derived a zero scalar, which cannot be used')
  return scalarToPrivateKey(scalar)
}

/** The scope itself: its label and the key pair that reads it. */
export function deriveScope(keys: StealthKeys, label: string): Scope {
  const viewingPrivateKey = scopedViewingKey(keys.viewing.privateKey, label)
  return {
    label: label.trim(),
    viewingPrivateKey,
    viewingPublicKey: secp256k1.getPublicKey(viewingPrivateKey, true),
  }
}

/**
 * The wallet as it behaves inside one scope.
 *
 * The spending half is untouched: the same keys, so the same ability to move what arrives. Only
 * the viewing half is swapped, which is what makes every existing derivation work unchanged
 * against a scope without a second implementation of any of it.
 */
export function keysForScope(keys: StealthKeys, label: string): StealthKeys {
  const scope = deriveScope(keys, label)
  return {
    spending: keys.spending,
    viewing: { privateKey: scope.viewingPrivateKey, publicKey: scope.viewingPublicKey },
    /* Deliberately the wallet's own meta-address. A scope is a disclosure boundary, not a second
     * identity, and minting a meta-address per scope would invite publishing one, which would
     * turn a private boundary into a public marker. */
    metaAddress: keys.metaAddress,
  }
}
