/**
 * The two operations a stealth payment consists of: the sender creating one, and the recipient
 * recognising it.
 *
 * Both sides carry the same warning, and the product surfaces it rather than burying it: a stealth
 * address hides the link between a public identity and the address that received an asset. It does
 * not hide the amount, the timing, or the sender. Funding one of these addresses from a wallet that
 * is already linked to the recipient undoes the entire construction.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { deriveSharedSecret, deriveStealthPrivateScalar, stealthAddressFrom } from './derive.js'
import { decodeMetaAddress, SCHEME_ID } from './meta-address.js'
import { scalarToPrivateKey, toScalar, type StealthKeys } from './keys.js'
import type { Address } from './address.js'

export interface StealthPayment {
  readonly schemeId: number
  /** Where the sender sends the asset. */
  readonly stealthAddress: Address
  /** Published in the announcement so the recipient can complete the exchange. Compressed. */
  readonly ephemeralPublicKey: Uint8Array
  /** Published in the announcement. Lets a scanner reject almost everything cheaply. */
  readonly viewTag: number
}

/** Sender side. Produces a fresh one-time address for a recipient's published meta-address. */
export function createStealthPayment(metaAddress: string): StealthPayment {
  const { spendingPublicKey, viewingPublicKey } = decodeMetaAddress(metaAddress)

  const ephemeralPrivateKey = secp256k1.utils.randomSecretKey()
  const secret = deriveSharedSecret(toScalar(ephemeralPrivateKey), viewingPublicKey)

  return {
    schemeId: SCHEME_ID,
    stealthAddress: stealthAddressFrom(spendingPublicKey, secret.scalar),
    ephemeralPublicKey: secp256k1.getPublicKey(ephemeralPrivateKey, true),
    viewTag: secret.viewTag,
  }
}

export interface AnnouncementCandidate {
  readonly ephemeralPublicKey: Uint8Array
  readonly stealthAddress: string
  /** Omit when the announcement carried no tag; the check then falls back to full derivation. */
  readonly viewTag?: number
}

export interface StealthMatch {
  readonly stealthAddress: Address
  /** The only value that can move the funds at that address. */
  readonly privateKey: Uint8Array
}

/**
 * Recipient side. Returns a match only when the announcement really was for these keys.
 *
 * The view tag is compared first because it is the cheap rejection. Getting that order wrong turns
 * a scan of a day of announcements from seconds into minutes.
 */
export function checkAnnouncement(
  keys: StealthKeys,
  candidate: AnnouncementCandidate,
): StealthMatch | null {
  let secret: ReturnType<typeof deriveSharedSecret>
  try {
    secret = deriveSharedSecret(toScalar(keys.viewing.privateKey), candidate.ephemeralPublicKey)
  } catch {
    /** A malformed ephemeral key is someone else's bad announcement, not our error. */
    return null
  }

  if (candidate.viewTag !== undefined && candidate.viewTag !== secret.viewTag) return null

  const derived = stealthAddressFrom(keys.spending.publicKey, secret.scalar)
  if (derived.toLowerCase() !== candidate.stealthAddress.toLowerCase()) return null

  const scalar = deriveStealthPrivateScalar(toScalar(keys.spending.privateKey), secret.scalar)
  return { stealthAddress: derived, privateKey: scalarToPrivateKey(scalar) }
}
