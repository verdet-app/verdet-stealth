/**
 * Key material handling.
 *
 * Key generation delegates to the audited library's own secret-key generator rather than drawing
 * raw bytes and hoping they land in range.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { bytesToNumberBE, bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { encodeMetaAddress } from './meta-address.js'

export const SECRET_KEY_BYTES = 32

export interface StealthKeyPair {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
}

export interface StealthKeys {
  /** Moves funds. Never leaves the device. */
  readonly spending: StealthKeyPair
  /** Finds incoming payments. Can be delegated to a scanner without granting the ability to spend. */
  readonly viewing: StealthKeyPair
  readonly metaAddress: string
}

function keyPairFrom(privateKey: Uint8Array): StealthKeyPair {
  if (privateKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`A secret key must be ${SECRET_KEY_BYTES} bytes`)
  }
  if (!secp256k1.utils.isValidSecretKey(privateKey)) {
    throw new Error('Secret key is out of range for secp256k1')
  }
  return { privateKey, publicKey: secp256k1.getPublicKey(privateKey, true) }
}

export function generateStealthKeys(): StealthKeys {
  return keysFromPrivate(
    secp256k1.utils.randomSecretKey(),
    secp256k1.utils.randomSecretKey(),
  )
}

export function keysFromPrivate(
  spendingPrivateKey: Uint8Array,
  viewingPrivateKey: Uint8Array,
): StealthKeys {
  const spending = keyPairFrom(spendingPrivateKey)
  const viewing = keyPairFrom(viewingPrivateKey)
  return {
    spending,
    viewing,
    metaAddress: encodeMetaAddress({
      spendingPublicKey: spending.publicKey,
      viewingPublicKey: viewing.publicKey,
    }),
  }
}

export function toScalar(privateKey: Uint8Array): bigint {
  return bytesToNumberBE(privateKey)
}

export function scalarToPrivateKey(scalar: bigint): Uint8Array {
  const hex = scalar.toString(16).padStart(SECRET_KEY_BYTES * 2, '0')
  return hexToBytes(hex)
}

export function privateKeyToHex(privateKey: Uint8Array): string {
  return `0x${bytesToHex(privateKey)}`
}
