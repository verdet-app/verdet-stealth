/**
 * Meta-address encoding, the one string a recipient publishes.
 *
 * It is two compressed public keys concatenated: spending first, viewing second. The pair is
 * deliberately separate. A viewing key can be handed to a scanner so it can find incoming payments
 * without ever being able to spend them.
 */

import { bytesToHex, hexToBytes, concatBytes } from '@noble/curves/utils.js'

/** ERC-5564 scheme 1: secp256k1 with view tags. */
export const SCHEME_ID = 1

export const COMPRESSED_KEY_BYTES = 33
export const META_ADDRESS_BYTES = COMPRESSED_KEY_BYTES * 2

const PREFIX = 'st:eth:'

export interface MetaAddressKeys {
  readonly spendingPublicKey: Uint8Array
  readonly viewingPublicKey: Uint8Array
}

export function encodeMetaAddress(keys: MetaAddressKeys): string {
  assertCompressed(keys.spendingPublicKey, 'spending')
  assertCompressed(keys.viewingPublicKey, 'viewing')
  const packed = concatBytes(keys.spendingPublicKey, keys.viewingPublicKey)
  return `${PREFIX}0x${bytesToHex(packed)}`
}

export function decodeMetaAddress(metaAddress: string): MetaAddressKeys {
  const trimmed = metaAddress.trim()
  if (!trimmed.startsWith(PREFIX)) {
    throw new Error(`Meta-address must start with "${PREFIX}"`)
  }

  const body = trimmed.slice(PREFIX.length)
  const hex = body.startsWith('0x') ? body.slice(2) : body
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Meta-address payload is not hex')
  }

  const bytes = hexToBytes(hex.toLowerCase())
  if (bytes.length !== META_ADDRESS_BYTES) {
    throw new Error(`Meta-address payload must be ${META_ADDRESS_BYTES} bytes, got ${bytes.length}`)
  }

  const spendingPublicKey = bytes.subarray(0, COMPRESSED_KEY_BYTES)
  const viewingPublicKey = bytes.subarray(COMPRESSED_KEY_BYTES)
  assertCompressed(spendingPublicKey, 'spending')
  assertCompressed(viewingPublicKey, 'viewing')

  return { spendingPublicKey, viewingPublicKey }
}

function assertCompressed(key: Uint8Array, label: string): void {
  if (key.length !== COMPRESSED_KEY_BYTES) {
    throw new Error(`The ${label} public key must be ${COMPRESSED_KEY_BYTES} bytes`)
  }
  const prefix = key[0]
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error(`The ${label} public key must be compressed, with a 0x02 or 0x03 prefix`)
  }
}
