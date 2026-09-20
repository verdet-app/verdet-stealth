/**
 * Address encoding.
 *
 * Addresses are the product's notion of identity, never symbols, so the checksum form is produced
 * here once and used everywhere a human will read one.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex } from '@noble/curves/utils.js'

export type Address = `0x${string}`

/**
 * Derive an address from an uncompressed public key.
 *
 * The leading 0x04 tag is dropped before hashing. Including it silently produces a valid-looking
 * address that no counterparty will ever pay.
 */
export function publicKeyToAddress(uncompressedPublicKey: Uint8Array): Address {
  if (uncompressedPublicKey.length !== 65 || uncompressedPublicKey[0] !== 0x04) {
    throw new Error('Expected a 65-byte uncompressed public key with a 0x04 prefix')
  }
  const hashed = keccak_256(uncompressedPublicKey.subarray(1))
  return toChecksumAddress(`0x${bytesToHex(hashed.subarray(12))}`)
}

/** EIP-55 mixed-case checksum. Case is the only error detection an address carries. */
export function toChecksumAddress(address: string): Address {
  const lower = address.toLowerCase()
  if (!/^0x[0-9a-f]{40}$/.test(lower)) {
    throw new Error(`Not a 20-byte hex address: ${address}`)
  }

  const body = lower.slice(2)
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(body)))

  let out = '0x'
  for (let i = 0; i < body.length; i += 1) {
    const char = body[i] as string
    const nibble = Number.parseInt(hash[i] as string, 16)
    out += nibble >= 8 ? char.toUpperCase() : char
  }
  return out as Address
}

export function isChecksumValid(address: string): boolean {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) return false
  return toChecksumAddress(address) === address
}
