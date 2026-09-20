/**
 * The ERC-6538 registry, as calldata.
 *
 * Two calls and nothing else: `registerKeys(uint256,bytes)`, which publishes a meta-address under
 * the sender's own address, and `stealthMetaAddressOf(address,uint256)`, which reads one back.
 * Encoding is the little ABI in `abi.ts`.
 */

import { bytesToHex } from '@noble/curves/utils.js'

import { addressWord, bytesTail, concat, hexToBytesLoose, readBytes, selector, word, WORD } from './abi.js'
import { decodeMetaAddress, encodeMetaAddress, META_ADDRESS_BYTES, SCHEME_ID } from './meta-address.js'

export const REGISTER_KEYS_SELECTOR = selector('registerKeys(uint256,bytes)')
export const STEALTH_META_ADDRESS_OF_SELECTOR = selector('stealthMetaAddressOf(address,uint256)')

/**
 * Calldata for `registerKeys(SCHEME_ID, metaAddressBytes)`.
 *
 * Layout, per the ABI: selector, then the scheme id, then the offset of the dynamic argument (one
 * static word after it, so 0x40), then the byte length (66), then the 66 bytes padded to a whole
 * number of words. 196 bytes in all, every time, because every meta-address is the same length.
 */
export function encodeRegisterKeys(metaAddress: string): string {
  const { spendingPublicKey, viewingPublicKey } = decodeMetaAddress(metaAddress)
  const payload = concat(spendingPublicKey, viewingPublicKey)
  return `0x${bytesToHex(concat(REGISTER_KEYS_SELECTOR, word(SCHEME_ID), word(2 * WORD), bytesTail(payload)))}`
}

/** Calldata for `stealthMetaAddressOf(registrant, SCHEME_ID)`. */
export function encodeStealthMetaAddressOf(registrant: string): string {
  return `0x${bytesToHex(concat(STEALTH_META_ADDRESS_OF_SELECTOR, addressWord(registrant), word(SCHEME_ID)))}`
}

/**
 * The meta-address a `stealthMetaAddressOf` call returned, or `null` when nothing is registered.
 *
 * An unregistered address returns a length of zero, which is reported as `null` rather than as an
 * empty string so a caller cannot mistake it for a registered but blank entry.
 */
export function decodeStealthMetaAddressOf(returnData: string): string | null {
  const bytes = hexToBytesLoose(returnData)
  if (bytes.length < WORD * 2) return null
  const payload = readBytes(bytes, 0)
  if (payload === null) return null
  if (payload.length !== META_ADDRESS_BYTES) {
    throw new Error(`Registry returned ${payload.length} bytes, expected ${META_ADDRESS_BYTES}`)
  }
  return encodeMetaAddress({
    spendingPublicKey: payload.subarray(0, META_ADDRESS_BYTES / 2),
    viewingPublicKey: payload.subarray(META_ADDRESS_BYTES / 2),
  })
}
