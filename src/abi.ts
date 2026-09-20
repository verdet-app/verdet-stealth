/**
 * The little ABI: words, addresses, dynamic bytes, selectors.
 *
 * Shared by the registry and the announcer encoders. It is serialisation, not cryptography; the
 * only hash is the four-byte selector, from the same keccak the address derivation uses. Written
 * out rather than pulled from a library because the whole surface is a few words and the calldata
 * it produces is shown to the user to send by hand, so a reader should be able to follow how it was
 * made in one screen.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { hexToBytes } from '@noble/curves/utils.js'

export const WORD = 32

export function selector(signature: string): Uint8Array {
  return keccak_256(new TextEncoder().encode(signature)).subarray(0, 4)
}

export function eventTopic(signature: string): string {
  return `0x${Array.from(keccak_256(new TextEncoder().encode(signature)), (b) => b.toString(16).padStart(2, '0')).join('')}`
}

/** A number as a 32-byte big-endian word. */
export function word(value: number | bigint): Uint8Array {
  const out = new Uint8Array(WORD)
  let n = BigInt(value)
  for (let i = WORD - 1; i >= 0 && n > 0n; i -= 1) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/** A 20-byte address left-padded into a word. */
export function addressWord(address: string): Uint8Array {
  const hex = address.startsWith('0x') ? address.slice(2) : address
  if (!/^[0-9a-fA-F]{40}$/.test(hex)) throw new Error('Address must be 20 bytes of hex')
  const out = new Uint8Array(WORD)
  out.set(hexToBytes(hex.toLowerCase()), WORD - 20)
  return out
}

/** Dynamic `bytes` as a tail: the length word, then the payload padded to whole words. */
export function bytesTail(payload: Uint8Array): Uint8Array {
  const padded = new Uint8Array(WORD + Math.ceil(payload.length / WORD) * WORD)
  padded.set(word(payload.length))
  padded.set(payload, WORD)
  return padded
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export function readWord(bytes: Uint8Array, at: number): bigint {
  let n = 0n
  for (let i = 0; i < WORD; i += 1) n = (n << 8n) | BigInt(bytes[at + i] ?? 0)
  return n
}

/** The dynamic `bytes` whose offset word sits at `slot` in `bytes`, or `null` when it is empty. */
export function readBytes(bytes: Uint8Array, slot: number): Uint8Array | null {
  const offset = Number(readWord(bytes, slot))
  const length = Number(readWord(bytes, offset))
  if (length === 0) return null
  const start = offset + WORD
  if (start + length > bytes.length) throw new Error('Dynamic bytes run past the end of the data')
  return bytes.subarray(start, start + length)
}

/** The low 20 bytes of a word, as a checksum-free lowercase address. */
export function wordToAddress(wordBytes: Uint8Array): string {
  return `0x${Array.from(wordBytes.subarray(WORD - 20), (b) => b.toString(16).padStart(2, '0')).join('')}`
}

export function hexToBytesLoose(hex: string): Uint8Array {
  const body = hex.startsWith('0x') ? hex.slice(2) : hex
  return body.length === 0 ? new Uint8Array(0) : hexToBytes(body.toLowerCase())
}
