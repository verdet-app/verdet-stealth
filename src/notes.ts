/**
 * Labels on requests, kept as ciphertext on the device.
 *
 * ## Why a request needs a label at all
 *
 * The wallet hands out request 0, request 1, request 2. That is enough to find the money and not
 * enough to run a business: nobody reconciles a bank statement that says "account 7". "Invoice
 * 1042" beside request 7 is the difference between a list of numbers and a record somebody can
 * actually use.
 *
 * ## Why it is encrypted when it never leaves the device
 *
 * Because the wallet beside it is. `vault.ts` wraps the keys so a stolen laptop or a synced
 * profile finds ciphertext, and a plaintext file reading "Invoice 1042, Acme Corp, 14 March"
 * sitting next to it would hand back most of what the wrapping was protecting. A store that is
 * encrypted in one half and clear in the other is protected by neither.
 *
 * ## The key, and why there is no second passphrase
 *
 * Derived from the viewing key rather than from anything typed. A second passphrase would be a
 * second thing to lose, and losing it would cost the labels while the money stayed safe, which is
 * a bad trade for both. Deriving from the viewing key means **the labels open exactly when the
 * wallet opens and are ciphertext whenever it is locked**, with nothing extra to remember.
 *
 * The viewing key is 32 bytes of key material, not a passphrase, so there is nothing to stretch:
 * PBKDF2 exists to make guessing slow, and nobody guesses a 256-bit secret. The tag is there so
 * the label key and any future use of the viewing key cannot be the same bytes.
 *
 * ## What this means for a watch key
 *
 * A watch key carries the viewing key, so its holder can derive this label key. They still need
 * the stored blob, which never leaves the device, so in practice handing over a watch key does
 * not hand over the labels. Handing over a watch key **and** a copy of this browser's storage
 * does. `components/watch-only.tsx` says so where the grant is made.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'

const TAG = new TextEncoder().encode('verdet/notes/v1')

/** Long enough for an invoice number and a name, short enough that this is not a filing cabinet. */
export const NOTE_MAX_LENGTH = 120

/** A label per request, and a wallet that has handed out more than this has outgrown a browser tab. */
export const NOTES_MAX = 512

/** The stored form. No salt: the key is the viewing key, which is already unique to the wallet. */
export interface NoteBlob {
  readonly v: 1
  /** Base64. Fresh per write. Reusing one with the same key breaks GCM completely. */
  readonly iv: string
  readonly ct: string
}

/** Request index to label. Absent means no label, which is the ordinary case. */
export type Notes = Readonly<Record<string, string>>

const encoder = new TextEncoder()
const decoder = new TextDecoder()

interface Subtle {
  importKey(format: 'raw', data: Uint8Array, algorithm: object, extractable: boolean, usages: readonly string[]): Promise<unknown>
  encrypt(algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer>
  decrypt(algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer>
}

function subtle(): Subtle {
  const api = (globalThis as { crypto?: { subtle?: unknown } }).crypto?.subtle
  if (!api) throw new Error('WebCrypto is unavailable, so labels cannot be read here')
  return api as Subtle
}

function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

async function noteKey(viewingPrivateKey: Uint8Array): Promise<unknown> {
  if (viewingPrivateKey.length !== 32) throw new Error('A viewing key is 32 bytes')
  const material = keccak_256(new Uint8Array([...TAG, ...viewingPrivateKey]))
  return subtle().importKey('raw', material, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

/**
 * Refuse a label rather than truncate it.
 *
 * A silently shortened label is worse than a rejected one: the holder writes "Invoice 1042, March
 * retainer, Acme" and later reads something that stops mid-word and means something else.
 */
export function checkNotes(notes: Notes): void {
  const entries = Object.entries(notes)
  if (entries.length > NOTES_MAX) throw new Error(`A wallet holds at most ${NOTES_MAX} labels`)
  for (const [index, label] of entries) {
    if (!/^\d+$/.test(index)) throw new Error('A label is keyed by a request index')
    if (label.length > NOTE_MAX_LENGTH) {
      throw new Error(`A label is at most ${NOTE_MAX_LENGTH} characters, and this one is ${label.length}`)
    }
  }
}

export async function sealNotes(notes: Notes, viewingPrivateKey: Uint8Array): Promise<NoteBlob> {
  checkNotes(notes)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await noteKey(viewingPrivateKey)
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(notes)))
  return { v: 1, iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)) }
}

/**
 * Open a blob, or return an empty set.
 *
 * Null would make every caller handle a case that has one sensible answer. A blob written by a
 * different wallet, or a damaged one, means this wallet has no labels, and that is what an empty
 * set says. It never throws, because a label failing to open must not stop a wallet showing a
 * balance.
 */
export async function openNotes(blob: NoteBlob, viewingPrivateKey: Uint8Array): Promise<Notes> {
  try {
    if (blob.v !== 1) return {}
    const key = await noteKey(viewingPrivateKey)
    const plain = await subtle().decrypt({ name: 'AES-GCM', iv: fromBase64(blob.iv) }, key, fromBase64(blob.ct))
    const parsed: unknown = JSON.parse(decoder.decode(plain))
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return {}

    /* Trust the ciphertext for authenticity and still check the shape. GCM proves this wallet
     * wrote it; it does not prove an older build wrote it in the shape this one expects. */
    const out: Record<string, string> = {}
    for (const [index, label] of Object.entries(parsed as Record<string, unknown>)) {
      if (/^\d+$/.test(index) && typeof label === 'string' && label.length <= NOTE_MAX_LENGTH) {
        out[index] = label
      }
    }
    return out
  } catch {
    /* GCM's tag check fails for another wallet's blob, which is the authentication working. */
    return {}
  }
}
