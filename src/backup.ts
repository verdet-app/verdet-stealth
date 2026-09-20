/**
 * The sheet somebody writes down, and the check that says they wrote it down correctly.
 *
 * ## The failure this is for
 *
 * A wallet that says "write these down" and stops has done half a job. The half it skipped is the
 * one that costs money: a key copied with two characters swapped looks exactly like a key copied
 * correctly, and the holder finds out years later, at the only moment the paper matters, when
 * there is nothing left to compare it against.
 *
 * So the sheet carries a fingerprint per key. Type the keys back in from the paper today and the
 * wallet says whether the paper is right. That is the whole feature: **the error is found while
 * the original is still on screen.**
 *
 * ## Why one fingerprint per key and not one for the pair
 *
 * A single fingerprint over both says "something is wrong" and leaves sixty-four characters to
 * hunt through. One per key says which line to look at, which is the difference between a
 * correction and an afternoon. The pair fingerprint is there too, because it is the one a holder
 * can compare against a wallet already open without typing anything secret.
 *
 * ## What a fingerprint gives away
 *
 * Four bytes of keccak over a tag and the key. Nothing usable: there are 2^224 keys behind any
 * one fingerprint, so it narrows a 256-bit search by nothing that matters. It is printed on the
 * paper and shown on the screen for exactly that reason.
 *
 * It is not a checksum in the error-correcting sense. It detects a wrong transcription and cannot
 * repair one, and no four bytes could.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'

import { SECRET_KEY_BYTES, privateKeyToHex, type StealthKeys } from './keys.js'

const TAG = new TextEncoder().encode('verdet/backup/v1')

/** Four bytes, written as two groups of four uppercase hex characters. */
const FINGERPRINT_BYTES = 4

const HEX_KEY = /^[0-9a-f]{64}$/

export interface BackupSheet {
  readonly spendingKey: string
  readonly viewingKey: string
  readonly metaAddress: string
  readonly spendingFingerprint: string
  readonly viewingFingerprint: string
  /** Over both keys in order, so it identifies the wallet rather than either half. */
  readonly walletFingerprint: string
}

/**
 * Hex, uppercase, in groups of four.
 *
 * Uppercase because it is read off paper, and grouped because a run of eight characters is copied
 * wrong more often than two runs of four. Hex specifically: its alphabet contains no O and no I,
 * so the two substitutions that ruin hand-copied codes cannot arise.
 */
function group(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').toUpperCase()
  return `${hex.slice(0, 4)}-${hex.slice(4)}`
}

export function fingerprint(privateKey: Uint8Array): string {
  if (privateKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`A key to fingerprint is ${SECRET_KEY_BYTES} bytes`)
  }
  return group(keccak_256(new Uint8Array([...TAG, ...privateKey])).subarray(0, FINGERPRINT_BYTES))
}

export function walletFingerprint(keys: StealthKeys): string {
  return group(
    keccak_256(
      new Uint8Array([...TAG, ...keys.spending.privateKey, ...keys.viewing.privateKey]),
    ).subarray(0, FINGERPRINT_BYTES),
  )
}

export function backupSheet(keys: StealthKeys): BackupSheet {
  return {
    spendingKey: privateKeyToHex(keys.spending.privateKey),
    viewingKey: privateKeyToHex(keys.viewing.privateKey),
    metaAddress: keys.metaAddress,
    spendingFingerprint: fingerprint(keys.spending.privateKey),
    viewingFingerprint: fingerprint(keys.viewing.privateKey),
    walletFingerprint: walletFingerprint(keys),
  }
}

/**
 * A key as somebody typed it off paper, or nothing.
 *
 * One parser, used by the check below and by the restore panel, because two cleaners that drift
 * apart is how a key accepted in one place is refused in the other.
 *
 * It tolerates what a person writes and refuses what a person means differently: an `0x` or not,
 * either case, spaces and dashes left over from grouping. It does **not** tolerate a wrong
 * length, because a dropped leading zero would otherwise parse as a valid shorter number and pass
 * as a different, working key.
 */
export function parsePrivateKey(typed: string): Uint8Array | null {
  const hex = typed.trim().replace(/^0[xX]/, '').replace(/[\s-]/g, '').toLowerCase()
  if (!HEX_KEY.test(hex)) return null
  return Uint8Array.from({ length: SECRET_KEY_BYTES }, (_, i) =>
    Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  )
}

export interface TranscriptionResult {
  readonly spendingMatches: boolean
  readonly viewingMatches: boolean
  readonly ok: boolean
}

/**
 * Check what was written on the paper against the wallet on the screen.
 *
 * Takes the typed text rather than parsed keys, because "this is not 32 bytes of hex" is one of
 * the answers the holder needs and throwing it away would turn a wrong line into a crash.
 */
export function checkTranscription(
  keys: StealthKeys,
  typedSpending: string,
  typedViewing: string,
): TranscriptionResult {
  const spendingMatches = sameKey(typedSpending, keys.spending.privateKey)
  const viewingMatches = sameKey(typedViewing, keys.viewing.privateKey)
  return { spendingMatches, viewingMatches, ok: spendingMatches && viewingMatches }
}

function sameKey(typed: string, actual: Uint8Array): boolean {
  const parsed = parsePrivateKey(typed)
  if (!parsed) return false
  /* Constant time is not the concern here: the holder already has both values on screen. */
  return parsed.length === actual.length && parsed.every((byte, i) => byte === actual[i])
}
