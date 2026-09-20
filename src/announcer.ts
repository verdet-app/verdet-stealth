/**
 * The ERC-5564 announcer, as calldata and as logs.
 *
 * A payer derives a stealth address for the recipient, sends the asset to it, and calls
 * `announce(schemeId, stealthAddress, ephemeralPubKey, metadata)` so the recipient's scanner can
 * find it. For scheme 1 the metadata's first byte is the view tag, which is what lets a scanner
 * reject almost every announcement on one byte before doing any curve work.
 *
 * `decodeAnnouncementLog` turns one raw log from `eth_getLogs` into the candidate the scanner
 * checks. Anything that is not a well-formed scheme-1 announcement decodes to `null` rather than
 * throwing, because a scan over a public event stream will meet announcements from other schemes
 * and from other people's mistakes, and neither should stop it.
 */

import { bytesToHex } from '@noble/curves/utils.js'

import {
  addressWord, bytesTail, concat, eventTopic, hexToBytesLoose, readBytes, readWord, selector, word, wordToAddress, WORD,
} from './abi.js'
import { COMPRESSED_KEY_BYTES, SCHEME_ID } from './meta-address.js'

export const ANNOUNCE_SELECTOR = selector('announce(uint256,address,bytes,bytes)')
export const ANNOUNCEMENT_TOPIC = eventTopic('Announcement(uint256,address,address,bytes,bytes)')

export interface AnnounceInput {
  readonly stealthAddress: string
  readonly ephemeralPublicKey: Uint8Array
  readonly viewTag: number
}

/**
 * Calldata for `announce(SCHEME_ID, stealthAddress, ephemeralPubKey, [viewTag])`.
 *
 * Four head words (scheme id, address, offset of the first bytes, offset of the second), then the
 * two tails. The ephemeral key is 33 bytes, so its tail is a length word and two payload words;
 * the metadata is one byte, so its tail is a length word and one payload word. 292 bytes, always.
 */
export function encodeAnnounce(input: AnnounceInput): string {
  if (input.ephemeralPublicKey.length !== COMPRESSED_KEY_BYTES) {
    throw new Error(`The ephemeral public key must be ${COMPRESSED_KEY_BYTES} bytes`)
  }
  if (!Number.isInteger(input.viewTag) || input.viewTag < 0 || input.viewTag > 255) {
    throw new Error('The view tag is one byte')
  }
  const ephemeral = bytesTail(input.ephemeralPublicKey)
  const metadata = bytesTail(new Uint8Array([input.viewTag]))
  const head = concat(word(SCHEME_ID), addressWord(input.stealthAddress), word(4 * WORD), word(4 * WORD + ephemeral.length))
  return `0x${bytesToHex(concat(ANNOUNCE_SELECTOR, head, ephemeral, metadata))}`
}

export interface RawLog {
  readonly topics: readonly string[]
  readonly data: string
  readonly blockNumber?: string
  readonly transactionHash?: string
}

export interface DecodedAnnouncement {
  readonly schemeId: number
  readonly stealthAddress: string
  readonly caller: string
  readonly ephemeralPublicKey: Uint8Array
  readonly viewTag: number
  readonly blockNumber: number | null
  readonly transactionHash: string | null
}

/** One log from the announcer as a scan candidate, or `null` if it is not a scheme-1 announcement. */
export function decodeAnnouncementLog(log: RawLog): DecodedAnnouncement | null {
  /* Everything below can throw on a malformed log: an odd-length topic, data that is not hex, a
   * length word past the end. A public event stream will contain all of those eventually, and none
   * of them is this scanner's problem, so the whole parse answers null instead of throwing. */
  try {
    if (log.topics.length !== 4 || log.topics[0]?.toLowerCase() !== ANNOUNCEMENT_TOPIC) return null

    const schemeId = Number(readWord(hexToBytesLoose(log.topics[1] ?? ''), 0))
    if (schemeId !== SCHEME_ID) return null

    const data = hexToBytesLoose(log.data)
    if (data.length < WORD * 2) return null

    const ephemeralPublicKey = readBytes(data, 0)
    const metadata = readBytes(data, WORD)
    if (!ephemeralPublicKey || ephemeralPublicKey.length !== COMPRESSED_KEY_BYTES) return null
    if (!metadata || metadata.length < 1) return null

    return {
      schemeId,
      stealthAddress: wordToAddress(hexToBytesLoose(log.topics[2] ?? '')),
      caller: wordToAddress(hexToBytesLoose(log.topics[3] ?? '')),
      ephemeralPublicKey,
      viewTag: metadata[0] as number,
      blockNumber: log.blockNumber ? Number.parseInt(log.blockNumber, 16) : null,
      transactionHash: log.transactionHash ?? null,
    }
  } catch {
    return null
  }
}
