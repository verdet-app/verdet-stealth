/**
 * Watch-only wallets: seeing everything, moving nothing. And seeing one period, not everything.
 *
 * ## The property this exposes, which the design has had since the first commit
 *
 * Two keys, and they do different jobs. The viewing key finds the money. The spending key moves
 * it. Nothing in the derivation ever needs both at once on the same machine, so a viewing key
 * plus a spending **public** key regenerates every request address a wallet ever handed out and
 * cannot sign a single byte.
 *
 * That is the whole of what an accountant, an auditor, a co-founder or a tax filing needs. Every
 * other wallet answers this with a full export and a promise, and a promise is what a key is for
 * not having to make.
 *
 * ## Two shapes of grant, and the format says which
 *
 * **Unscoped**, version 1: the master viewing key. Everything, forever, including payments that
 * have not arrived yet.
 *
 * **Scoped**, version 2: a viewing key derived for one label, and the label travels with it. One
 * period, one mandate, one counterparty, and nothing outside it. See `scope.ts` for why the
 * one-wayness of that derivation is the whole feature.
 *
 * A holder can always tell which they were handed, because it is a byte in the key rather than a
 * claim in an email. That is the difference between a scope somebody can check and a scope
 * somebody was told about.
 *
 * ## What the holder of a watch key can do, exactly
 *
 * Derive the addresses in their grant, read the balances, reconcile the payments, export the lot.
 * They can also derive addresses of requests not handed out yet, which is a feature rather than a
 * leak: those addresses hold nothing and the payer picks none of them.
 *
 * ## What they cannot do
 *
 * Sign. `deriveStealthPrivateScalar` needs the spending private key and there is no path from the
 * public one, which is the discrete logarithm problem and not a policy we enforce.
 *
 * ## What it still costs
 *
 * A grant cannot be revoked, scoped or not. Handing one over is handing it over, the way a
 * photograph is. Scoping bounds what it covers; it does not make it recallable, and an unscoped
 * key covers the whole future of the wallet.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/curves/utils.js'

import { deriveSharedSecret, stealthAddressFrom } from './derive.js'
import { scalarToPrivateKey, SECRET_KEY_BYTES, type StealthKeys } from './keys.js'
import { COMPRESSED_KEY_BYTES } from './meta-address.js'
import { requestEphemeralScalar } from './request.js'
import { scopedViewingKey, scopeLabelBytes, SCOPE_LABEL_MAX_BYTES } from './scope.js'
import type { Address } from './address.js'

const PREFIX = 'verdet:watch:'

/** The whole wallet's viewing key. Everything, forever. */
const VERSION_UNSCOPED = 0x01
/** One label's viewing key, with the label carried alongside it. */
const VERSION_SCOPED = 0x02

/**
 * Four bytes of keccak over everything before them.
 *
 * Not security: anyone holding the string holds the key. It is there because a watch key that
 * lost a character still decodes to valid-looking bytes, derives valid-looking addresses that
 * belong to nobody, and shows an empty wallet. The holder would read that as "nothing has
 * arrived" and be wrong in the one direction that costs money.
 */
const CHECKSUM_BYTES = 4

const UNSCOPED_BODY_BYTES = 1 + SECRET_KEY_BYTES + COMPRESSED_KEY_BYTES
const UNSCOPED_BYTES = UNSCOPED_BODY_BYTES + CHECKSUM_BYTES

export interface WatchKeys {
  /** Finds the payments. The master key for an unscoped grant, one scope's key for a scoped one. */
  readonly viewingPrivateKey: Uint8Array
  /** Places them. Public, so nothing here can spend. */
  readonly spendingPublicKey: Uint8Array
  /** Present exactly when the grant is scoped, and then it names what it covers. */
  readonly label?: string
}

/** A request address as a watcher sees it: where and which, and no key to move it. */
export interface WatchedRequest {
  readonly index: number
  readonly stealthAddress: Address
  readonly ephemeralPublicKey: Uint8Array
  readonly viewTag: number
}

/** The watching half of a wallet, taken from the whole of one. Unscoped: everything, forever. */
export function watchKeysFrom(keys: StealthKeys): WatchKeys {
  return { viewingPrivateKey: keys.viewing.privateKey, spendingPublicKey: keys.spending.publicKey }
}

/**
 * The watching half of one scope.
 *
 * The spending public key is the wallet's own and is the same in every scope, which is correct:
 * the money is not split across scopes, only the ability to see it is.
 */
export function scopedWatchKeys(keys: StealthKeys, label: string): WatchKeys {
  return {
    viewingPrivateKey: scopedViewingKey(keys.viewing.privateKey, label),
    spendingPublicKey: keys.spending.publicKey,
    label: label.trim(),
  }
}

export function encodeWatchKey(keys: WatchKeys): string {
  if (keys.viewingPrivateKey.length !== SECRET_KEY_BYTES) {
    throw new Error(`A viewing key must be ${SECRET_KEY_BYTES} bytes`)
  }
  assertCompressed(keys.spendingPublicKey)

  const head = keys.label === undefined ? new Uint8Array([VERSION_UNSCOPED]) : new Uint8Array([VERSION_SCOPED])
  const tail =
    keys.label === undefined
      ? new Uint8Array(0)
      : (() => {
          const bytes = scopeLabelBytes(keys.label)
          return concatBytes(new Uint8Array([bytes.length]), bytes)
        })()

  const body = concatBytes(head, keys.viewingPrivateKey, keys.spendingPublicKey, tail)
  return `${PREFIX}0x${bytesToHex(concatBytes(body, keccak_256(body).subarray(0, CHECKSUM_BYTES)))}`
}

export function decodeWatchKey(watchKey: string): WatchKeys {
  const trimmed = watchKey.trim()
  if (!trimmed.startsWith(PREFIX)) throw new Error(`A watch key starts with "${PREFIX}"`)

  const body = trimmed.slice(PREFIX.length)
  const hex = body.startsWith('0x') ? body.slice(2) : body
  if (!/^[0-9a-fA-F]+$/.test(hex)) throw new Error('The watch key payload is not hex')

  const bytes = hexToBytes(hex.toLowerCase())
  if (bytes.length < UNSCOPED_BYTES) {
    throw new Error(`A watch key payload is at least ${UNSCOPED_BYTES} bytes, and this one is ${bytes.length}`)
  }

  const version = bytes[0]
  if (version !== VERSION_UNSCOPED && version !== VERSION_SCOPED) {
    throw new Error(`This watch key is version ${version}, and this build reads versions 1 and 2`)
  }

  /* The body length is decided by the version and, for a scoped key, by the length byte inside it.
   * Both are checked before the checksum, so a corrupted length byte fails as a length rather than
   * as a checksum, which is the more useful message. */
  let bodyBytes = UNSCOPED_BODY_BYTES
  let label: string | undefined

  if (version === VERSION_SCOPED) {
    const labelLength = bytes[UNSCOPED_BODY_BYTES]
    if (labelLength === undefined || labelLength === 0) throw new Error('A scoped watch key carries a label and this one has none')
    if (labelLength > SCOPE_LABEL_MAX_BYTES) {
      throw new Error(`A scope label is at most ${SCOPE_LABEL_MAX_BYTES} bytes, and this one claims ${labelLength}`)
    }
    bodyBytes = UNSCOPED_BODY_BYTES + 1 + labelLength
    label = new TextDecoder().decode(bytes.subarray(UNSCOPED_BODY_BYTES + 1, bodyBytes))
  }

  if (bytes.length !== bodyBytes + CHECKSUM_BYTES) {
    throw new Error(`This watch key should be ${bodyBytes + CHECKSUM_BYTES} bytes and is ${bytes.length}`)
  }

  const payload = bytes.subarray(0, bodyBytes)
  const expected = keccak_256(payload).subarray(0, CHECKSUM_BYTES)
  const given = bytes.subarray(bodyBytes)
  for (let i = 0; i < CHECKSUM_BYTES; i += 1) {
    if (expected[i] !== given[i]) {
      throw new Error('That watch key fails its own checksum, so a character of it is wrong')
    }
  }

  const spendingPublicKey = payload.subarray(1 + SECRET_KEY_BYTES, 1 + SECRET_KEY_BYTES + COMPRESSED_KEY_BYTES)
  assertCompressed(spendingPublicKey)

  const viewingPrivateKey = payload.subarray(1, 1 + SECRET_KEY_BYTES)
  return label === undefined
    ? { viewingPrivateKey, spendingPublicKey }
    : { viewingPrivateKey, spendingPublicKey, label }
}

/**
 * One request address, derived without the ability to spend it.
 *
 * Deliberately the same arithmetic as `deriveRequest`, minus the last line. If the two ever
 * disagree the watcher reconciles against addresses the wallet never used, so a test holds them
 * to the same answer.
 */
export function watchRequest(keys: WatchKeys, index: number): WatchedRequest {
  const ephemeralScalar = requestEphemeralScalar(keys.viewingPrivateKey, index)
  const ephemeralPublicKey = secp256k1.getPublicKey(scalarToPrivateKey(ephemeralScalar), true)

  /* The shared secret needs the viewing *public* key, which is this grant's own and derives from
   * the private one it already holds. */
  const viewingPublicKey = secp256k1.getPublicKey(keys.viewingPrivateKey, true)
  const secret = deriveSharedSecret(ephemeralScalar, viewingPublicKey)

  return {
    index,
    stealthAddress: stealthAddressFrom(keys.spendingPublicKey, secret.scalar),
    ephemeralPublicKey,
    viewTag: secret.viewTag,
  }
}

export function watchRequests(keys: WatchKeys, count: number, from = 0): readonly WatchedRequest[] {
  if (!Number.isInteger(count) || count < 0) throw new Error('A count is a non-negative integer')
  return Array.from({ length: count }, (_, i) => watchRequest(keys, from + i))
}

function assertCompressed(key: Uint8Array): void {
  if (key.length !== COMPRESSED_KEY_BYTES) {
    throw new Error(`A spending public key is ${COMPRESSED_KEY_BYTES} bytes`)
  }
  if (key[0] !== 0x02 && key[0] !== 0x03) {
    throw new Error('A spending public key must be compressed, with a 0x02 or 0x03 prefix')
  }
}
