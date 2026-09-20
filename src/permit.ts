/**
 * Moving an asset out of a stealth address, without that address ever sending a transaction.
 *
 * A stealth address receives a token and holds no gas, because it was never funded: that is the
 * whole point of it. An address with no gas cannot send anything, so the asset moves on somebody
 * else's transaction, authorised by one signature from the key that owns it.
 *
 * `docs/SWEEP-SPEC.md` is the full specification. Two things from it are load bearing here.
 *
 * **It is two transactions, not one.** An externally owned account carries one destination and one
 * calldata per transaction, so it makes one call. `permit` and `transferFrom` are two calls. They
 * live on the same contract, which is what made the error easy to miss for as long as it stood in
 * the architecture, and a token without a batching entry point cannot run both from one EOA
 * transaction.
 *
 * **Nobody ever holds the asset.** `transferFrom` moves it from the stealth address to the
 * destination in one step. There is no intermediate balance and no moment of custody, which is
 * what makes this shape defensible rather than merely convenient.
 *
 * ## What this module does and does not do
 *
 * It builds and signs. It does not send, does not choose a destination, and does not know whether
 * anybody will submit what it produces. The calldata it returns is the same calldata whether a
 * relay sends it or the holder sends it from any funded address they already have, which is why
 * the self-service path needs no relay to exist.
 */

import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'

import { addressWord, concat, hexToBytesLoose, selector, word } from './abi.js'
import { publicKeyToAddress, type Address } from './address.js'

/** `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` */
const PERMIT = selector('permit(address,address,uint256,uint256,uint8,bytes32,bytes32)')
/** `transferFrom(address,address,uint256)` */
const TRANSFER_FROM = selector('transferFrom(address,address,uint256)')

/** `nonces(address)` and `DOMAIN_SEPARATOR()`, the two reads a permit needs. */
export const NONCES = selector('nonces(address)')
export const DOMAIN_SEPARATOR = selector('DOMAIN_SEPARATOR()')

export function encodeNoncesCall(owner: Address): string {
  return `0x${bytesToHex(concat(NONCES, addressWord(owner)))}`
}

export function encodeDomainSeparatorCall(): string {
  return `0x${bytesToHex(DOMAIN_SEPARATOR)}`
}

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

/**
 * The EIP-2612 type hash, fixed by the standard.
 *
 * `keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")`.
 * Computed rather than pasted, so a typo in the string fails a test instead of producing a
 * signature no token will accept.
 */
const PERMIT_TYPEHASH = keccak_256(
  new TextEncoder().encode('Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)'),
)

export interface PermitTerms {
  /** The stealth address that holds the asset. */
  readonly owner: Address
  /** Who will be allowed to move it. Only this address can then call `transferFrom`. */
  readonly spender: Address
  readonly value: bigint
  readonly nonce: bigint
  /** Unix seconds. Short, because a signed permit is a bearer instrument until it expires. */
  readonly deadline: bigint
  /** Read from the token with `DOMAIN_SEPARATOR()`. Binds the signature to one token on one chain. */
  readonly domainSeparator: string
}

/**
 * The digest a token will check the signature against.
 *
 * `0x1901` then the domain separator then the struct hash, which is EIP-712's envelope. The prefix
 * is what stops a signature made for one purpose being replayed as another, so it is not optional
 * and not cosmetic.
 */
export function permitDigest(terms: PermitTerms): Uint8Array {
  const structHash = keccak_256(
    concat(
      PERMIT_TYPEHASH,
      addressWord(terms.owner),
      addressWord(terms.spender),
      word(terms.value),
      word(terms.nonce),
      word(terms.deadline),
    ),
  )
  const separator = hexToBytesLoose(terms.domainSeparator)
  if (separator.length !== 32) throw new Error('A domain separator is 32 bytes')

  return keccak_256(concat(new Uint8Array([0x19, 0x01]), separator, structHash))
}

export interface SignedPermit {
  readonly v: number
  readonly r: string
  readonly s: string
  readonly digest: string
}

/**
 * Sign the digest with the stealth address's own spending key.
 *
 * **The key is checked against the address before anything is signed.** A permit signed by the
 * wrong key is not rejected loudly: it recovers to some other address, the token sees an owner
 * who never authorised anything, and the call reverts with nothing useful in it. Failing here,
 * with a sentence, costs one comparison.
 *
 * `lowS` is on, which Ethereum requires: the other half of each signature pair is malleable and
 * many contracts refuse it.
 */
export function signPermit(digest: Uint8Array, privateKey: Uint8Array, owner: Address): SignedPermit {
  const derived = publicKeyToAddress(secp256k1.getPublicKey(privateKey, false))
  if (derived.toLowerCase() !== owner.toLowerCase()) {
    throw new Error(`This key controls ${derived}, not ${owner}. Signing would authorise nothing.`)
  }

  /* The recovered format is 65 bytes: the recovery id, then r, then s. The digest is already a
   * hash, so `prehash` stays off; hashing it again would sign the wrong thing. */
  const signature = secp256k1.sign(digest, privateKey, { prehash: false, lowS: true, format: 'recovered' })

  return {
    /* 27 is the offset Ethereum applies to the recovery id. */
    v: 27 + (signature[0] as number),
    r: `0x${bytesToHex(signature.subarray(1, 33))}`,
    s: `0x${bytesToHex(signature.subarray(33, 65))}`,
    digest: `0x${bytesToHex(digest)}`,
  }
}

export interface SweepCalls {
  /** Anyone may send this. It only proves a signature and sets an allowance. */
  readonly permit: string
  /** Only `spender` may send this. It moves the asset owner to destination, in one step. */
  readonly transfer: string
  /** Both go to the token contract. */
  readonly to: Address
}

/**
 * The two calls, in the order they have to happen.
 *
 * The permit sets the allowance; the transfer spends it. Sending them out of order fails, and
 * sending them in one transaction is not possible from an ordinary account, which is the whole of
 * why this returns two strings rather than one.
 */
export function encodeSweep(
  token: Address,
  terms: PermitTerms,
  signed: SignedPermit,
  destination: Address,
): SweepCalls {
  const permit = concat(
    PERMIT,
    addressWord(terms.owner),
    addressWord(terms.spender),
    word(terms.value),
    word(terms.deadline),
    word(BigInt(signed.v)),
    hexToBytesLoose(signed.r),
    hexToBytesLoose(signed.s),
  )
  const transfer = concat(TRANSFER_FROM, addressWord(terms.owner), addressWord(destination), word(terms.value))

  return { permit: `0x${bytesToHex(permit)}`, transfer: `0x${bytesToHex(transfer)}`, to: token }
}
