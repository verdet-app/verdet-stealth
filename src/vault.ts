/**
 * Wrapping a key pair with a passphrase, so a wallet can be closed and opened again.
 *
 * Until this existed the product had no returning user: the keys lived in one tab and died with
 * it, and a meta-address whose keys are gone receives payments nobody can ever spend. That is not
 * a rough edge, it is the difference between a demonstration and a wallet.
 *
 * ## What this protects against, and what it does not
 *
 * Stated first because the honest version is narrower than the one a reader assumes.
 *
 * **It protects against somebody who gets the stored blob.** A stolen laptop, a synced profile, a
 * backup, someone reading the browser's storage later. Without the passphrase the blob is
 * ciphertext.
 *
 * **It does not protect against a script running on the page.** Anything with script access to
 * this origin can read the ciphertext and can also read the passphrase as it is typed, so the
 * wrapping buys nothing against that adversary. Only a separate process does, which is the actual
 * argument for a wallet extension and the reason the roadmap still has one. Anyone describing
 * this store as protection against a compromised page is wrong, and `lib/features.ts` 10 has been
 * corrected to say so.
 *
 * ## The construction, and why each part
 *
 * PBKDF2-HMAC-SHA-256 to stretch the passphrase, then AES-256-GCM to wrap. Both come from
 * WebCrypto, so **no dependency is added to handle keys**, which `RULES.md` section 6 asks for
 * directly. Argon2id would be the better stretch and the platform does not offer it; adding a
 * wasm implementation to get it would mean shipping somebody else's compiled binary into the one
 * code path that touches a private key, and that trade is not worth making here.
 *
 * The iteration count is high enough to be felt. That is deliberate: a passphrase a person can
 * remember is weak, and the only thing standing between it and an offline guessing attack is how
 * long each guess takes.
 */

import { keysFromPrivate, type StealthKeys } from './keys.js'
import { hexToBytesLoose } from './abi.js'

/** OWASP's floor for PBKDF2-HMAC-SHA-256 at the time of writing. Costs roughly a second. */
export const VAULT_ITERATIONS = 600_000

/**
 * The stored form. Everything needed to open it except the passphrase.
 *
 * The salt and the iteration count travel with the blob rather than being constants in the code,
 * so raising the cost later does not lock anyone out of a wallet wrapped under the old one.
 */
export interface VaultBlob {
  readonly v: 1
  /** Base64. Fresh per wrap, so the same passphrase never derives the same key twice. */
  readonly salt: string
  /** Base64. Fresh per wrap. Reusing one with the same key breaks GCM completely. */
  readonly iv: string
  readonly ct: string
  readonly iter: number
}

const encoder = new TextEncoder()
const decoder = new TextDecoder()

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

/**
 * The slice of WebCrypto this uses, described here rather than imported.
 *
 * The package deliberately does not pull in DOM types: it has to compile the same way for a
 * browser and for Node, and `SubtleCrypto` is a DOM name that does not exist in a Node-only
 * type environment. Four methods is the whole surface, so describing them costs less than
 * widening the package's type dependencies to get them.
 */
interface Subtle {
  importKey(format: 'raw', data: Uint8Array, algorithm: string, extractable: boolean, usages: readonly string[]): Promise<unknown>
  deriveKey(algorithm: object, base: unknown, derived: object, extractable: boolean, usages: readonly string[]): Promise<unknown>
  encrypt(algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer>
  decrypt(algorithm: object, key: unknown, data: Uint8Array): Promise<ArrayBuffer>
}

function subtle(): Subtle {
  const api = (globalThis as { crypto?: { subtle?: unknown } }).crypto?.subtle
  if (!api) throw new Error('WebCrypto is unavailable, so a wallet cannot be wrapped here')
  return api as Subtle
}

async function deriveKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<unknown> {
  const material = await subtle().importKey('raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    /** Not extractable. Nothing in this module ever needs the wrapping key as bytes. */
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Only the two private keys are stored. Everything else is derived from them on open. */
interface Plaintext {
  readonly spending: string
  readonly viewing: string
}

const hex = (bytes: Uint8Array): string =>
  `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`

export async function lockKeys(keys: StealthKeys, passphrase: string): Promise<VaultBlob> {
  if (passphrase.length < 8) throw new Error('A passphrase shorter than eight characters is not worth wrapping with')

  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await deriveKey(passphrase, salt, VAULT_ITERATIONS)

  const plaintext: Plaintext = {
    spending: hex(keys.spending.privateKey),
    viewing: hex(keys.viewing.privateKey),
  }
  const ct = await subtle().encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(JSON.stringify(plaintext)))

  return { v: 1, salt: toBase64(salt), iv: toBase64(iv), ct: toBase64(new Uint8Array(ct)), iter: VAULT_ITERATIONS }
}

/**
 * Open a blob, or return null.
 *
 * **A wrong passphrase returns null rather than throwing**, because it is the ordinary case and
 * not an error: people mistype. A malformed blob returns null too. The caller cannot tell the two
 * apart, and should not be able to: "wrong passphrase" and "this is not a wallet" are the same
 * answer to whoever is trying passphrases.
 */
export async function unlockKeys(blob: VaultBlob, passphrase: string): Promise<StealthKeys | null> {
  try {
    if (blob.v !== 1) return null
    const key = await deriveKey(passphrase, fromBase64(blob.salt), blob.iter)
    const plain = await subtle().decrypt({ name: 'AES-GCM', iv: fromBase64(blob.iv) }, key, fromBase64(blob.ct))
    const parsed = JSON.parse(decoder.decode(plain)) as Plaintext
    return keysFromPrivate(hexToBytesLoose(parsed.spending), hexToBytesLoose(parsed.viewing))
  } catch {
    /* GCM's tag check fails on a wrong passphrase, which is the authentication doing its job. */
    return null
  }
}
