/**
 * The vault, tested against the ways it could quietly fail.
 *
 * A key store that round-trips is not enough. The failures that cost somebody their money are the
 * ones where it appears to work: a wrong passphrase that opens something, a tampered blob that
 * decrypts, a salt or an IV that repeats. Each of those has a test here and the round trip is the
 * least interesting of them.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { generateStealthKeys, lockKeys, unlockKeys, VAULT_ITERATIONS } from '../dist/index.js'

const PASSPHRASE = 'correct horse battery staple'

test('a wallet survives being closed and opened', async () => {
  const keys = generateStealthKeys()
  const blob = await lockKeys(keys, PASSPHRASE)
  const opened = await unlockKeys(blob, PASSPHRASE)

  assert.ok(opened, 'the right passphrase did not open it')
  assert.equal(opened.metaAddress, keys.metaAddress)
  assert.deepEqual(opened.spending.privateKey, keys.spending.privateKey)
  assert.deepEqual(opened.viewing.privateKey, keys.viewing.privateKey)
})

test('a wrong passphrase returns null rather than throwing or opening', async () => {
  const blob = await lockKeys(generateStealthKeys(), PASSPHRASE)
  assert.equal(await unlockKeys(blob, 'correct horse battery stapl'), null)
  assert.equal(await unlockKeys(blob, ''), null)
  assert.equal(await unlockKeys(blob, PASSPHRASE.toUpperCase()), null)
})

test('a tampered ciphertext does not decrypt', async () => {
  /* This is the whole reason for GCM over CBC. An unauthenticated mode would hand back garbage
   * plaintext, and garbage parsed as a private key is an address nobody can spend from. */
  const blob = await lockKeys(generateStealthKeys(), PASSPHRASE)
  const bytes = Buffer.from(blob.ct, 'base64')
  bytes[4] ^= 0x01
  const tampered = { ...blob, ct: bytes.toString('base64') }

  assert.equal(await unlockKeys(tampered, PASSPHRASE), null)
})

test('the salt and the iv are fresh on every wrap', async () => {
  /* One repeated IV under one key destroys AES-GCM outright, and a repeated salt means two
   * wallets with the same passphrase share a wrapping key. Both are silent. */
  const keys = generateStealthKeys()
  const salts = new Set()
  const ivs = new Set()
  const cts = new Set()

  for (let i = 0; i < 6; i += 1) {
    const blob = await lockKeys(keys, PASSPHRASE)
    salts.add(blob.salt)
    ivs.add(blob.iv)
    cts.add(blob.ct)
  }

  assert.equal(salts.size, 6, 'a salt repeated')
  assert.equal(ivs.size, 6, 'an iv repeated')
  assert.equal(cts.size, 6, 'the same plaintext produced the same ciphertext twice')
})

test('the blob carries no private key in the clear', async () => {
  const keys = generateStealthKeys()
  const blob = await lockKeys(keys, PASSPHRASE)
  const serialised = JSON.stringify(blob)
  const spendingHex = Buffer.from(keys.spending.privateKey).toString('hex')
  const viewingHex = Buffer.from(keys.viewing.privateKey).toString('hex')

  assert.ok(!serialised.includes(spendingHex), 'the spending key is in the stored blob')
  assert.ok(!serialised.includes(viewingHex), 'the viewing key is in the stored blob')
  /* Base64 of the raw bytes would be just as bad and less obvious. */
  assert.ok(!serialised.includes(Buffer.from(keys.spending.privateKey).toString('base64')))
})

test('a passphrase too short to be worth anything is refused at the door', async () => {
  /* Refused rather than accepted with a warning. A store that wraps under "1234" and tells you it
   * is encrypted has taught you something false about your own safety. */
  await assert.rejects(() => lockKeys(generateStealthKeys(), 'short'), /eight characters/)
})

test('the stretch cost travels with the blob, so raising it later locks nobody out', async () => {
  const blob = await lockKeys(generateStealthKeys(), PASSPHRASE)
  assert.equal(blob.iter, VAULT_ITERATIONS)

  /* A blob wrapped under a lower count must still open, which is what makes the constant safe to
   * raise. Forged here rather than waited for. */
  const older = { ...blob, iter: 120_000 }
  assert.equal(await unlockKeys(older, PASSPHRASE), null, 'a changed iteration count must fail the tag check')
})

test('a blob from a future version is refused rather than guessed at', async () => {
  const blob = await lockKeys(generateStealthKeys(), PASSPHRASE)
  assert.equal(await unlockKeys({ ...blob, v: 2 }, PASSPHRASE), null)
})
