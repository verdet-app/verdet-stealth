/**
 * The backup sheet and its fingerprints.
 *
 * The property that matters is the one a holder is relying on years later: a key copied wrong
 * must not produce the same fingerprint as the key itself. Everything else here is bookkeeping.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  generateStealthKeys,
  keysFromPrivate,
  backupSheet,
  fingerprint,
  walletFingerprint,
  checkTranscription,
} from '../dist/index.js'

const fixed = () =>
  keysFromPrivate(
    Uint8Array.from({ length: 32 }, (_, i) => i + 1),
    Uint8Array.from({ length: 32 }, (_, i) => 200 - i),
  )

test('a sheet carries both keys, the meta-address and three fingerprints', () => {
  const keys = fixed()
  const sheet = backupSheet(keys)
  assert.match(sheet.spendingKey, /^0x[0-9a-f]{64}$/)
  assert.match(sheet.viewingKey, /^0x[0-9a-f]{64}$/)
  assert.equal(sheet.metaAddress, keys.metaAddress)
  for (const print of [sheet.spendingFingerprint, sheet.viewingFingerprint, sheet.walletFingerprint]) {
    assert.match(print, /^[0-9A-F]{4}-[0-9A-F]{4}$/)
  }
})

test('the fingerprint alphabet has no character that is copied wrong', () => {
  /* Hex specifically: no O to confuse with 0, no I to confuse with 1. */
  const print = backupSheet(fixed()).walletFingerprint
  assert.ok(!/[OI]/.test(print))
  assert.match(print, /^[0-9A-F-]+$/)
})

test('one character wrong gives a different fingerprint', () => {
  /* The whole point. A swapped pair of characters must not fingerprint the same as the original. */
  const key = Uint8Array.from({ length: 32 }, (_, i) => i + 1)
  const original = fingerprint(key)
  for (let i = 0; i < 32; i += 1) {
    const altered = Uint8Array.from(key)
    altered[i] ^= 0x01
    assert.notEqual(fingerprint(altered), original, `byte ${i} flipped and the fingerprint held`)
  }
})

test('the two keys of one wallet fingerprint differently', () => {
  const sheet = backupSheet(fixed())
  assert.notEqual(sheet.spendingFingerprint, sheet.viewingFingerprint)
  assert.notEqual(sheet.spendingFingerprint, sheet.walletFingerprint)
  assert.notEqual(sheet.viewingFingerprint, sheet.walletFingerprint)
})

test('the wallet fingerprint depends on the order of the pair', () => {
  /* Otherwise a wallet with its keys swapped, which is a real transcription error and a wallet
   * that cannot spend, would report the same fingerprint as the correct one. */
  const a = keysFromPrivate(Uint8Array.from({ length: 32 }, (_, i) => i + 1), Uint8Array.from({ length: 32 }, (_, i) => 200 - i))
  const b = keysFromPrivate(Uint8Array.from({ length: 32 }, (_, i) => 200 - i), Uint8Array.from({ length: 32 }, (_, i) => i + 1))
  assert.notEqual(walletFingerprint(a), walletFingerprint(b))
})

test('two wallets do not share a fingerprint', () => {
  const seen = new Set()
  for (let i = 0; i < 50; i += 1) seen.add(walletFingerprint(generateStealthKeys()))
  assert.equal(seen.size, 50)
})

test('a correct transcription is accepted in every ordinary form', () => {
  const keys = fixed()
  const sheet = backupSheet(keys)
  for (const shape of [
    (s) => s,
    (s) => s.slice(2),
    (s) => s.toUpperCase(),
    (s) => `  ${s}  `,
    (s) => s.replace(/(.{8})/g, '$1 '),
    (s) => s.slice(2).replace(/(.{4})/g, '$1-').replace(/-$/, ''),
  ]) {
    const result = checkTranscription(keys, shape(sheet.spendingKey), shape(sheet.viewingKey))
    assert.ok(result.ok, `rejected a correct key written as ${shape(sheet.spendingKey)}`)
  }
})

test('a wrong transcription says which line is wrong', () => {
  const keys = fixed()
  const sheet = backupSheet(keys)
  const broken = `${sheet.spendingKey.slice(0, -1)}${sheet.spendingKey.endsWith('a') ? 'b' : 'a'}`

  const result = checkTranscription(keys, broken, sheet.viewingKey)
  assert.equal(result.spendingMatches, false)
  assert.equal(result.viewingMatches, true)
  assert.equal(result.ok, false)
})

test('a dropped leading zero is refused, not silently parsed', () => {
  /* Parsing would turn 0x0abc... into the number 0xabc... and call it a match at a different
   * length, which is the worst outcome available: a wrong key reported as correct. */
  const keys = keysFromPrivate(
    Uint8Array.from([0, ...Array.from({ length: 31 }, (_, i) => i + 1)]),
    Uint8Array.from({ length: 32 }, (_, i) => 200 - i),
  )
  const sheet = backupSheet(keys)
  const dropped = `0x${sheet.spendingKey.slice(4)}`
  assert.equal(checkTranscription(keys, dropped, sheet.viewingKey).spendingMatches, false)
})

test('the keys of a different wallet do not pass', () => {
  const mine = fixed()
  const theirs = backupSheet(generateStealthKeys())
  const result = checkTranscription(mine, theirs.spendingKey, theirs.viewingKey)
  assert.equal(result.ok, false)
  assert.equal(result.spendingMatches, false)
  assert.equal(result.viewingMatches, false)
})

test('swapped keys are caught', () => {
  const keys = fixed()
  const sheet = backupSheet(keys)
  const result = checkTranscription(keys, sheet.viewingKey, sheet.spendingKey)
  assert.equal(result.ok, false)
})

test('a fingerprint refuses anything that is not a key', () => {
  assert.throws(() => fingerprint(new Uint8Array(31)), /32 bytes/)
  assert.throws(() => fingerprint(new Uint8Array(33)), /32 bytes/)
})

test('the parser accepts what a person writes and refuses what they mean differently', async () => {
  const { parsePrivateKey } = await import('../dist/index.js')
  const key = backupSheet(fixed()).spendingKey
  const bytes = parsePrivateKey(key)
  assert.equal(bytes.length, 32)

  for (const shape of [key.slice(2), key.toUpperCase(), ` ${key} `, key.replace(/(.{4})/g, '$1-')]) {
    assert.deepEqual(parsePrivateKey(shape), bytes, `refused ${shape}`)
  }

  /* Length is the one thing it will not forgive, because a dropped character parses fine as a
   * shorter number and would come back as a different working key. */
  assert.equal(parsePrivateKey(key.slice(0, -1)), null)
  assert.equal(parsePrivateKey(`${key}0`), null)
  assert.equal(parsePrivateKey('0xnothexatall'), null)
  assert.equal(parsePrivateKey(''), null)
})

test('a key written down and typed back rebuilds the same wallet', async () => {
  /* The round trip the backup sheet promises, end to end: sheet, paper, restore, same wallet. */
  const { parsePrivateKey } = await import('../dist/index.js')
  const original = generateStealthKeys()
  const sheet = backupSheet(original)

  const asWritten = (hex) => hex.slice(2).toUpperCase().replace(/(.{4})/g, '$1 ').trim()
  const restored = keysFromPrivate(
    parsePrivateKey(asWritten(sheet.spendingKey)),
    parsePrivateKey(asWritten(sheet.viewingKey)),
  )

  assert.equal(restored.metaAddress, original.metaAddress)
  assert.equal(walletFingerprint(restored), sheet.walletFingerprint)
})
