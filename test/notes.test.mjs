/**
 * Labels on requests.
 *
 * The claim is narrow and worth holding to: the labels are readable with the wallet's viewing key
 * and are ciphertext without it. The tests that matter are the ones where it fails, because a
 * store that quietly returns nothing looks identical to a wallet with no labels.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  generateStealthKeys,
  sealNotes,
  openNotes,
  checkNotes,
  NOTE_MAX_LENGTH,
  NOTES_MAX,
} from '../dist/index.js'

const sample = { 0: 'Invoice 1042', 7: 'March retainer', 23: 'Deposit, unit 4' }

test('labels round-trip under the wallet that wrote them', async () => {
  const keys = generateStealthKeys()
  const blob = await sealNotes(sample, keys.viewing.privateKey)
  assert.deepEqual(await openNotes(blob, keys.viewing.privateKey), sample)
})

test('the stored form carries no readable label', async () => {
  const keys = generateStealthKeys()
  const blob = await sealNotes(sample, keys.viewing.privateKey)
  const stored = JSON.stringify(blob)
  for (const label of Object.values(sample)) {
    assert.ok(!stored.includes(label), `${label} is readable in the stored blob`)
  }
  /* Base64 of the plaintext would also be a leak, and the check above would miss it. */
  assert.ok(!stored.includes(Buffer.from('Invoice 1042').toString('base64')))
})

test('another wallet reads no labels rather than wrong ones', async () => {
  const mine = generateStealthKeys()
  const theirs = generateStealthKeys()
  const blob = await sealNotes(sample, mine.viewing.privateKey)
  assert.deepEqual(await openNotes(blob, theirs.viewing.privateKey), {})
})

test('the spending key does not open the labels', async () => {
  /* They are keyed to the viewing key specifically, so a watch key opens them and nothing else
   * about the wallet does. */
  const keys = generateStealthKeys()
  const blob = await sealNotes(sample, keys.viewing.privateKey)
  assert.deepEqual(await openNotes(blob, keys.spending.privateKey), {})
})

test('a damaged blob reads as no labels and does not throw', async () => {
  const keys = generateStealthKeys()
  const blob = await sealNotes(sample, keys.viewing.privateKey)
  const damaged = { ...blob, ct: `${blob.ct.slice(0, -4)}AAAA` }
  assert.deepEqual(await openNotes(damaged, keys.viewing.privateKey), {})
  assert.deepEqual(await openNotes({ v: 2, iv: blob.iv, ct: blob.ct }, keys.viewing.privateKey), {})
  assert.deepEqual(await openNotes({ v: 1, iv: 'not base64!', ct: '' }, keys.viewing.privateKey), {})
})

test('each write draws a fresh nonce', async () => {
  /* Reusing an IV with the same key does not weaken GCM, it breaks it. The key here is fixed by
   * the wallet, so the nonce is the only thing keeping two writes apart. */
  const keys = generateStealthKeys()
  const seen = new Set()
  for (let i = 0; i < 20; i += 1) {
    seen.add((await sealNotes(sample, keys.viewing.privateKey)).iv)
  }
  assert.equal(seen.size, 20)
})

test('an over-long label is refused rather than shortened', async () => {
  const keys = generateStealthKeys()
  const long = { 0: 'x'.repeat(NOTE_MAX_LENGTH + 1) }
  await assert.rejects(() => sealNotes(long, keys.viewing.privateKey), /at most 120 characters/)
  assert.doesNotThrow(() => checkNotes({ 0: 'x'.repeat(NOTE_MAX_LENGTH) }))
})

test('labels are keyed by a request index and nothing else', () => {
  assert.throws(() => checkNotes({ 'not-an-index': 'x' }), /request index/)
  assert.doesNotThrow(() => checkNotes({ 0: 'x', 41: 'y' }))
})

test('the store has a ceiling', () => {
  const many = {}
  for (let i = 0; i <= NOTES_MAX; i += 1) many[i] = 'x'
  assert.throws(() => checkNotes(many), /at most 512 labels/)
})

test('an empty set is a legitimate state', async () => {
  const keys = generateStealthKeys()
  assert.deepEqual(await openNotes(await sealNotes({}, keys.viewing.privateKey), keys.viewing.privateKey), {})
})

test('a blob written in an unexpected shape is filtered, not trusted', async () => {
  /* The ciphertext proves this wallet wrote it. It does not prove which build did, so an older
   * shape must read as absent rather than reaching the interface. */
  const keys = generateStealthKeys()
  const blob = await sealNotes({ 3: 'kept' }, keys.viewing.privateKey)
  const opened = await openNotes(blob, keys.viewing.privateKey)
  assert.deepEqual(opened, { 3: 'kept' })
  assert.equal(Object.getPrototypeOf(opened), Object.prototype)
})
