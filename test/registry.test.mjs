/**
 * The registry calldata, checked against the ABI by hand.
 *
 * The selectors are constants computed once from the signatures in the ERC-6538 specification and
 * pinned here, so a typo in a signature string fails the build rather than sending a transaction
 * that reverts. The layout vector is derived from the ABI rules on paper: selector, static word,
 * offset word, length word, payload padded to whole words.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  REGISTER_KEYS_SELECTOR,
  STEALTH_META_ADDRESS_OF_SELECTOR,
  encodeRegisterKeys,
  encodeStealthMetaAddressOf,
  decodeStealthMetaAddressOf,
  encodeMetaAddress,
} from '../dist/index.js'

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
const word = (n) => n.toString(16).padStart(64, '0')

/* Two well-formed compressed keys that are obviously synthetic. */
const SPENDING = new Uint8Array([0x02, ...new Array(32).fill(0x11)])
const VIEWING = new Uint8Array([0x03, ...new Array(32).fill(0x22)])
const META = encodeMetaAddress({ spendingPublicKey: SPENDING, viewingPublicKey: VIEWING })
const PAYLOAD = hex(SPENDING) + hex(VIEWING)

test('the selectors are the ones the specification names', () => {
  assert.equal(hex(REGISTER_KEYS_SELECTOR), '042c7aa3', 'registerKeys(uint256,bytes)')
  assert.equal(hex(STEALTH_META_ADDRESS_OF_SELECTOR), '7aa8b5ad', 'stealthMetaAddressOf(address,uint256)')
})

test('registerKeys calldata is laid out exactly as the ABI says', () => {
  const data = encodeRegisterKeys(META)
  const expected =
    '0x042c7aa3' +
    word(1) + /* schemeId */
    word(0x40) + /* offset of the bytes argument: two static words in */
    word(66) + /* length */
    PAYLOAD + '0'.repeat((96 - 66) * 2) /* 66 bytes padded to three words */
  assert.equal(data, expected)
  assert.equal((data.length - 2) / 2, 196, 'always 196 bytes, because every meta-address is 66 bytes')
})

test('stealthMetaAddressOf calldata pads the address into a word', () => {
  const data = encodeStealthMetaAddressOf('0x1111111111111111111111111111111111111111')
  assert.equal(data, '0x7aa8b5ad' + '0'.repeat(24) + '11'.repeat(20) + word(1))
})

test('a registered meta-address round-trips through the return encoding', () => {
  const returned = '0x' + word(0x20) + word(66) + PAYLOAD + '0'.repeat((96 - 66) * 2)
  assert.equal(decodeStealthMetaAddressOf(returned), META)
})

test('an unregistered address decodes to null, not to an empty string', () => {
  assert.equal(decodeStealthMetaAddressOf('0x' + word(0x20) + word(0)), null)
  assert.equal(decodeStealthMetaAddressOf('0x'), null)
})

test('a return of the wrong length is refused rather than guessed at', () => {
  const short = '0x' + word(0x20) + word(33) + hex(SPENDING) + '0'.repeat((64 - 33) * 2)
  assert.throws(() => decodeStealthMetaAddressOf(short), /expected 66/)
})
