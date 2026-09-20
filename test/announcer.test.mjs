/**
 * The announcer calldata and the log decoder, checked against the ABI by hand.
 *
 * The selector and the event topic are constants computed once from the signatures in the ERC-5564
 * specification and pinned here. The calldata vector is derived from the ABI rules on paper. The
 * decoder is fed a log built the same way and has to give back what went in, and is fed the ways a
 * public event stream goes wrong and has to say null rather than throw.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import {
  ANNOUNCE_SELECTOR,
  ANNOUNCEMENT_TOPIC,
  encodeAnnounce,
  decodeAnnouncementLog,
  createStealthPayment,
  checkAnnouncement,
  generateStealthKeys,
} from '../dist/index.js'

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
const word = (n) => n.toString(16).padStart(64, '0')

const EPHEMERAL = new Uint8Array([0x02, ...new Array(32).fill(0x33)])
const STEALTH = '0x2222222222222222222222222222222222222222'
const CALLER = '0x4444444444444444444444444444444444444444'

test('the selector and the topic are the ones the specification names', () => {
  assert.equal(hex(ANNOUNCE_SELECTOR), '4d1f9583', 'announce(uint256,address,bytes,bytes)')
  assert.equal(ANNOUNCEMENT_TOPIC, '0x5f0eab8057630ba7676c49b4f21a0231414e79474595be8e4c432fbf6bf0f4e7')
})

test('announce calldata is laid out exactly as the ABI says', () => {
  const data = encodeAnnounce({ stealthAddress: STEALTH, ephemeralPublicKey: EPHEMERAL, viewTag: 0xab })
  const expected =
    '0x4d1f9583' +
    word(1) + /* schemeId */
    '0'.repeat(24) + '22'.repeat(20) + /* stealth address, padded */
    word(0x80) + /* offset of ephemeralPubKey: four head words in */
    word(0xe0) + /* offset of metadata: 0x80 + length word + two payload words */
    word(33) + hex(EPHEMERAL) + '0'.repeat((64 - 33) * 2) +
    word(1) + 'ab' + '0'.repeat(31 * 2)
  assert.equal(data, expected)
  assert.equal((data.length - 2) / 2, 292, 'always 292 bytes')
})

test('the view tag is one byte and the key is 33, or it is refused', () => {
  assert.throws(() => encodeAnnounce({ stealthAddress: STEALTH, ephemeralPublicKey: EPHEMERAL, viewTag: 256 }), /one byte/)
  assert.throws(() => encodeAnnounce({ stealthAddress: STEALTH, ephemeralPublicKey: EPHEMERAL.subarray(1), viewTag: 1 }), /33 bytes/)
})

/** A log as the node returns it for the announcement above. */
function logFor({ scheme = 1, ephemeral = EPHEMERAL, viewTag = 0xab, topic = ANNOUNCEMENT_TOPIC } = {}) {
  return {
    topics: [topic, '0x' + word(scheme), '0x' + '0'.repeat(24) + '22'.repeat(20), '0x' + '0'.repeat(24) + '44'.repeat(20)],
    data: '0x' + word(0x40) + word(0x40 + 32 + 64) + word(ephemeral.length) + hex(ephemeral) + '0'.repeat((64 - ephemeral.length) * 2) + word(1) + viewTag.toString(16).padStart(2, '0') + '0'.repeat(62),
    blockNumber: '0x3f9c2a0',
    transactionHash: '0x' + 'ee'.repeat(32),
  }
}

test('a scheme-1 log decodes to the candidate the scanner needs', () => {
  const decoded = decodeAnnouncementLog(logFor())
  assert.ok(decoded)
  assert.equal(decoded.schemeId, 1)
  assert.equal(decoded.stealthAddress, STEALTH.toLowerCase())
  assert.equal(decoded.caller, CALLER.toLowerCase())
  assert.equal(hex(decoded.ephemeralPublicKey), hex(EPHEMERAL))
  assert.equal(decoded.viewTag, 0xab)
  assert.equal(decoded.blockNumber, 0x3f9c2a0)
  assert.equal(decoded.transactionHash, '0x' + 'ee'.repeat(32))
})

test('anything that is not a scheme-1 announcement is null, not an exception', () => {
  assert.equal(decodeAnnouncementLog(logFor({ scheme: 2 })), null, 'another scheme')
  assert.equal(decodeAnnouncementLog(logFor({ topic: '0x' + '00'.repeat(32) })), null, 'another event')
  assert.equal(decodeAnnouncementLog(logFor({ ephemeral: EPHEMERAL.subarray(0, 20) })), null, 'a malformed key')
  assert.equal(decodeAnnouncementLog({ topics: [ANNOUNCEMENT_TOPIC], data: '0x' }), null, 'missing topics')
  assert.equal(decodeAnnouncementLog({ topics: [ANNOUNCEMENT_TOPIC, '0x1', '0x2', '0x3'], data: '0x00' }), null, 'truncated data')
})

test('a real payment survives encode, log, decode and is found by its viewing key', () => {
  const keys = generateStealthKeys()
  const payment = createStealthPayment(keys.metaAddress)
  const calldata = encodeAnnounce(payment)
  assert.equal((calldata.length - 2) / 2, 292)

  /* What the node would log for that call: the same tails, after the four head words. */
  const tails = calldata.slice(2 + 8 + 64 * 4)
  const log = {
    topics: [ANNOUNCEMENT_TOPIC, '0x' + word(1), '0x' + '0'.repeat(24) + payment.stealthAddress.slice(2).toLowerCase(), '0x' + '0'.repeat(24) + '44'.repeat(20)],
    data: '0x' + word(0x40) + word(0x40 + 32 + 64) + tails,
  }
  const decoded = decodeAnnouncementLog(log)
  assert.ok(decoded)
  const match = checkAnnouncement(keys, decoded)
  assert.ok(match, 'the viewing key did not recognise its own payment')
  assert.equal(match.stealthAddress.toLowerCase(), payment.stealthAddress.toLowerCase())

  const stranger = generateStealthKeys()
  assert.equal(checkAnnouncement(stranger, decoded), null, 'a stranger recognised a payment that was not theirs')
})
