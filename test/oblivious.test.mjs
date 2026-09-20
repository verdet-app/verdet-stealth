/**
 * Oblivious transfer.
 *
 * Two properties, and a test suite is only honest about one of them. **The keys agree on the
 * chosen branch and disagree everywhere else** is checkable here. **The sender cannot tell which
 * branch was chosen** is an argument about the distribution of the request, and the closest a test
 * gets is showing that the request is a function of a fresh uniform scalar and that two requests
 * for different choices are indistinguishable by anything this code can compute.
 */

import test from 'node:test'
import assert from 'node:assert/strict'

import { otSenderBegin, otReceiverChoose, otSenderKeys, otReceiverKey } from '../dist/index.js'

test('the chosen branch agrees and no other does', () => {
  const count = 8
  for (let choice = 0; choice < count; choice += 1) {
    const sender = otSenderBegin()
    const receiver = otReceiverChoose(sender.point, choice, count)

    const keys = otSenderKeys(sender, receiver.request, count)
    const mine = otReceiverKey(receiver, sender.point, count)

    assert.deepEqual(mine, keys[choice], `branch ${choice} did not agree`)
    for (let j = 0; j < count; j += 1) {
      if (j !== choice) assert.notDeepEqual(mine, keys[j], `branch ${j} agreed and should not have`)
    }
  }
})

test('the zero branch works, which is the one an off-by-one breaks', () => {
  /* Choice zero is the case where the protocol reduces to xG and a naive implementation
   * multiplies a point by zero, which no curve library will return. */
  const sender = otSenderBegin()
  const receiver = otReceiverChoose(sender.point, 0, 4)
  const keys = otSenderKeys(sender, receiver.request, 4)
  assert.deepEqual(otReceiverKey(receiver, sender.point, 4), keys[0])
})

test('a two-branch transfer works', () => {
  for (const choice of [0, 1]) {
    const sender = otSenderBegin()
    const receiver = otReceiverChoose(sender.point, choice, 2)
    const keys = otSenderKeys(sender, receiver.request, 2)
    assert.deepEqual(otReceiverKey(receiver, sender.point, 2), keys[choice])
  }
})

test('every branch gets a different key', () => {
  const sender = otSenderBegin()
  const receiver = otReceiverChoose(sender.point, 3, 12)
  const keys = otSenderKeys(sender, receiver.request, 12)
  const seen = new Set(keys.map((k) => Buffer.from(k).toString('hex')))
  assert.equal(seen.size, 12)
})

test('two runs of the same choice share nothing', () => {
  /* Fresh scalars each run, so a sender correlating two requests learns nothing from their bytes. */
  const a = otSenderBegin()
  const b = otSenderBegin()
  const ra = otReceiverChoose(a.point, 2, 5)
  const rb = otReceiverChoose(b.point, 2, 5)

  assert.notDeepEqual(ra.request, rb.request)
  assert.notDeepEqual(otReceiverKey(ra, a.point, 5), otReceiverKey(rb, b.point, 5))
})

test('requests for different choices are the same shape and size', () => {
  /* The sender sees a compressed point and nothing else, whatever was chosen. */
  const sender = otSenderBegin()
  const sizes = new Set()
  for (let choice = 0; choice < 6; choice += 1) {
    sizes.add(otReceiverChoose(sender.point, choice, 6).request.length)
  }
  assert.equal(sizes.size, 1)
  assert.equal([...sizes][0], 33)
})

test('the receiver secret never appears in the request', () => {
  const sender = otSenderBegin()
  const receiver = otReceiverChoose(sender.point, 1, 4)
  const hex = (b) => Buffer.from(b).toString('hex')
  assert.ok(!hex(receiver.request).includes(hex(receiver.secret)))
})

test('the sender secret never appears in what it publishes', () => {
  const sender = otSenderBegin()
  const hex = (b) => Buffer.from(b).toString('hex')
  assert.ok(!hex(sender.point).includes(hex(sender.secret)))
})

test('a request built against a different sender does not open anything', () => {
  const sender = otSenderBegin()
  const impostor = otSenderBegin()
  const receiver = otReceiverChoose(impostor.point, 2, 5)

  const keys = otSenderKeys(sender, receiver.request, 5)
  assert.notDeepEqual(otReceiverKey(receiver, sender.point, 5), keys[2])
})

test('the branch count is part of the key', () => {
  /* Otherwise a sender could answer a five-branch request with a three-branch table and the
   * receiver would not notice the records had been swapped underneath. */
  const sender = otSenderBegin()
  const receiver = otReceiverChoose(sender.point, 1, 5)
  assert.notDeepEqual(otReceiverKey(receiver, sender.point, 5), otReceiverKey(receiver, sender.point, 6))
})

test('a choice outside the offer is refused', () => {
  const sender = otSenderBegin()
  assert.throws(() => otReceiverChoose(sender.point, 5, 5), /not one of the records/)
  assert.throws(() => otReceiverChoose(sender.point, -1, 5), /not one of the records/)
})

test('a transfer of one is refused, and so is an absurd one', () => {
  const sender = otSenderBegin()
  assert.throws(() => otReceiverChoose(sender.point, 0, 1), /at least two records/)
  assert.throws(() => otReceiverChoose(sender.point, 0, 100000), /denial of service/)
})
