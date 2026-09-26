/**
 * The command, run as a command.
 *
 * ## Why this spawns instead of importing
 *
 * Because the parts of a CLI that break are the parts an import does not touch. The shebang, the
 * argument split, the exit code, whether a flag reaches the branch that reads it, and whether a
 * secret stays off stdout: all of those live between `process.argv` and `process.exitCode`, and a
 * test that imports a function and calls it directly proves none of them.
 *
 * It costs a process per case. There are nine of them.
 *
 * ## The one that matters
 *
 * `keys` withholds private keys unless asked. That is a promise made in the help text and in the
 * package's README, and it is the single thing in this file most damaging to be wrong about, so it
 * is asserted from both directions: the secrets are absent by default, and present with the flag.
 * An assertion that only checks the default would still pass if the flag had quietly stopped
 * working, and then the warning about scrollback would be attached to nothing.
 */

import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import test from 'node:test'
import assert from 'node:assert/strict'

const CLI = fileURLToPath(new URL('../dist/cli.js', import.meta.url))
const MANIFEST = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))

/** Runs the command and returns its stdout. Throws, with the status attached, on a non-zero exit. */
function run(args, { colour = false } = {}) {
  return execFileSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8',
    env: colour ? { ...process.env, FORCE_COLOR: '1' } : { ...process.env, NO_COLOR: '1' },
  })
}

function runExpectingFailure(args) {
  try {
    run(args)
    return null
  } catch (error) {
    return { status: error.status, stderr: String(error.stderr) }
  }
}

const freshMetaAddress = () => JSON.parse(run(['keys', '--json'])).metaAddress

test('with no arguments it prints the banner and the commands', () => {
  const output = run([])
  assert.match(output, /VERDET/)
  assert.match(output, /@verdet\/stealth/)
  for (const command of ['keys', 'address', 'check', 'version']) {
    assert.ok(output.includes(command), `the help does not mention ${command}`)
  }
})

test('the banner draws the mark as five rows of blocks', () => {
  const rows = run([])
    .split('\n')
    .filter((line) => line.includes('█'))
  assert.equal(rows.length, 5)
  /* Two characters a cell, so every painted run is even. An odd run means a half cell. */
  for (const row of rows) {
    for (const run_ of row.match(/█+/g) ?? []) {
      assert.equal(run_.length % 2, 0, `a painted run of ${run_.length} is not whole cells`)
    }
  }
})

test('version reports what the manifest says, not a literal in the source', () => {
  assert.equal(run(['version']).trim(), MANIFEST.version)
})

test('keys withholds the private keys', () => {
  const json = JSON.parse(run(['keys', '--json']))
  assert.ok(json.metaAddress.startsWith('st:eth:0x'))
  assert.ok(json.spendingPublicKey.startsWith('0x'))
  assert.equal(json.spendingPrivateKey, undefined)
  assert.equal(json.viewingPrivateKey, undefined)

  const text = run(['keys'])
  assert.match(text, /Private keys withheld/)
  /* A compressed public key is 33 bytes and a secret is 32. Nothing 64 hex digits long and no
   * longer should reach stdout without the flag. */
  assert.equal(text.match(/0x[0-9a-f]{64}(?![0-9a-f])/g), null)
})

test('keys prints the private keys when asked, and says what that costs', () => {
  const json = JSON.parse(run(['keys', '--json', '--show-secret']))
  assert.match(json.spendingPrivateKey, /^0x[0-9a-f]{64}$/)
  assert.match(json.viewingPrivateKey, /^0x[0-9a-f]{64}$/)

  const text = run(['keys', '--show-secret'])
  assert.match(text, /0x[0-9a-f]{64}(?![0-9a-f])/)
  assert.match(text, /scrollback/)
})

test('check parses a meta-address this command just produced', () => {
  const json = JSON.parse(run(['check', freshMetaAddress(), '--json']))
  assert.equal(json.valid, true)
  assert.equal(json.schemeId, 1)
  assert.match(json.spendingPublicKey, /^0x0[23][0-9a-f]{64}$/)
  assert.match(json.viewingPublicKey, /^0x0[23][0-9a-f]{64}$/)
})

test('address derives a checksummed one-time address and a view tag', () => {
  const json = JSON.parse(run(['address', freshMetaAddress(), '--json']))
  assert.match(json.stealthAddress, /^0x[0-9a-fA-F]{40}$/)
  assert.notEqual(json.stealthAddress, json.stealthAddress.toLowerCase(), 'not checksummed')
  assert.match(json.ephemeralPublicKey, /^0x0[23][0-9a-f]{64}$/)
  assert.ok(json.viewTag >= 0 && json.viewTag <= 255)
})

test('a bad meta-address fails loudly rather than producing an address', () => {
  const failed = runExpectingFailure(['check', 'st:eth:0xdeadbeef'])
  assert.ok(failed, 'a malformed meta-address was accepted')
  assert.equal(failed.status, 1)
  assert.match(failed.stderr, /66 bytes/)

  const unknown = runExpectingFailure(['teleport'])
  assert.ok(unknown, 'an unknown command exited zero')
  assert.equal(unknown.status, 1)
})

test('colour is opt in, and off when the output is not a terminal', () => {
  const ESCAPE = /\u001b\[/
  assert.doesNotMatch(run([]), ESCAPE, 'escape codes reached a pipe')
  assert.doesNotMatch(run([], { colour: true }).replace(ESCAPE, ''), /^$/)
  assert.match(run([], { colour: true }), ESCAPE, 'FORCE_COLOR produced no colour')
  assert.doesNotMatch(run(['--no-color'], { colour: true }), ESCAPE, '--no-color did not win')
})
