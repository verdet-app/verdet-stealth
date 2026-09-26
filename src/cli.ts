#!/usr/bin/env node
/**
 * The command line, so the derivation can be run without a browser and without this repository.
 *
 * ## Why a library ships a command
 *
 * The argument this package makes is that you do not have to trust anybody's description of ERC-5564:
 * the spec is public, the implementation is here, and you can read it. That argument has a gap in it
 * while the only way to run the code is to write a program that imports it. `npx @verdet/stealth keys`
 * closes the gap. It is thirty seconds between doubting the claim and watching the arithmetic happen
 * on your own machine, with no wallet, no site and no account in the way.
 *
 * ## What it will not do
 *
 * **There is no network in this file and there is none underneath it.** Nothing here reads a chain,
 * posts an announcement or contacts a registry. Every command is arithmetic over inputs you supply,
 * which is what makes it safe to run on a machine you care about and what makes its output something
 * you can check against any other ERC-5564 implementation.
 *
 * **Private keys are not printed unless you ask.** `keys` derives a spending key and a viewing key
 * and shows you neither. A secret that appears on a terminal has been written to a scrollback buffer,
 * probably to a shell history if it was piped, and possibly to a terminal multiplexer's log. That is
 * a decision for the person at the keyboard, so it takes a flag and it prints a warning.
 *
 * ## The banner
 *
 * The mark is a five by five grid of whole cells, which is the one piece of brand geometry that
 * survives being rendered in a terminal without being redrawn for it. `MARK_ROWS` below is that
 * grid, and `packages/stealth/test/cli-banner.test.mjs` in the monorepo derives the same grid from
 * the rectangles in `scripts/lib/mark.mjs` and fails if the two ever disagree. A logo copied by eye
 * into an ASCII art string is a logo that quietly stops being the logo.
 *
 * Usage:
 *   npx @verdet/stealth               the banner and what the commands are
 *   npx @verdet/stealth keys          a fresh spending and viewing pair
 *   npx @verdet/stealth address <m>   a one-time address for a published meta-address
 *   npx @verdet/stealth check <m>     what is inside a meta-address
 */

import { readFileSync } from 'node:fs'

import { createStealthPayment } from './payment.js'
import { generateStealthKeys } from './keys.js'
import { decodeMetaAddress, META_ADDRESS_BYTES, SCHEME_ID } from './meta-address.js'
/**
 * Read out of the package manifest at startup, not typed here.
 *
 * A version literal in a source file is a version that is correct until the day somebody bumps the
 * manifest and forgets this line, and the banner then reports a release that does not exist. From
 * `dist/cli.js` the manifest is one directory up, and npm puts it in every tarball whatever `files`
 * says.
 */
const VERSION: string = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version

/* --- The mark, as cells ------------------------------------------------------- */

/**
 * The mark's five by five grid. `b` is the body, `n` the near tile, `f` the far tile, `.` is empty.
 *
 * This is the shape in `docs/BRAND.md` section 2: one connected body and two tiles that have left
 * it, brightening with distance. The near tile sits in the body's own column with exactly one empty
 * cell between them, so they line up and do not touch.
 */
const MARK_ROWS = [
  '....f',
  'bb.n.',
  'b....',
  'b..b.',
  'bbbb.',
] as const

/** The three tones, as the tokens they are on every other surface. */
const TONES = {
  b: [0x3f, 0xbf, 0x23],
  n: [0x84, 0xe6, 0x61],
  f: [0xc6, 0xee, 0x2e],
} as const

/* --- Colour ------------------------------------------------------------------- */

/**
 * Whether to emit escape codes at all.
 *
 * Off when the output is not a terminal, because the first thing anybody does with a command like
 * this is pipe it somewhere, and escape codes in a pipe are corruption rather than colour. Off for
 * `NO_COLOR` and `--no-color`, on for `FORCE_COLOR`, which is the only way a capture like the one
 * behind our own posters can ask for the real thing.
 */
function wantsColour(argv: readonly string[]): boolean {
  if (argv.includes('--no-color')) return false
  if (process.env['NO_COLOR']) return false
  if (process.env['FORCE_COLOR']) return true
  return Boolean(process.stdout.isTTY)
}

let colour = true
const paint = (text: string, rgb: readonly number[]): string =>
  colour ? `\u001b[38;2;${rgb[0]};${rgb[1]};${rgb[2]}m${text}\u001b[0m` : text

const DIM: readonly number[] = [0x6b, 0x74, 0x6d]
const HI: readonly number[] = [0xe8, 0xed, 0xe9]
const GREEN: readonly number[] = [0x5f, 0xd6, 0x3a]
const AMBER: readonly number[] = [0xff, 0xc5, 0x3d]

/* --- Output ------------------------------------------------------------------- */

const out = (line = '') => process.stdout.write(`${line}\n`)
const hex = (bytes: Uint8Array): string =>
  `0x${Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')}`

/** Two characters per cell, because a terminal cell is about half as wide as it is tall. */
function banner(): string[] {
  return MARK_ROWS.map((row) =>
    `  ${[...row].map((cell) => (cell === '.' ? '  ' : paint('██', TONES[cell as 'b' | 'n' | 'f']))).join('')}`,
  )
}

/** A label and a value, with the labels in one column so values line up down the page. */
const field = (label: string, value: string, tone: readonly number[] = HI) =>
  out(`  ${paint(label.padEnd(22), DIM)}${paint(value, tone)}`)

function help(): void {
  out()
  for (const line of banner()) out(line)
  out()
  out(`  ${paint('VERDET', HI)}  ${paint(`@verdet/stealth ${VERSION}`, DIM)}`)
  out(`  ${paint('Stealth addresses for tokenized equities. No network in this command.', DIM)}`)
  out()
  out(`  ${paint('USAGE', GREEN)}`)
  out(`    npx @verdet/stealth <command> [options]`)
  out()
  out(`  ${paint('COMMANDS', GREEN)}`)
  out(`    ${'keys'.padEnd(24)}${paint('Derive a spending key and a viewing key', DIM)}`)
  out(`    ${'address <meta-address>'.padEnd(24)}${paint('A one-time address for a published meta-address', DIM)}`)
  out(`    ${'check <meta-address>'.padEnd(24)}${paint('What is inside a meta-address', DIM)}`)
  out(`    ${'version'.padEnd(24)}${paint('Print the version and exit', DIM)}`)
  out()
  out(`  ${paint('OPTIONS', GREEN)}`)
  out(`    ${'--show-secret'.padEnd(24)}${paint('Print private keys. They are withheld otherwise.', DIM)}`)
  out(`    ${'--json'.padEnd(24)}${paint('One JSON object, for piping', DIM)}`)
  out(`    ${'--no-color'.padEnd(24)}${paint('No escape codes', DIM)}`)
  out()
  out(`  ${paint('verdet.app', DIM)}`)
  out()
}

/* --- Commands ----------------------------------------------------------------- */

function commandKeys(argv: readonly string[]): number {
  const keys = generateStealthKeys()
  const showSecret = argv.includes('--show-secret')

  if (argv.includes('--json')) {
    out(JSON.stringify({
      metaAddress: keys.metaAddress,
      spendingPublicKey: hex(keys.spending.publicKey),
      viewingPublicKey: hex(keys.viewing.publicKey),
      ...(showSecret
        ? {
            spendingPrivateKey: hex(keys.spending.privateKey),
            viewingPrivateKey: hex(keys.viewing.privateKey),
          }
        : {}),
    }, null, 2))
    return 0
  }

  out()
  field('meta-address', keys.metaAddress, GREEN)
  field('spending public key', hex(keys.spending.publicKey))
  field('viewing public key', hex(keys.viewing.publicKey))
  out()
  if (showSecret) {
    field('spending private key', hex(keys.spending.privateKey), AMBER)
    field('viewing private key', hex(keys.viewing.privateKey), AMBER)
    out()
    out(`  ${paint('These are now in your scrollback, and in your shell history if you piped them.', AMBER)}`)
  } else {
    out(`  ${paint('Private keys withheld. Pass --show-secret to print them.', DIM)}`)
  }
  out(`  ${paint('A meta-address whose keys are lost receives payments nobody can spend.', DIM)}`)
  out()
  return 0
}

function commandAddress(argv: readonly string[], metaAddress: string | undefined): number {
  if (!metaAddress) return fail('address needs a meta-address: npx @verdet/stealth address st:eth:0x...')

  let payment
  try {
    payment = createStealthPayment(metaAddress)
  } catch (error) {
    return fail(error instanceof Error ? error.message : String(error))
  }

  if (argv.includes('--json')) {
    out(JSON.stringify({
      schemeId: payment.schemeId,
      stealthAddress: payment.stealthAddress,
      ephemeralPublicKey: hex(payment.ephemeralPublicKey),
      viewTag: payment.viewTag,
    }, null, 2))
    return 0
  }

  out()
  field('stealth address', payment.stealthAddress, GREEN)
  field('ephemeral public key', hex(payment.ephemeralPublicKey))
  field('view tag', `0x${payment.viewTag.toString(16).padStart(2, '0')}`)
  field('scheme id', String(payment.schemeId))
  out()
  out(`  ${paint('Send the asset to the stealth address. Publish the ephemeral key and the view tag', DIM)}`)
  out(`  ${paint('in an announcement, or hand them to the recipient directly.', DIM)}`)
  out()
  return 0
}

function commandCheck(argv: readonly string[], metaAddress: string | undefined): number {
  if (!metaAddress) return fail('check needs a meta-address: npx @verdet/stealth check st:eth:0x...')

  let decoded
  try {
    decoded = decodeMetaAddress(metaAddress)
  } catch (error) {
    return fail(error instanceof Error ? error.message : String(error))
  }

  if (argv.includes('--json')) {
    out(JSON.stringify({
      valid: true,
      schemeId: SCHEME_ID,
      bytes: META_ADDRESS_BYTES,
      spendingPublicKey: hex(decoded.spendingPublicKey),
      viewingPublicKey: hex(decoded.viewingPublicKey),
    }, null, 2))
    return 0
  }

  out()
  field('parsed', 'yes', GREEN)
  field('scheme id', String(SCHEME_ID))
  field('payload bytes', String(META_ADDRESS_BYTES))
  field('spending public key', hex(decoded.spendingPublicKey))
  field('viewing public key', hex(decoded.viewingPublicKey))
  out()
  out(`  ${paint('Two compressed secp256k1 points. The first moves funds, the second only finds them.', DIM)}`)
  out()
  return 0
}

function fail(message: string): number {
  process.stderr.write(`${paint('verdet:', AMBER)} ${message}\n`)
  return 1
}

/* --- Entry -------------------------------------------------------------------- */

function main(argv: readonly string[]): number {
  colour = wantsColour(argv)
  const positional = argv.filter((a) => !a.startsWith('--'))
  const command = positional[0]

  switch (command) {
    case undefined:
    case 'help':
      help()
      return 0
    case 'version':
      out(VERSION)
      return 0
    case 'keys':
      return commandKeys(argv)
    case 'address':
      return commandAddress(argv, positional[1])
    case 'check':
      return commandCheck(argv, positional[1])
    default:
      return fail(`no command called "${command}". Run npx @verdet/stealth for the list.`)
  }
}

/*
 * Run on load, with nothing exported.
 *
 * The tests spawn this file rather than importing it, which is the right way round: it exercises
 * the shebang, the argument parsing and the exit code, all of which are the parts of a command that
 * actually break. The banner's grid is checked separately, against the brand geometry, by reading
 * this file as text.
 */
process.exitCode = main(process.argv.slice(2))
