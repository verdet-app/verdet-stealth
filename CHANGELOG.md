# Changelog

Notable changes, newest first. This project is pre-1.0: the surface can change between minor
versions, and anything that changes a derivation will say so at the top of its entry, because a
derivation change means addresses that no longer match.

## Unreleased

Nothing yet.

## 0.2.0

No derivation changed. Every address this version produces is an address `0.1.0` produces.

**The first release published by the workflow**, so the first tarball carrying a provenance
attestation. `npm audit signatures` now answers for it rather than for the registry signature
alone. `0.1.0` remains the one exception, for the reason in its own entry below.

### Added

- **A command.** `npx @verdet/stealth` derives a key pair, turns a published meta-address into the
  one-time address a payment to it should go to, and takes a meta-address apart.

  It exists because the argument this package makes had a hole in it. The README says you do not
  have to take anybody's description of ERC-5564 on trust, and that was true only for people
  willing to write a program that imports it first.

  - **No network in it and none under it.** Nothing reads a chain, posts an announcement or
    contacts a registry. Every command is arithmetic over inputs you supply, which is what makes it
    safe to run on a machine you care about and what makes its output something you can check
    against any other implementation of the spec.
  - **Private keys are withheld unless you ask.** `keys` shows a meta-address and two public keys.
    `--show-secret` prints the rest, and says what a secret on a terminal costs you.
  - `--json` on any command, for piping. `--no-color` and `NO_COLOR` are honoured, and colour is
    off by default when the output is not a terminal.
  - The version in the banner is read from the manifest at startup rather than written into the
    source, so it cannot report a release that does not exist.

### Notes

- **The only new surface is the binary.** The library's exports are unchanged, so upgrading from
  `0.1.0` cannot break an import.
- **The command's tests spawn it as a process** rather than importing it, because the parts of a
  CLI that break live between `process.argv` and `process.exitCode`. The withholding of private
  keys is asserted from both directions, absent by default and present with the flag: a test that
  only checked the default would still pass if the flag had quietly stopped working, and the
  warning printed beside them would then be attached to nothing.

## 0.1.0

Released 2026-09-20. First published version. Everything below runs in production at
[verdet.app](https://verdet.app).

Published by hand, which is the only version of this package that ever will be. npm attaches a
trusted publisher to a package that already exists, so creating the package had to come first.
From 0.1.1 the release workflow publishes by OIDC and every tarball carries a provenance
attestation.

### Receiving

- **Stealth derivation** (ERC-5564 scheme 1). One published meta-address, a different address for
  every payment, with nothing on chain joining one to the next.
- **Private requests.** The recipient picks the ephemeral key, so the payer receives one address
  and nothing that outlives the payment, and **nothing has to be announced at all**.
- **ERC-6538 registry and ERC-5564 announcer** call encoding, for the flow where the payer picks
  the key.
- **Published interoperability vector.** The specification does not fix how the shared-secret point
  is serialised; this is what we produce, so another implementation can find out whether it
  disagrees.

### Disclosure

- **Watch-only grants.** A viewing key and a spending public key rebuild every address a wallet
  handed out and sign nothing.
- **Scoped disclosure.** A viewing key per label, so handing over one period reaches that period
  and nothing else.
- **Zero-knowledge proofs.** Schnorr and Chaum-Pedersen sigma protocols with Fiat-Shamir: prove you
  control a set of addresses, or that a payment was derived for you, without revealing a key.

### Acting

- **Linkable ring signatures** (CryptoNote LSAG). Sign as one member of a set. The key image is
  constant for a signer across every ring, so one action per holder can be counted by somebody who
  cannot identify any of them.
- **Oblivious transfer** (Chou-Orlandi 1-of-N). Retrieve one record from a server that holds many
  without the server learning which. Client half only: nothing is oblivious until a server speaks
  the other half.

### Holding

- **Vault.** PBKDF2 into AES-GCM from the platform, so no dependency is added to the path that
  touches a private key.
- **Permits** (EIP-2612), so an address holding no gas can still move its token.
- **Backup sheet** with a fingerprint per key, so a key copied wrong is named rather than
  discovered years later.
- **Sealed labels**, encrypted under the viewing key and readable only while the wallet is open.

### Known limits

Not defects, and not going away. The full list is in the
[README](README.md#what-it-does-not-do); the two that surprise people most:

- **Spending from several addresses joins them.** Receiving privately is the part this does well.
- **Amounts and timing are public.** Everything here is about identity and linkage.
