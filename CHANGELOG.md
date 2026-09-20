# Changelog

Notable changes, newest first. This project is pre-1.0: the surface can change between minor
versions, and anything that changes a derivation will say so at the top of its entry, because a
derivation change means addresses that no longer match.

## Unreleased

Nothing yet.

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
