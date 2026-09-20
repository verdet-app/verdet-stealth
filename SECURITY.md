# Security

## Reporting something

Email **admin@verdet.app**, or open a [private advisory][advisory] on this repository.

Please do not open a public issue for anything that affects key material, signature forgery, or the
privacy properties in the table below. A public issue for those is a disclosure, not a report.

**What to expect.** An acknowledgement within 72 hours and an assessment within 7 days. If a fix is
needed you will hear what it is and when it lands. If the report turns out not to be a
vulnerability you will hear why, because "we looked and here is what we found" is worth more than
silence to anybody who took the time.

[advisory]: https://github.com/verdet-app/verdet-stealth/security/advisories/new

---

## The honest status

> [!WARNING]
> **This code has not been independently audited.** It is used in production by
> [verdet.app](https://verdet.app), which is a statement about our own risk appetite and not a
> substitute for review.

The primitives underneath it are audited: point arithmetic, hash-to-curve and secret generation all
come from [@noble/curves][noble] and are not reimplemented here. What is unaudited is the protocol
layer written in this repository, which is exactly the part a reviewer should spend time on.

[noble]: https://github.com/paulmillr/noble-curves

---

## What is in scope

A report is in scope if it breaks one of these. They are listed in the order a break would matter.

| # | The property | Broken if |
|---|---|---|
| 1 | Spending needs the spending key | Anything derives a spending key from a watch key, a scoped key, a proof, a signature or a key image |
| 2 | A scope reaches one label | Anything reaches `vk(labelB)` or the master from `vk(labelA)` |
| 3 | A ring signature names nobody | Anything identifies the signer from a signature, or produces one without a member key |
| 4 | Linkability is per signer, not per ring | Two signers collide on a key image, or one signer produces two |
| 5 | A proof reveals nothing | Anything recovers a viewing key from a payment proof, or forges one for a statement it does not hold |
| 6 | Oblivious means oblivious | The sender learns the choice, or the receiver opens a branch it did not choose |
| 7 | The vault resists an offline guess | Anything opens a blob materially faster than the iteration count implies |

## What is out of scope

- **Amounts, timing and the sender.** These are public by design and saying so is not a finding.
  See "What it does not do" in the [README](README.md#what-it-does-not-do).
- **Spending from several addresses joins them.** Known, documented, unsolved.
- **A ring of two is a coin flip.** Choosing decoys is the caller's problem.
- **A compromised page.** A script running on the origin can read a passphrase as it is typed. The
  vault protects a stored copy, and that limit is stated where the passphrase is asked for.
- **Denial of service against a caller's own machine**, such as asking for a ring of a million.
  There is a ceiling and it throws.

---

## If you are reviewing this

The three habits worth checking first, because they are where this class of code usually fails:

1. **Fiat-Shamir completeness.** Every public value a verifier checks must be inside the challenge
   hash. `controlChallenge` and `paymentChallenge` in [`src/prove.ts`](src/prove.ts), and
   `challenge` plus `ringPrefix` in [`src/ring.ts`](src/ring.ts). The tests change each input in
   turn and require failure; a value that is not covered is a forgery.
2. **Nonce reuse.** Every proof and signature draws a fresh scalar and none is derived from the
   message. Reuse across two signatures leaks the key by subtraction.
3. **Domain separation.** Every construction hashes a distinct tag before anything else, so the
   viewing key used for scopes cannot collide with the same key used for requests or labels. Grep
   for `TextEncoder().encode('verdet/` to see all of them at once.

Length and range checks refuse rather than truncate throughout. That is deliberate: a silently
shortened key is a different, working, wrong key, and it fails at the only moment it matters.
