# Contributing

## Setting up

```bash
git clone https://github.com/verdet-app/verdet-stealth.git
cd verdet-stealth
npm install
npm test
```

Node 22 or newer. There is no build step to configure and no environment to set: if `npm test`
passes you have a working tree.

**Install the hooks once per clone**, because a hook is not cloned with the repository:

```bash
git config core.hooksPath .githooks
```

The `pre-push` hook runs the same checks CI runs. It has no override flag, which is the point of
it.

---

## The rules that are not negotiable

**Every claim has a check.** If a change adds a sentence to a doc or a comment that asserts a
privacy property, it adds the test that would fail if the property broke. A property nobody can
check is a property nobody should believe, including us.

**A limit is written at the size of the claim.** Where a module says what it protects, it says what
it does not, in the same paragraph and the same voice. A caveat moved to the bottom in smaller type
is a caveat designed not to be read.

**No new dependencies in the key path.** The list is two audited packages and it stays that way.
If something genuinely needs a third, open an issue first and expect the answer to be no.

**Refuse rather than truncate.** A key of the wrong length, a label too long, a ring of one: throw.
Silently accepting a shortened key is how a dropped leading zero becomes a different, working,
wrong wallet.

---

## Cryptography changes

Anything touching `derive`, `keys`, `ring`, `prove`, `oblivious` or `vault` needs, in the pull
request body:

- [ ] The construction named, and a reference. "Chou-Orlandi 1-of-N" is a review; "an OT scheme" is not.
- [ ] What goes into every hash, and why each input is there. Fiat-Shamir soundness is exactly this list.
- [ ] A test that fails if any public input is removed from a challenge.
- [ ] A test that two runs over the same input differ, where a nonce is involved.
- [ ] The limit, written into the module's own doc comment.

Changes that reimplement a primitive already in `@noble` will be closed. Curve arithmetic and
hash-to-curve are solved problems and ours would be worse.

---

## Commits

[Conventional Commits](https://www.conventionalcommits.org), scoped to the module:

```
feat(ring): add linkable ring signatures over secp256k1
fix(scope): hash the label length to stop two scopes colliding
test(prove): cover a substituted shared point
docs(security): name what is in scope
```

- One commit is one reviewable change. One to six files is normal.
- Subject in the imperative, under 60 characters, no trailing period.
- The body explains **why**, not what. The diff already says what.
- **No trailers of any kind.** The `pre-push` hook rejects co-author trailers and assistant
  identities in the author, committer or message. Contributors here are people.
- Never amend or force-push a commit that is already on `main`.

## Releasing

Publishing runs in CI and nowhere else, because a publish from a laptop cannot carry a provenance
attestation and an unattested tarball is the thing this library argues against. Version 0.1.0 is
the one exception in this package's history, and it exists only because npm attaches a trusted
publisher to a package that already exists, so something had to create the package first.

CI authenticates by [trusted publishing][tp]: the workflow exchanges a short-lived OIDC token with
the registry at publish time. **There is no npm token stored in this repository**, which is the
point. A long-lived publish credential sitting in a settings page is a credential that can be read
by anything that ever gains access to it.

[tp]: https://docs.npmjs.com/trusted-publishers

### The one-time setup, written down because it is done once and then forgotten

On npmjs.com, under the package's settings, add a trusted publisher:

| Field | Value |
|---|---|
| Publisher | GitHub Actions |
| Organization or user | `verdet-app` |
| Repository | `verdet-stealth` |
| Workflow filename | `release.yml` |
| Environment | leave empty |

Nothing else is needed. No secret is added to the repository, and if one ever appears there it is
a mistake rather than a step somebody forgot to undo.

1. Land the change on `main` with CI green.
2. Update `CHANGELOG.md`. An entry that changes a derivation says so at the top of it, because a
   derivation change means addresses that no longer match.
3. `npm version <patch|minor>` to bump the manifest and create the tag.
4. `git push --follow-tags`
5. Publish a GitHub release for that tag. The `release` workflow builds, tests, checks the tag
   against the manifest, and publishes with `--provenance`.

The workflow can be run by hand with `workflow_dispatch` to pack and verify without publishing,
which is how to prove the pipeline without spending a version number.

**Pre-1.0.** The surface can change between minor versions. Anything that changes a derivation is
a breaking change whatever the number says, because somebody's addresses stop matching.

## Pull requests

Branch per change, pull request into `main`. Green CI, and a body that says what would be different
for somebody using this if the change is wrong.
