# Contributing to puddle

Thanks for wanting to help. puddle is a personal project of Tijs van Kampen, licensed
GPL-3.0-or-later (see `LICENSE`). Questions about contributing or the CLA:
<puddle@tijsvankampen.be>. Security problems: see [SECURITY.md](SECURITY.md), not a public issue.

## Before your first pull request: the CLA

Every contributor signs the [puddle Individual Contributor License Agreement](CLA.md) (CLA) once,
before their first contribution is merged. It is the Harmony Individual CLA (HA-CLA-I 1.0) with its
placeholders filled in.

What it means in short (the [CLA](CLA.md) itself is what counts):

- **You keep the copyright** in your contribution and can use it however you like (§2.1(a)).
- You give the project owner a broad, irrevocable, transferable licence to your contribution,
  including a patent licence (§2.1(b), §2.2).
- **The owner may relicense** your contribution under any licence, including permissive or
  proprietary ones, but must always also offer it under the licence puddle used when you submitted
  it (§2.3, Harmony "Option Five"). This keeps options open, for example moving puddle under an
  organisation later; your contribution stays available under GPL-3.0-or-later either way.
- You confirm the work is yours to give (§3). **If you write code as an employee**, your employer
  may own it: get your employer's approval first (§3(c)), or ask us about the entity version.

### Signing the CLA

1. Read [CLA.md](CLA.md) (version 1.0).
2. Open your pull request.
3. Post this comment on the pull request, from the GitHub account that made the commits:

   > I have read the puddle CLA (version 1.0) and I hereby sign it.

That comment is your electronic signature. You sign once per CLA version, not per pull request. If
the CLA's version changes, you are asked to sign the new version on your next pull request.

## Work you did not write

Only submit work you wrote yourself. If a change includes code, text or images written by someone
else (copied from another project, generated from a template, and so on):

- put it in a separate commit, not mixed with your own work;
- say in the pull request where it comes from and under which licence, with a link;
- mark it in the pull request description as "Submitted on behalf of a third party: <name>".

Material under a licence that isn't compatible with GPL-3.0-or-later can't be accepted. Do not
submit code copied from, or translated from, Huddle (infosupport/huddle): puddle takes only ideas
from it.

## Pull requests

- Branch from `develop` and open the pull request against `develop`. `main` holds released
  versions only.
- Keep a pull request to one change, with a description of what and why.
- Run `scripts/check.sh` before pushing (or enable the hooks: `git config core.hooksPath .githooks`).
  The rules your change must meet are in [docs/STANDARDS.md](docs/STANDARDS.md).
- By submitting a pull request you confirm that your contribution falls under the CLA you signed.
- Keep code, comments, docs and commit messages self-contained: say the reason in words or cite an ADR or
  spec section, and don't reference ticket or planning-note IDs. The `standalone` gate and the
  `commit-msg` hook check this.

### Maintainer note: branch protection

Rulesets on `main` and `develop` block force-push and deletion only (agents and the maintainer land
by fast-forward push), and `v*` tags can't be deleted or moved. There is no required pull request or
status check yet. Tighten that when outside contributors join: require a PR with the `linux (all gates)`
check on `develop` and `main`, and `windows-msvc (build, clippy, tests)` on `main`.

## Licence headers

Every source file starts with an SPDX licence identifier in the file's own comment syntax, as its
first line (after a shebang, if any):

```rust
// SPDX-License-Identifier: GPL-3.0-or-later
```

```sh
# SPDX-License-Identifier: GPL-3.0-or-later
```

```html
<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
```

Package manifests carry the same identifier (`license = "GPL-3.0-or-later"` in `Cargo.toml`,
`"license": "GPL-3.0-or-later"` in `package.json`). Files that come from elsewhere keep their own
identifier and copyright line (see "Work you did not write"). Generated files and lock files need
no header.
