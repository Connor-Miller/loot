# git interop bridge: bidirectional loot ↔ git mirror

## Status

accepted (spec; implementation pending)

## Context

loot dual-runs with git today (the thesis-proof milestone keeps a git repo for
backup + issues), and "git interop bridge" has sat in `CONTEXT.md` as "important
eventually." The recurring pain is *two histories drifting*. This ADR specifies a
**bidirectional loot ↔ git mirror**: keep a loot repo and a git repo continuously
in step, so git can serve as a familiar backup/inspection surface without loot
ceasing to be canonical.

The design is constrained by a fundamental model gap. git holds plaintext and has
no notion of loot's:

- **per-content visibility** (Public / Restricted / Embargoed, ADR 0003),
- **signed, multi-parent Changes** (ADR 0018),
- **absence of branches** (ADR 0022 — repo-level branches are the anti-thesis),
- and loot Changes carry **no timestamp**.

So loot→git is a *lossy projection* and git→loot cannot natively restore what git
never held. Charted in `.scratch/git-interop-bridge/` (wayfinder), non-relay.

## Decision

### Symmetry: git is a plaintext mirror of the syncing identity's readable tree; loot is the permission source of truth

- **loot → git** = `surface` for the syncing identity (reuse
  `DagRepo::surface_with_report`). The git tree is exactly what that identity can
  decrypt — the **full readable set**, not just ANYONE-public. Sealed / not-yet-
  revealed paths are **omitted entirely** (no filename, no placeholder — `surface`
  already skips them), so there is no path-name or structure leak.
- **git → loot** = write incoming files into the working tree, then run loot's
  normal `.lootattributes` snapshot (ADR 0006), so classification happens **at
  ingest**: a path matching a restricted/embargoed glob is sealed immediately and
  never lands public; only unmatched files default to Public — identical to normal
  loot authoring.
- **Hard constraint:** the git side carries the identity's private plaintext, so
  the **git remote must be trusted as much as that identity** — this projection
  must NOT be pushed to a public host. A public-host (ANYONE-only) projection is a
  separate future variant, out of scope here.

### History: 1:1 change=commit with trailers; deterministic dates; a ref per head

- Each loot Change ↔ one git commit. Tree = the surfaced tree above; parents = the
  mapped parent commits. loot-only metadata rides in **commit trailers** for a
  lossless, verifiable round-trip:
  `Loot-Change-Id`, `Loot-Author` (pubkey hex), `Loot-Signature` (when signed).
- **Deterministic dates** (loot stores none): committer = author date =
  `BASE_EPOCH + generation` (ancestor count), tie-broken by change-id —
  reproducible, ancestry-respecting for `git log --date-order`.
- **DAG / refs:** every loot head is kept under `refs/loot/heads/<change-id>` (with
  a friendly `refs/loot/docks/<name>` where a head is a known dock tip) so all
  commits stay reachable (GC-safe); `refs/heads/main` points at a designated dock's
  tip (`home` by default, or `harbor`). These refs are mechanical reachability
  handles, **not** loot branches — the no-branches thesis is intact.
- **Reverse:** a commit carrying `Loot-Change-Id` maps straight back (lossless,
  idempotent); a git-native commit (no trailer) gets a fresh change-id via
  `compute_change_id`. The mark map carries an `origin: loot|git` flag so a
  git-native change is never re-emitted to git as a duplicate commit.

### Identity: an identity map auto-seeded from git config; SSH-signed commits

- A lightweight `pubkey ↔ Name <email>` map, **auto-seeded for self** from
  `git config user.name/user.email` so git history looks native and the syncing
  identity's own git-native commits resolve back to it; unmapped peers fall back to
  the peer-registry nickname + `<nickname>@loot.local`. The `Loot-Author` trailer
  stays authoritative.
- **git-native authorship:** the syncing identity if the git author resolves to it
  (signed as part of the sync); otherwise an **unauthored/legacy** loot change
  (`author: None`, already supported) with the original author kept in a
  `Git-Author:` trailer. Never forge another identity's loot signature.
- **Signing:** mirrored commits are SSH-signed (`gpg.format=ssh`) with loot's
  OpenSSH ed25519 key, so one key verifies in both worlds; the `Loot-Signature`
  trailer is retained for loot-side verification.

### Reconciliation: loot is the merge authority; a git edit is just another fork

- When both sides advance, ingest git-native commits as loot changes, then run
  loot's converge classifier (ADR 0001, decrypt-then-merge) against loot's heads,
  and re-project the converged result to git. **One** visibility-aware merge engine;
  git never merges.
- **Divergence detection:** per-side **last-synced pointers** in the mark map
  (loot heads + git refs at last agreement); divergence = both advanced past them.
  Incremental, O(delta).
- **Conflicts** surface via the shipped `loot conflicts` / `loot resolve` + CA3
  porcelain and are resolved **in loot**; a conflicted path is held at its last
  clean state in git until resolved (no git-marker injection). Non-conflicting
  paths sync normally.
- **Visibility invariant:** ingest seals per `.lootattributes`; projection surfaces
  only readable content; the converge classifier's **relay role** carries content
  the syncing identity can't read as ciphertext without merging — so reconciliation
  can never surface sealed content into git nor clobber a sealed path.

### Mechanism: a one-shot `loot ferry` verb over git2

- **`loot ferry`** runs one bidirectional reconcile pass (ingest → converge →
  project), matching push/pull's deliberate-act stance. `--watch`/daemon and
  git-hook auto-triggers are deferred.
- **Plumbing:** git2 (libgit2) — direct object/ref read+write; loot does the merge,
  so git's merge/push aren't needed. gitoxide is a future pure-Rust swap;
  fast-import+marks a bulk fallback.
- **Mark map** in `.loot/git-mirror/` via RepoStore (ADR 0017), **local-only**
  (never synced, like `keyring`/`escrow`): `marks` (sha ↔ change-id ↔ origin) and
  `state` (last-synced pointers). Line-oriented (fast-import `:mark SHA` precedent);
  rebuildable from `Loot-Change-Id` trailers if lost. Identity map, allowed-signers,
  and the mirror-remote config live locally too.
- **loot-only artifacts** (grants, manifest, attestations) are **not** projected in
  v1 (git mirrors only the working tree; keyring never leaves loot).

## Considered alternatives

- **Public (ANYONE-only) projection** — safe for a public git host, but doesn't meet
  the full-backup goal. Deferred as a separate variant.
- **git does the merge; loot ingests the result** — reuses git merge, but loses
  visibility-aware convergence and risks sealed content in git merges. Rejected.
- **Sidecar change-id table (jj-style)** instead of trailers — cleaner commit
  messages, but doesn't survive a plain `git clone`; trailers are more portable.
- **Remote-helper (`git-remote-loot`) / daemon** — seamless `git push loot::` UX,
  but more surface than a v1 needs. Deferred.
- **Map attestations to git notes/tags now** — richer mirror, scope creep. Deferred.

## Consequences

- git becomes a faithful, private, signed backup/inspection surface for loot, with
  loot remaining canonical and permission-authoritative.
- Reconciliation reuses loot's shipped converge classifier and conflict verbs — no
  second merge engine, and the visibility invariant is preserved by construction.
- The mark map (id↔sha + origin + last-synced pointers) is the spine; it is
  local-only and rebuildable, so a lost map is not data loss.
- The trusted-remote constraint is a real operational limit: the mirror target must
  be private. Mixing this with the milestone's public GitHub backup requires the
  (out-of-scope) public projection.
- New surface: a `loot ferry` verb, a git2 dependency, `.loot/git-mirror/` in
  RepoStore, and the identity map + SSH signing config.
