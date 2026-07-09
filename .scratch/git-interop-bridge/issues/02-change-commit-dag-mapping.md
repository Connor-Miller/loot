# 02 — Change ↔ commit & DAG mapping

Type: grilling
Status: resolved
Blocked by: —

## Question

How does loot's history model map to git's, both directions?

- **Change → commit.** A loot Change (message, parents, per-path tree, author
  pubkey, signature) → a git commit. 1:1? What carries in the commit message /
  trailers (change-id, author pubkey)?
- **DAG shape & refs.** loot has **no branches** (ADR 0022) and can have multiple
  heads (forks). How is that represented in git — a single mirrored ref, one ref
  per head, or a synthetic convergence? How are loot merges (multi-parent)
  rendered?
- **commit → Change.** Reverse construction: a git commit with no loot metadata →
  a Change (author, parents, tree). What's synthesized vs required?
- **Stable identity.** How change-ids and commit-shas correspond and stay stable
  across re-syncs (feeds the mark-map fog item).

## Notes

Independent of 01 for the *structural* mapping; a commit's tree *contents* come
from 01's visibility boundary. See how jj's git backend and git-cinnabar model
this (ticket 04).

## Answer

**Change ↔ commit: 1:1 with loot trailers.** Each loot change maps to exactly one
git commit. Tree = the surfaced (readable) tree from ticket 01. Parents = the
mapped commits of the change's parents. The commit message is the change message
plus trailers carrying loot-only metadata for a lossless, verifiable round-trip:

```
Loot-Change-Id: <hex change id>
Loot-Author: <ed25519 pubkey hex>
Loot-Signature: <hex signature>     # present for signed (finalized) changes
```

`compute_change_id` folds author+message+parents+tree, so the trailers carry
everything the reverse needs without recomputation.

**Timestamps: deterministic derivation** (loot stores none; git requires them).
Recommended concrete scheme (implementer may refine): author date = committer date
= `BASE_EPOCH + generation`, where `generation` = the change's ancestor count
(topological depth), tie-broken by change-id. This is reproducible (no reliance on
the mark map for the sha), respects ancestry so `git log --date-order` reads
sensibly along a line, and lets concurrent changes share a timestamp (acceptable).

**DAG / refs: one ref per head, main at a designated dock.** loot's forks are
first-class, so every head is preserved:

- `refs/loot/heads/<change-id-hex>` for every loot head → all commits reachable
  (git gc safe). Where a head is a known dock tip, also publish
  `refs/loot/docks/<name>`.
- `refs/heads/main` points at a **designated dock's tip** — `home` by default, or
  the `harbor` dock if present (ADR 0022) — giving humans a normal branch.
- Prune a head ref once it is no longer a loot head (its commits remain reachable
  via the merged child).
- Thesis note: these git refs are mechanical reachability handles, **not** loot
  branches (which stay a permission-scope non-goal, ADR 0022) — no loot semantics
  ride on them.

**Reverse (commit → Change): trailer short-circuit + recompute for git-native.**

- A commit carrying `Loot-Change-Id` maps straight back to that change — never
  recomputed — so loot→git→loot returns the identical change-id (idempotent).
- A commit authored natively in git (no trailer) gets a synthesized Change:
  author via the identity map (ticket 03), parents = mapped change-ids of parent
  commits, tree = commit tree sealed at ingest per `.lootattributes` (ticket 01),
  message = commit message; change-id via `compute_change_id`. Record the new
  change-id↔sha pair.

**Consequence for the mark map (feeds the fog item):** the persistent map must be
`change-id ↔ sha` **plus an `origin: loot|git` flag**, so a git-native change that
was ingested is never re-emitted to git as a second commit (which would fork its
identity). The loot→git projection skips `origin: git` changes already present
under their original sha.

**Feeds:** 05 (divergence uses the mark map + head refs to detect and reconcile);
the sync-mechanism / mark-map fog item (now specified to carry origin + support the
deterministic-date scheme).

