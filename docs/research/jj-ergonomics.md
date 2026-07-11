# Research: jj's auto-snapshot, change-ids, and oplog/undo — and what transfers to loot

Grounding for wayfinder map #132 (jj-ergonomics trio). Primary source: the
Jujutsu docs (`docs.jj-vcs.dev`, latest) — [working copy](http://docs.jj-vcs.dev/latest/working-copy/),
[operation log](http://docs.jj-vcs.dev/latest/operation-log/),
[glossary](http://docs.jj-vcs.dev/latest/glossary/). Each section ends with the
**transfer question** to loot's model (the design tickets #134/#135/#136 pick these up).

## 1. Auto-snapshot — "the working copy is a commit"

**How jj does it.** The working copy is itself an editable commit (`@`). "Most `jj`
commands you run will commit the working-copy changes if they have changed." Every
command runs three steps: **(1)** snapshot the working copy (recorded as an
operation), **(2)** build the new commits in memory (another operation), **(3)**
update the working copy to match. A snapshot **amends `@` in place** — "the
resulting revision will replace the previous working-copy revision" — there is no
staging area. Starting a new change is explicit: `jj new <commit>` sets `@` to a
fresh empty commit on top. Added files are **implicitly tracked** by default
(`snapshot.auto-track` config; `.gitignore` suppresses); an optional filesystem
monitor (watchman) avoids re-scanning large trees.

**Transfer to loot (→ #135).** loot already has this shape (ADR 0006: the working
tree *is* the working change) but snapshots **only on explicit `loot status -m`**.
The gap is just making it implicit — snapshot at the **start of every command**,
like jj's step 1. loot's snapshot is already visibility-aware and O(delta) (#98),
so command-time cost is plausibly fine; no watchman needed initially. The real
work is the **verb reconciliation**: jj keeps an explicit `jj new` (change
boundary) while snapshot is implicit — loot's `new` (finalize) and `status`
(snapshot+report) must be re-split so `status` becomes a pure report and the
snapshot rides on every verb. Message capture moves to describe-after (jj's
`jj describe`), since there's no `-m` at an implicit snapshot.

## 2. Stable change-ids — change-id vs commit-id

**How jj does it.** Two identifiers per commit:
- **Change ID** — "typically 16 bytes long and often **randomly generated**,"
  assigned at creation and **stable across rewrites**: "rewriting a commit results
  in a new commit… but the change ID generally remains the same." Displayed as 12
  letters (k–z). Changes "don't exist as objects, only the change ID does."
- **Commit ID** — the content hash (the Git commit id under the Git backend), 20
  bytes, **changes on every rewrite**.

Crucially, a change ID can map to **more than one commit** — a **"divergent
change"** (edited two ways, e.g. on two machines) — which jj **tolerates and
labels `divergent`** rather than forcing agreement. And under the Git backend the
change-id lives in a **side table, not in the git commit**, so it is **local to a
repo** — two clones over git do **not** share change-ids.

**Transfer to loot (→ #134, the keystone).** This is where jj's model **does not
just copy over**, because loot's ids are load-bearing in ways jj's are not:
- **Signing (ADR 0018).** loot *signs the change id* at finalize (`compute_change_id`
  folds author+parents+message+tree). A jj-style stable id is **random and
  content-independent**, so it cannot be the thing a signature commits to — the
  signature must cover the **content hash** (loot's current id, now playing jj's
  "commit-id" role), with the stable id as separate, unsigned-or-separately-signed
  metadata. Clean split: **content id = integrity/signing/dedup anchor; stable id
  = the durable handle**.
- **Sync (ADR 0011) — the hard part.** jj change-ids are **local and uncoordinated**;
  loot's travel in bundles and must mean the same thing to every peer. Two forks
  for #134: **(a)** accept jj's model — stable ids are locally minted, and the
  "same logical change" edited on two machines becomes a **divergent change** loot
  must represent and display (fits loot's existing multi-head/converge model
  surprisingly well); or **(b)** derive the stable id from something both peers
  agree on (first-parent + author + a nonce?) so independent mints collide —
  harder, and arguably reinvents content-addressing. **Lean: (a)** — divergent
  changes are the honest distributed answer and loot already reasons about forks.
- **git-bridge (ADR 0028).** The ferry already emits a `Loot-Change-Id` trailer.
  Decide whether that carries the *content* id (today) or the new *stable* id —
  fog flagged on the map.

## 3. Oplog + undo — operations over repo *views*

**How jj does it.** Every command records an **operation**: "a snapshot of how the
repo looked at the end of the operation" — a **view** object holding all heads,
bookmark/tag positions, git refs, and **the working-copy commit per workspace**,
plus parent-op pointers and metadata (time, user, host, description). The log is
**append-only**, addressed relative to now (`@-` parent op, `@+` child). `jj undo`
steps back one operation; `jj op restore <op>` **restores the entire repo view**
to an earlier point; `jj op log` lists them. Concurrency is **lock-free**: "you
can run concurrent `jj` commands without corrupting the repo, even on different
machines" — each command loads the latest op and doesn't see concurrent ones;
clashes surface as **divergent operations** to resolve later.

**Transfer to loot (→ #136).** loot has **no oplog** today. The model transfers
well because loot's mutable state is small and already file-backed in `.loot/`
(RepoStore, ADR 0017): an operation snapshots the **change-graph heads + the
ambient dock's tip/working pointer** (the loot analogue of jj's view). Open
questions for #136: does undo also cover the **keyring** (a `grant`/`maroon` undo)?
The **append-only** graph means undo should add a **compensating op**, never
delete nodes. And the **local-only boundary (ADR 0011)**: you cannot undo a change
a peer already `pull`ed — undo rewinds *local view/pointers*, not published
history. jj's lock-free "divergent operations" idea maps onto loot's existing
concurrent-writer tolerance (docks fork; the relay accumulates forks).

## Bottom line for the design tickets

- **Auto-snapshot (#135)** is the *smallest* delta — loot already has the model;
  make it implicit + reconcile the `status`/`new`/`describe` verbs.
- **Stable change-ids (#134)** is the *keystone*: jj's random+local id can't be
  copied wholesale because loot **signs** and **syncs** its ids. The likely shape
  is content-id (signed, integrity) **+** a separate durable stable-id, with
  **divergent changes** as the honest answer to independent minting.
- **Oplog+undo (#136)** transfers cleanly (view = graph heads + dock pointers),
  gated by the local-only (un-pushed) boundary and whether the keyring is in scope.
