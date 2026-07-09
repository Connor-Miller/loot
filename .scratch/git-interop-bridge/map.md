# Map: Chart the git interop bridge (bidirectional loot ↔ git mirror) to a spec

<!-- wayfinder:map -->

## Destination

A single, implementation-ready spec for a **bidirectional loot ↔ git mirror** —
keeping a loot repo and a git repo continuously in step — with every design
decision pinned so an implementer can build it with no open questions. Planning
map: it produces the spec, not the implementation.

## Notes

**Why this is hard (the core tension).** git holds plaintext with no notion of
loot's per-content **visibility** (ADR 0003), its **signed, multi-parent Changes**
(ADR 0018), or its deliberate **absence of branches** (ADR 0022, the anti-thesis).
So loot→git is a *lossy projection* and git→loot cannot natively restore what git
never held. How symmetric the mirror must be is the pivotal decision (ticket 01).

**Domain grounding.** A loot *Change* is permission-bearing, ed25519-signed,
DAG-shaped (multi-head forks, no branches); content is *sealed* per-path via
`.lootattributes`; convergence is the decrypt-then-merge classifier (ADR 0001).
git-only artifacts loot won't hold: none. loot-only artifacts git can't hold:
grants, manifest, attestations (and never the keyring).

**Execution constraint.** Claude cannot run `cargo`/`git` in this environment.
Anything empirical (a plumbing spike, a round-trip test) is handed to Connor to run
in his Rust/git environment; use the run-loop pattern from
`.scratch/ca4-buoys/issues/03-rust-run-loop.md`. Prefer decisions makeable from
reading code.

**Tracker.** Local-markdown here (`gh` unavailable); push up with
`.scratch/sync-to-github.md`. The canonical tracker is GitHub
(`docs/agents/issue-tracker.md`); this map coexists with the thesis-proof
milestone (#54), which lists "git interop bridge" as fog.

**Skills per session:** `/grilling`, `/domain-modeling`, `/research`,
`/prototype`. Refer to tickets by name.

## Decisions so far

<!-- one line per resolved ticket: gist + link -->

- [01 — Symmetry & the visibility boundary](issues/01-symmetry-and-visibility-boundary.md)
  — git = a plaintext mirror of the **syncing identity's readable tree**; loot is
  the permission source of truth. loot→git = `surface` for that identity (sealed
  paths **omitted entirely**, reusing `surface`'s skip). git→loot = write files +
  run loot's normal `.lootattributes` snapshot, so sealing happens **at ingest**
  and only unmatched files default to Public. Hard constraint: the git remote must
  be trusted as much as the identity — **not** a public host.
- [02 — Change ↔ commit & DAG mapping](issues/02-change-commit-dag-mapping.md) —
  1:1 change=commit with `Loot-Change-Id`/`Loot-Author`/`Loot-Signature` trailers;
  **deterministic** synthetic dates (base epoch + generation, tie-break change-id);
  every head kept under `refs/loot/heads/<id>` with `main` at a designated dock
  (home/harbor); reverse = trailer short-circuit (lossless) + recompute only for
  git-native commits. Mark map must carry an `origin: loot|git` flag so git-native
  changes aren't re-emitted.
- [03 — Identity & authorship mapping](issues/03-identity-authorship-mapping.md) —
  identity map `pubkey ↔ Name <email>` auto-seeded from git config (self), peer-
  registry fallback for others; authoritative id = `Loot-Author` trailer. git-native
  commits → syncing identity if it matches, else **unauthored/legacy** change with a
  `Git-Author:` trailer. Mirrored commits are **SSH-signed with loot's ed25519 key**
  + keep the `Loot-Signature` trailer.
- [05 — Divergence & reconciliation](issues/05-divergence-and-source-of-truth.md) —
  **loot is the reconciliation authority**: git edits are ingested as forks and
  merged by loot's converge classifier (ADR 0001), then re-projected; a git edit is
  just another fork. Divergence detected via **last-synced pointers** in the mark
  map; conflicts surface + resolve **in loot** (git held at last clean state);
  visibility invariant — reconciliation never surfaces sealed into git nor clobbers
  a sealed path (converge's relay role carries unreadable ciphertext).
- [04 — Mechanism & prior art](issues/04-mechanism-and-prior-art.md) — survey in
  [assets/04-mechanism-survey.md](assets/04-mechanism-survey.md): use **git2
  (libgit2)** primary (gitoxide a future pure-Rust swap; fast-import+marks a bulk
  fallback). Prior art (jj, git-cinnabar) validates the mark map, `refs/loot/*`
  GC-protection refs, and derived ids for git-native commits; we keep loot metadata
  in **commit trailers** (vs jj's sidecar) for portability.
- [06 — Sync mechanism & mark-map format](issues/06-sync-mechanism-and-mark-map.md)
  — one-shot **`loot ferry`** verb (bidirectional reconcile pass; watch/hooks
  deferred); **git2** plumbing; mark map in **`.loot/git-mirror/`** via RepoStore,
  local-only (`marks`: sha↔change-id↔origin; `state`: last-synced pointers),
  rebuildable from trailers; identity-map + allowed-signers + mirror remote also
  local. loot-only artifacts (grants/manifest/attestations) **not projected** in v1
  (attestations→git-notes a future enhancement).

## Not yet specified

<!-- in-scope fog; graduates into tickets as the frontier advances -->

_Nothing left._ All seven tickets are resolved.

---

**Map status: destination reached — route fully walked.** Every design and
mechanism decision is pinned and the hand-off spec exists:
[docs/adr/0026-git-interop-bridge.md](../../docs/adr/0026-git-interop-bridge.md)
(decision record) and [issues/GB1-git-interop-bridge.md](../../issues/GB1-git-interop-bridge.md)
(implementation-ready ticket + test plan). Next step is implementation, not
wayfinding.

## Out of scope

<!-- ruled beyond this destination; never graduates -->

- **Import-only migration** (git→loot onboarding) and **git-as-dumb-backup**
  (encrypted objects in a git remote) — the other bridge shapes not chosen;
  separate future efforts.
- **Anything relay-related** — excluded from this effort by request.
- **Public-host mirror (ANYONE-public projection)** — ruled out by ticket 01: the
  chosen projection mirrors the syncing identity's full readable (private)
  plaintext, so the git remote must be trusted. Mirroring only ANYONE-public
  content to a public host is a separate future variant, not this map.
- **Implementing / building the bridge** — the hand-off target downstream of this
  map, not a decision on the route.
