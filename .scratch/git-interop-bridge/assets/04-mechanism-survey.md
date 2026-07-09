# Mechanism & prior-art survey — git interop bridge (ticket 04)

Research asset for `.scratch/git-interop-bridge/issues/04-mechanism-and-prior-art.md`.
Purpose: choose the git plumbing and learn from foreign-VCS bridges before
specifying the sync mechanism (ticket 06).

## Rust git plumbing options

| Option | What it gives | Fit for the loot↔git mirror |
| --- | --- | --- |
| **git2 (libgit2 bindings)** | Mature, full read/write of objects, refs, index, config; integrity checks (`strict_hash_verification`, `strict_object_creation`); large ecosystem. | **Recommended primary.** We write commits/trees/refs directly and control the mapping; we do NOT need git's merge or push (loot is the merge authority, ticket 05). Direct object writing fits both directions cleanly. |
| **gitoxide (`gix`)** | Pure-Rust, lean/fast; full read/write of objects/refs/index/config today. But push, full merge, rebase, hooks still under development; smaller ecosystem; some perf caveats reported. | **Future swap.** We don't need its unfinished bits (merge/push), so it *could* serve for object/ref writing — but git2 is the safer first cut. Watch gix maturity for a later pure-Rust move (jj already uses it, see below). |
| **`git fast-import` / `fast-export` + marks** | Stream commits into/out of git; `--export-marks`/`--import-marks` persist a `:markid SHA-1` table across incremental runs. Battle-tested, language-agnostic, incremental. | **Reusable pattern / bulk path.** The marks file *is* a ready-made incremental id↔sha map. Good for the initial/bulk loot→git projection; for fine bidirectional control, direct git2 writes beat generating import streams. |
| **git-remote-helper (`git-remote-loot`)** | Implement the remote-helper protocol so `git push/pull loot::…` works transparently; `export`/`import` capabilities delegate to fast-export/import with marks for incremental. | **Heaviest / best UX.** How git-cinnabar and git-remote-hg integrate. More protocol surface than we need for a v1 mirror; revisit if seamless `git push loot::` is wanted later. |

## Prior art (and how it validates our decisions)

**Jujutsu (jj) git backend** — the closest analogue (a change-id model layered on git).

- Stores data git can't hold (change-id, predecessors) in a **sidecar StackedTable**
  (`.jj/repo/store/extra/`), keyed by commit.
- Git-created commits (no jj data) get the **bit-reversed commit id** as their
  change-id — i.e. git-native commits get a *derived* stable id.
- Protects commits from GC with a **ref per commit** in `refs/jj/keep/`.
- Uses **gitoxide** to read/write commits and refs.

→ Validates our mark map (id↔sha), our "git-native commits get a derived loot
change-id" rule (ticket 02/03), and the **refs namespace to keep commits
reachable** (we chose `refs/loot/*`; jj uses `refs/jj/keep/`). **Divergence from
jj:** jj keeps change-id in a *sidecar table*; we chose **commit trailers**
(ticket 02) — more portable (survives a plain `git clone`, human-visible in
`git log`) at the cost of message noise. Worth recording as a conscious trade.

**git-cinnabar** (hg ↔ git remote helper).

- Maintains **metadata mapping git sha ↔ hg changeset** — the mark map is the core
  artifact, exactly as ours is.
- Can **graft metadata onto existing commits**, enabling migration from other
  hg→git tools while preserving existing git commits.
- Exposes hg bookmarks as `refs/heads/$bookmark`.

→ Validates the mark map as the spine, and the "graft onto an existing git history"
idea if we ever adopt a pre-existing git repo. Its remote-helper design is the
heavier-integration reference.

**git fast-import marks** — canonical incremental format: `:markid SHA-1`, dumped
via `--export-marks`, reloaded via `--import-marks` to resume across runs.

→ A proven, concrete shape for our persistent mark map + O(delta) resync.

## Recommendation into ticket 06

- **Plumbing:** git2 (libgit2) as the primary, direct object/ref read+write in both
  directions; keep gitoxide on the radar as a pure-Rust successor. fast-import with
  marks is a fallback for bulk projection.
- **Mark map:** persist `change-id ↔ sha` (+ `origin` from ticket 02, + last-synced
  pointers from ticket 05); the fast-import `:mark SHA` format is a good precedent.
- **GC safety:** keep every loot head under `refs/loot/*` (jj's `refs/jj/keep/`
  confirms the pattern).
- **Trailers vs sidecar:** stay with commit trailers (portability) — note jj's
  sidecar as the considered alternative.
- **Incremental:** sync only beyond the last-synced pointers; never full-repo per run.

## Sources

- [Jujutsu — Architecture (technical docs)](https://docs.jj-vcs.dev/latest/technical/architecture/)
- [git-cinnabar (glandium/git-cinnabar)](https://github.com/glandium/git-cinnabar)
- [gitoxide (GitoxideLabs/gitoxide)](https://github.com/GitoxideLabs/gitoxide)
- [git-fast-import documentation](https://git-scm.com/docs/git-fast-import)
- [gitremote-helpers documentation](https://git-scm.com/docs/gitremote-helpers)
- [git-fast-export documentation](https://git-scm.com/docs/git-fast-export)
