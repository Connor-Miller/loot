# 04 — Mechanism & prior art (research)

Type: research
Status: resolved
Blocked by: —

## Question

Survey the plumbing and prior art so the sync mechanism is chosen from evidence,
not guessed. Produce a markdown summary as a linked asset.

- **git plumbing options for Rust:** `git2`/libgit2, shelling to `git`
  fast-import/fast-export, git remote-helper protocol. Trade-offs for a
  bidirectional, incremental mirror.
- **Prior art on bidirectional/foreign-VCS mirrors:** jj's git backend (how it
  represents its ops over git), git-cinnabar (hg↔git), git-remote-hg,
  git-remote-helpers, `git fast-import` mark files. What each does for the
  identity map, the mark map, and divergence.
- **Incremental sync patterns:** how they persist a foreign-id↔sha map and do
  O(delta) re-syncs.

Output: `.scratch/git-interop-bridge/assets/04-mechanism-survey.md` (link it here).

## Notes

AFK — reading only, no loot decisions. Feeds 02, 05, and the mechanism fog item.
Run any `git`/`cargo` probing via the ticket-03-style handoff (Connor's env).

## Answer

Summary written to [assets/04-mechanism-survey.md](../assets/04-mechanism-survey.md).
Headlines:

- **Plumbing:** use **git2 (libgit2)** as the primary — direct object/ref read+write
  in both directions; we don't need git's merge/push (loot is the merge authority).
  **gitoxide (gix)** is a promising pure-Rust successor (jj uses it) but push/merge
  are still maturing — keep it as a future swap. **fast-import/export + marks** is a
  proven incremental pattern and a good fallback for bulk projection.
- **Prior art validates the design:** jj layers a change-id on git via a sidecar
  table + `refs/jj/keep/` GC-protection + derived ids for git-native commits;
  git-cinnabar's spine is a git-sha↔hg-changeset metadata map and it can graft onto
  existing commits. Both confirm our mark map, our `refs/loot/*` reachability refs,
  and derived ids for git-native commits.
- **Conscious divergence:** we keep loot metadata in **commit trailers** (portable,
  survives a plain clone) rather than jj's sidecar table (noted as the alternative).
- **Mark-map format precedent:** fast-import's `:markid SHA-1` export/import.

No empirical run needed to resolve this ticket (documentation survey). A small git2
spike belongs to ticket 06's mechanism work, run via the Rust/git handoff.

