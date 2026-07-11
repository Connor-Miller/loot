# Concurrent-agent model: docks, harbor, optimistic convergence

## Status

accepted — implemented. Docks (CA1), `loot dock merge` + harbor (CA2,
`588762d`), and porcelain verdicts (CA3) are on `main`; the physical-worktree
dock model was reconciled in PR #69. Cross-identity convergence is proven
end-to-end by the map #119 evidence (`docs/evidence/concurrent-agents.md`),
whose run also fixed peer-side fork-collapse (#128) and `dock merge` machine
output (#126).

## Context

Multiple agents (AI or human) increasingly need to work the *same* repository at
once. Git solves this with worktrees — N working trees over one object store —
layered on branches. loot has neither: the Workspace is a *process-bound ambient
repo* bound to one `.loot/`, one identity, one working tree, one working-change
tip (ADR 0006), and repository-level branches are a **permanent non-goal** (they
are the anti-thesis — permissions attach to content and changes, not to a repo
scope). So two agents in one directory today fight over a single working change.

The gap is narrow and specific. loot is *already* a multi-writer-converges
system: `stow` is append-only, concurrent pushes legitimately fork the DAG into
multiple tips (ADR 0011), and forks are collapsed when a keyholder pulls and
`apply`s through the converge classifier (ADR 0001). The convergence model is
solved. What is missing is an *isolation unit* between the shared object store
and the single working tree — the thing worktrees provide — plus an
agent-facing surface over the fork/merge machinery that already exists.

## Decision

### Docks are the isolation unit

A **dock** is an isolated working tree plus its own working-change tip,
materialized over the *shared* `.loot/` object store and change graph. An agent
*docks* into the repo to get its own tree and tip with no second clone and no
re-fetch of ciphertext. A dock is a **local fork** of the DAG — the same shape
`stow` already produces for remote pushes — so reconciliation reuses the
existing converge path unchanged. The loose-object store is already lock-free
for disjoint objects (ADR 0012); only the small graph metadata serializes.

### The dock name is the handle — not a branch, not a tag

A dock name is a *moving, workspace-scoped* pointer: what a branch gives you
(a name that follows your tip) without being a *gated repo-level* branch (the
non-goal). This collapses git's branch + worktree + checkout triple into one
named noun. There is deliberately **no tag primitive**: a git tag is an
immutable pointer at frozen history, which is not what a live workspace needs,
and a mutable named ref is a branch by another name.

### Reconciliation is direct and local; the harbor is a convention

`loot dock merge <name>` applies one dock's tip onto another's working change
**in-process**, reusing `apply`/converge with no relay hop, because docks share
one object store. A conventional **harbor** dock — a plain dock with a
well-known name and *no permissions attached* — is the integrator agents
converge into and re-base from. It is a coordination convention, not a gated
branch. The relay remains the path for *remote* agents only.

### Landmarks are derived attestations (buoys), not mutable refs

"Mark a historical change to build from" reuses the existing attestation lane
(ADR 0018 / S4): a **buoy** is the derived, read-side concept "the newest change
attested with role X (`reviewed`, `base`) by a trusted peer." Attestations are
append-only and signed, so each buoy pins one change immutably and "current" is
*computed*, never stored as a mutable ref. This gives moving-pointer behaviour
with none of the concurrent-writer race a shared mutable ref would suffer.
`attest` stays the only write-verb.

### Concurrency is optimistic; work-assignment is the orchestrator's job

Agents work in docks, fork freely, and converge at the harbor. Collisions are
*safe* by construction — the converge classifier never drops a side (worst case
is a surfaced `Conflict`, ADR 0001), so no lock is needed for correctness. loot's
responsibility ends at safe convergence; deciding *who works on what* belongs to
the orchestrator that fans out the agents. **File locking stays dropped** (a
binary-first concern; loot is code-first).

### Physical model (resolved in CA1)

Share the store; separate only the working trees. The costly data —
`.loot/objects` (ciphertext) and the change graph — lives once in the primary
repo and is never duplicated; a dock isolates only the *materialized working
tree* (the current visible snapshot, not history), which is small. So N docks
cost ~N working-sets, not ~N clones.

- **Named docks are worktree-style separate directories.** A dock directory
  holds a small `.loot` *pointer file* naming the shared store and the dock
  (mirroring a git worktree's `.git` file). Its files materialize in that dir, so
  concurrent agents edit physically separate trees with no on-disk clobber.
- **The primary directory is the default dock**, using the existing top-level
  `.loot/working` + `.loot/tree-hash`, so existing single-dir repos load
  byte-unchanged.
- **Per-dock process state** (`working` tip, `tree-hash`) for a named dock lives
  under `.loot/docks/<name>/`, routed through `RepoStore` (ADR 0017).
- **One noun, two ergonomics.** `loot dock <name>` switches the ambient dock in
  place and re-materializes (checkout-style: the single-dir human flow); with
  `--at <dir>` it binds a separate working directory (the concurrent-agent flow).
- **Deferred:** reflink/copy-on-write materialization (APFS/btrfs) to make even
  large working sets near-free to fork; CA1 materializes by plain `surface`.

## Considered alternatives

**Separate clone per agent.** Works today with zero new code (each agent = own
dir + identity, converge on push/pull). Rejected as the *local* model: it
duplicates the whole object store per agent and pays a relay round-trip to see a
peer's work — miserable as the "smoothest local devX" this targets. It remains
the right model for genuinely *remote* agents.

**Multiple named working changes over one shared tree.** One tree on disk, N
logical tips. Rejected: agents editing files need *physically separate* trees or
they clobber each other's uncommitted work on disk. The tree must fork, not just
the change.

**A tag or bookmark primitive for landmarks; a mutable "latest-reviewed" ref.**
Rejected: a single mutable ref that N agents race to move is precisely the
contention this design avoids. The append-only attestation lane already gives a
forge-evident, race-free equivalent (buoys).

**A claim/lease (soft lock) to prevent redundant work.** Deferred, not rejected.
Optimistic convergence is safe today; a soft *advisory* "working-on `<paths>`"
signal (advisory, append-only, not a lock) is a later-phase mitigation to add
only if real thrashing appears. Recorded under CONTEXT.md Open/undecided.

## Consequences

### Positive

- Worktree-class local isolation without branches, reusing the fork/converge
  machinery loot already has — docks are local forks, not a new model.
- One named noun (the dock) replaces git's branch+worktree+checkout ceremony.
- Landmarks (buoys) and integration (harbor) are conventions over existing
  primitives (attestations, docks), not new engine concepts.

### Negative / accepted costs

- The Workspace must grow from one bound `.loot/` tree to N docked trees over one
  store; the working-change/tree-hash process files (ADR 0017 `RepoStore`) become
  per-dock. This is the main implementation surface.
- Optimistic concurrency can waste agent effort on colliding work until the
  deferred advisory-claim signal exists; accepted for now.

### Explicitly deferred

- **Soft advisory claims** (intent-to-edit signal) — later phase.
- **Published bookmarks + relay CAS** — the *remote* form of a dock handle,
  already a "later ergonomics, ungated only" item in the backlog.
