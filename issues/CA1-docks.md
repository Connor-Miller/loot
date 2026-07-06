# CA1 — Docks: isolated working trees over one object store

**Type:** AFK · **Priority:** near (foundational) · **Source:** docs/adr/0022-concurrent-agent-model-docks.md; grill-with-docs 2026-07-06

## What to build

The isolation unit for concurrent agents — loot's answer to a git worktree.
Grow the Workspace from one bound `.loot/` tree to **N docks**, each with its own
working-change tip and tree-hash, materialized over the *shared* `.loot/` object
store and change graph. An agent (or human) *docks* into the repo to get its own
tree and tip with no second clone and no re-fetch of ciphertext. A dock is a
local fork of the DAG — the same shape `stow` already produces for remote pushes
— so nothing about convergence changes here; this slice only adds the per-dock
working state and the verbs to manage it.

`loot dock <name>` creates a dock (or switches the ambient dock to it); `loot
docks` lists live docks with their tip and visibility. The dock name is the
handle: a moving, workspace-scoped pointer, deliberately not a repo-level branch
(a permanent non-goal) and not a tag.

The per-dock process files (`working`, `tree-hash`) route through `RepoStore`
(ADR 0017) so the `.loot/` layout keeps one home.

## Acceptance criteria

- [ ] `loot dock <name>` creates a dock with its own working-change tip and tree, or switches the ambient dock to an existing one.
- [ ] `loot docks` lists live docks with tip and visibility.
- [ ] Two docks editing disjoint paths each `status` to independent tips while sharing one object store (no duplicated ciphertext, no re-fetch).
- [ ] Per-dock `working`/`tree-hash` process files are addressed via `RepoStore`; the single-dock case is unchanged on disk (existing repos load unmodified).
- [ ] Switching docks re-materializes the target dock's tree, visibility-aware (ADR 0006).

## Blocked by

- None — can start immediately.
