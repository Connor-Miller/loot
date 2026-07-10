# GB1 — git interop bridge: bidirectional loot ↔ git mirror (`loot ferry`)

**Type:** (mostly) AFK · **Priority:** near · **Source:** ADR 0028; wayfinder
`.scratch/git-interop-bridge/` 2026-07-09.

> Spec sharpened by the `.scratch/git-interop-bridge/` wayfinder map (tickets
> 01–06). All design + mechanism decisions are pinned — see ADR 0028 for full
> rationale. Implementation-ready.

## What to build

A `loot ferry` verb that keeps a loot repo and a private git repo continuously in
step. git is a plaintext mirror of the **syncing identity's readable tree**; loot
stays canonical and permission-authoritative.

### Projection (loot → git)

- Tree = `DagRepo::surface_with_report` for the syncing identity (full readable set;
  sealed / unrevealed paths omitted entirely — reuse surface's skip).
- One git commit per loot Change. Trailers: `Loot-Change-Id`, `Loot-Author`
  (pubkey hex), `Loot-Signature` (when signed). Deterministic dates
  (`BASE_EPOCH + generation`, tie-break change-id).
- Refs: every head under `refs/loot/heads/<change-id>` (+ `refs/loot/docks/<name>`
  where known); `refs/heads/main` → a designated dock tip (`home`/`harbor`).
- SSH-sign commits (`gpg.format=ssh`) with loot's ed25519 key.
- Skip `origin: git` changes already present under their original sha.

### Ingest (git → loot)

- Write incoming files to the working tree, then run the normal `.lootattributes`
  snapshot (sealing at ingest; unmatched → Public).
- Commit with `Loot-Change-Id` → map straight back (idempotent). git-native commit
  → syncing identity if it resolves via the identity map, else unauthored/legacy
  change with a `Git-Author:` trailer.

### Reconcile

- Ingest git-native commits as loot changes, converge with loot's classifier
  (ADR 0001), re-project. Divergence via last-synced pointers in the mark map.
- Conflicts surface in loot (`loot conflicts`/`loot resolve` + porcelain); a
  conflicted path is held at its last clean state in git until resolved.
- Invariant: never surface sealed content into git; never clobber a sealed path.

### Mechanism

- git2 (libgit2). Mark map in `.loot/git-mirror/` via RepoStore, local-only:
  `marks` (sha↔change-id↔origin) + `state` (last-synced pointers); rebuildable from
  trailers. Identity map (auto-seeded from git config), allowed-signers, and the
  mirror-remote config also local.

## Acceptance criteria

- [ ] `loot ferry` performs a full bidirectional reconcile pass and is idempotent
      (a second run with no changes is a no-op).
- [ ] Sealed/unrevealed paths never appear in the git repo (no filename, no bytes).
- [ ] A loot change round-trips loot→git→loot to the **same change-id** (trailer
      short-circuit).
- [ ] A git-native commit ingests as the syncing identity (if it matches) else an
      unauthored/legacy change preserving `Git-Author:`.
- [ ] Every loot head is reachable in git (`refs/loot/heads/*`); `main` tracks the
      designated dock.
- [ ] Mirrored commits are SSH-signed and verify with loot's key.
- [ ] Concurrent edits on both sides converge via loot's classifier; a conflict
      surfaces in `loot conflicts` and the conflicted path is not projected until
      resolved.
- [ ] Deleting `.loot/git-mirror/marks` and re-running rebuilds loot-origin entries
      from trailers with no data loss.

## Test plan (Rust + git — run via the Rust/git handoff)

- **Unit (loot-core / bridge module):** projection = surface tree; trailer
  encode/decode; deterministic date derivation; mark-map read/write + rebuild;
  reverse mapping (trailer short-circuit vs git-native); identity-map resolution.
- **Integration:** init a loot repo with a sealed path → `loot ferry` → assert git
  tree omits the sealed path, commit has trailers + valid SSH signature, refs
  present. Commit on the git side → `loot ferry` → assert ingest + converge; force a
  concurrent edit both sides → assert conflict surfaces in loot, git held clean.
- `cargo test -p loot-core` then full `cargo test`; manual `loot ferry` smoke
  against a scratch git remote.

## Out of scope (named follow-ons)

- Public-host (ANYONE-only) projection; `--watch`/daemon + git-hook triggers;
  remote-helper (`git-remote-loot`); attestations → git notes/tags; gitoxide swap.

## Blocked by

- None — implementation-ready per ADR 0028.
