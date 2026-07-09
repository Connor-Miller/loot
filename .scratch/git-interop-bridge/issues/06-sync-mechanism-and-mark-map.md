# 06 — Sync mechanism & mark-map format
GitHub: #84

Type: grilling
Status: resolved
Blocked by: 04

## Question

With the semantics settled (01–03, 05), pin the *mechanism*:

- **Mark map** — where it lives (e.g. `.loot/git-mirror/marks`) and its fields:
  `change-id ↔ commit-sha`, `origin: loot|git` (ticket 02), and the per-side
  **last-synced pointers** (loot heads + git refs) for divergence detection
  (ticket 05). Format + how it's kept consistent / recovered if lost.
- **Plumbing** — the git integration chosen from ticket 04's survey (`git2`/libgit2
  vs fast-import/export vs a remote-helper). Incremental (O(delta)) strategy.
- **Trigger model** — a `loot git sync` verb, a hook, or a daemon? One-shot vs
  watch. (Nautical-naming note: the verb could be e.g. `loot ferry` or `loot
  mirror` — decide during spec.)
- **loot-only artifacts** — confirm grants, manifest, and attestations are **not**
  projected to git (they're loot metadata, not working-tree files; keyring never
  leaves loot). This is expected to be a quick confirmation, not a hard call.
- **Config** — the identity-map file location and the SSH allowed-signers setup
  from ticket 03.

## Notes

Blocked by 04 (plumbing choice drives the mechanism). Consumes the mark-map shape
from 02, detection from 05, identity/signing config from 03.

## Answer

**Trigger: a one-shot `loot ferry` verb.** One explicit command runs a full
bidirectional reconcile pass — ingest git-native commits → converge in loot
(ticket 05) → project the converged result to git — mirroring push/pull's
deliberate-act stance. `--watch`/daemon and git-hook auto-triggers are deferred
(later additions over the verb). (`ferry` = carry cargo between two shores; fits
loot's nautical vocabulary alongside dock/harbor/buoy/stow.)

**Plumbing: git2 (libgit2)** per ticket 04 — direct object/ref read+write both
ways; loot performs the merge, so git's merge/push aren't needed. gitoxide is a
future pure-Rust swap; fast-import+marks a bulk fallback.

**Mark map: `.loot/git-mirror/` via RepoStore (ADR 0017), local-only.** Never
synced or bundled (like `keyring`/`escrow`). Two files:

- `marks` — `sha ↔ change-id ↔ origin(loot|git)` (ticket 02), line-oriented in the
  fast-import `:mark SHA` spirit.
- `state` — the per-side **last-synced pointers** (loot heads + git refs at last
  agreement) for divergence detection (ticket 05).

**Recovery if lost:** rebuild loot-origin entries by scanning `Loot-Change-Id`
trailers in the git repo (ticket 02); git-native entries re-derive on the next
`ferry`. The map is authoritative but reconstructible — no data loss if deleted.

**Config (also under `.loot/git-mirror/`, local):** the identity map
(auto-seeded from git config, ticket 03); the SSH allowed-signers file for
verifying signatures; and the git mirror target (a named remote in `.loot/config`).

**loot-only artifacts: not projected in v1.** grants, manifest, and attestations
stay loot-only (git mirrors only the working tree; keyring never leaves loot).
Mapping attestations to git notes / signed tags is a plausible later enhancement,
explicitly out of scope here.

**Feeds:** ticket 07 (the spec) — all mechanism decisions are now pinned.

