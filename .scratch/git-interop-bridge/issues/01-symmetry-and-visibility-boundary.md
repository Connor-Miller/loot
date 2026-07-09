# 01 — Symmetry & the visibility boundary

Type: grilling
Status: resolved
Blocked by: —

## Question

The pivotal decision. git can't carry loot's per-content visibility, so define:

- **What crosses loot → git.** Only public/ANYONE-granted content? How do
  restricted/embargoed paths appear on the git side — omitted entirely, or a
  placeholder (and if a placeholder, what, without leaking)?
- **How git → loot ingest works.** New/changed files land public-by-default and
  get reclassified via `.lootattributes`? Or a committed sidecar preserves
  visibility across the round-trip? Or is git→loot recovery-only (no
  co-development on git)?
- **The resulting symmetry statement** — one sentence an implementer can build to
  (e.g. "git is a lossy plaintext projection of visible content; loot is the
  permission source of truth").

This gates the tree contents in 02 and the reconciliation model in 05.

## Notes

Candidate framings surfaced while charting: (a) lossy projection + public-default
ingest; (b) full symmetry via a committed sidecar (`.lootattributes` + a
change-id↔sha map); (c) git→loot is recovery-only. Grill toward one.

## Answer

**Symmetry statement (build to this):** *git is a plaintext mirror of the syncing
identity's readable tree; loot is the permission source of truth.*

**loot → git projection = `surface` for the syncing identity.** The git tree is
exactly what that identity can decrypt — reuse `DagRepo::surface_with_report`
(engine.rs), which already materializes the readable tree and skips sealed paths.
Not the ANYONE-public subset: the **full readable set** of the syncing identity.

**Omitted paths are omitted entirely** — no filename, no placeholder. `surface`
already skips sealed/unrevealed paths with no on-disk trace, so the git tree is a
clean readable subset with no path-name or structure leak. Embargoed paths are
absent until their reveal, then appear naturally on the next sync.

**git → loot ingest = public-default via the normal snapshot path.** Incoming git
files are written into the loot working tree and then run through loot's existing
`.lootattributes`-driven snapshot (ADR 0006), so classification happens **at
ingest**: a file matching a restricted/embargoed glob is sealed immediately and
never lands as public; only files matched by nothing default to Public — identical
to normal loot authoring. loot stays the permission source of truth.

**Hard constraint (accepted):** because the git side carries the identity's
private plaintext, **the git remote must be trusted as much as that identity** —
this projection must NOT be pushed to a public host. Mirroring to a public host
would require the ANYONE-public projection, which is **out of scope** for this map
(see the map's Out of scope). This matters for the dual-run milestone (#54), which
currently backs up to GitHub: the loot↔git mirror target must be a private/trusted
git remote, or the public content only.

**Feeds:** 02 (a commit's tree contents = the surfaced tree), 05 (reconciliation
must never surface sealed content into git nor clobber a sealed path on ingest).

