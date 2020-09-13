# Burn and the mis-seal gate: a remedy for a secret sealed public

## Status

accepted (trust-hardening map #339, ticket #63 — the map's keystone grilling;
resolves pilot finding 3, the "no remedy for a mis-sealed secret" gap). Builds
on ADR 0003 (sealed content), ADR 0009/0010 (maroon and purge events), ADR
0018 (signed changes), ADR 0028 (the git bridge), ADR 0030 (the demotion
guard's refusal pattern), ADR 0031 (operation barriers), ADR 0034 (the
append-only shared store).

## Context

Once a change is finalized, plaintext sealed under an ANYONE key is immutable
history: `migrate`/`maroon` re-seal the *future*, but every peer, relay, and
mirror that holds the old object can read it forever. git has BFG/filter-repo;
loot had nothing — and the pilot showed the accident is easy: a typo'd
`.lootattributes` rule (`.evn restricted=alice`) lets `.env` fall through to
the public default and seal under ANYONE. The existing demotion guard (#62,
ADR 0030) cannot catch this: it compares against the visibility the tree
*already records*, and a brand-new path has no prior record.

Any cure collides with three deliberate invariants: the shared store is
append-only (ADR 0034), changes are signed and their ids stable (ADR 0018,
0029), and "no change is ever deleted" (ADR 0031). A filter-branch-style
rewrite would re-open all three — and would still not retract bytes from
machines we don't control.

## Decision

The remedy is **prevention plus a tiered cure**, split by the disclosure
barrier (`push`, ADR 0031), with **one destruction mechanism** serving both
tiers.

### 1. The mis-seal gate (prevention)

A built-in **secret-shaped name set** (`.env*`, `*.pem`, `*.key`, `id_*`,
`*credentials*`, … — the exact set lives with the implementation). At every
signing verb, a path that matches the set **and** resolves Public *via
fallthrough* — the default or a catch-all, not an explicit rule naming it —
gets a **typed refusal**, overridable per-path (the `--allow-demote` pattern
from ADR 0030). An explicit `.lootattributes` rule that names the path public
is consent; falling through to public is not. This catches the typo'd-rule
class directly, with zero plaintext inspection — loot stays content-agnostic
(no entropy scans, no token patterns; a gitleaks-style scanner can compose as
an external pre-finalize hook).

Alongside the refusal, finalize prints a **first-seal summary**: each path
being sealed for the first time, with its resolved visibility — so surprises
outside the name set are at least visible at the moment of signing.

*Implementation (#343).* The refusal is `RepoError::MisSeal`, a sibling of
`Demotion`; the override is `--allow-reveal <path>` (repeatable), riding
`describe`/`new` exactly as `--allow-demote` does and refused on read-only
`status`. The gate is **first-seal scoped** — it fires only on a path absent
from the finalized anchor, mirroring the demotion guard's history-relativity so
an override or explicit rule is a one-time ceremony and carry-along captures
(ferry/adopt/merge) never re-trip it. The secret-shaped name set is the
`SECRET_NAMES` constant in `crates/loot-cli/src/workspace.rs`, matched against a
path's basename anywhere in the tree, case-insensitively: the ADR's `.env*` /
`*.pem` / `*.key` / `*credentials*` families plus common cert/credential files,
with precise SSH key names (`id_rsa`, `id_ed25519`, …) chosen over a broad
`id_*` to avoid false-positives on ordinary source files. "Fallthrough" is the
default *or* a catch-all glob — a pattern made only of `*`/`/` (`* public`);
any literal segment makes a rule an explicit naming, i.e. consent.

*Amendment (#353).* The gate now lives inside the shared finalize seam
(`Workspace::finalize_capturing_allowing`) rather than only in the verbs, so
every capture-and-sign — `new`, the amend re-finalize after `edit` (ADR 0032),
and `loot-first land` — runs it; the folding verbs' wip-signing steps
(`fold_line_in`, ferry's reconcile) run it flagless, and `describe` keeps a
pre-capture preflight.

### 2. `loot burn <path>` (the cure)

Burn **destroys the object's bytes and records a signed tombstone** — the
**burn log** — while the change graph is never touched: every node, change id,
signature, and parent edge stays intact. Absence becomes *legible*:

- `verify` treats a burn-logged oid's absence as deliberate, not corruption;
- `surface`/checkout of an old change labels the path **burned** rather than
  silently missing;
- **sync permanently refuses to re-accept a burned oid** — apply, pull
  negotiation, and stow all consult the burn log, closing the resurrection
  hole where a later pull would quietly restore the bytes from a relay that
  still holds them.

Burn is a **non-undoable operation barrier** (ADR 0031, same class as `push`/
`grant`/`maroon`): destruction is not a view reset. The forward fix — re-seal
the path restricted, or delete it at tip — is the existing `migrate`/edit
path; burn's output points there, and at rotating the leaked credential
itself.

### 3. Tiers of honesty (what burn reports)

The same mechanism, two guarantees, and burn says which one you got:

- **Never pushed** (the op log's disclosure barriers know): the only copy was
  local — destruction is *complete*. This is the true remedy, and the reason
  the gate + early burn matter.
- **Already pushed**: local destruction plus the tombstone travels as a
  **purge event** (the hard-maroon precedent, ADR 0009/0010) asking
  cooperating relays and peers to destroy their copy — honestly best-effort,
  exactly like hard maroon: offline or modified peers cannot be forced. Burn
  prints the rotate-the-secret guidance; bytes on machines you don't control
  are gone, same as git.

### 4. The git mirror: detect and guide, never rewrite

A mis-sealed *public* path was also projected into the git mirror (ADR 0028)
and possibly pushed to a git remote. Burn consults the mark map: if the
object's change was ever projected, it says so and prints the git-side remedy
(git-native history rewrite — filter-repo/BFG — on mirror and remote, or
accept-and-rotate). Loot never rewrites git history itself: the mirror is
harbor-owned, a rewrite races concurrent agents' lands, and a botched
automated force-push is worse than the leak.

**Ferry-resurrection caveat**: bytes still present in the git *tip* would
re-ingest under a fresh oid the burn log cannot match (re-sealing mints a new
ciphertext address; loot is content-agnostic and cannot recognize plaintext).
The forward re-seal/removal at tip is what closes this — ferry ingests new
commits, not rewalked history — and burn's guidance makes that ordering
explicit: fix the tip, then burn.

## Alternatives considered

- **Supersede-then-destroy** (mint a new version via ADR 0032's amend
  machinery, then destroy the old version's object): descendants' trees still
  reference the old oid, so the tombstone is needed anyway — strictly more
  machinery for the same end state.
- **True history rewrite** (filter-branch equivalent): breaks stable change
  ids, invalidates descendant signatures (unfixable for other authors'
  changes), violates the append-only store, and still cannot reach other
  machines. The invariants exist for the concurrency model; not re-opened.
- **Content scanning as the gate**: catches more, but makes loot inspect
  plaintext semantics and false-positive forever; left to external hooks.
- **Refuse-unmatched-paths as the gate**: structurally explicit, but a
  catch-all rule (which every real repo wants) waves the typo'd-rule case
  straight through — the case that actually happened.

## Consequences

- The burn log is a new store artifact (shared, append-only — a burned oid is
  burned for every identity) that `verify`, `surface`, sync negotiation,
  `apply`, and `stow` must consult; `gc` treats burn-logged objects as
  already-collected.
- The wire format grows the tombstone/purge-event carriage for the
  post-disclosure tier (composes with the existing purge-event lane).
- The gate adds one refusal class to the signing verbs and a first-seal
  summary to finalize output.
- The evidence map ticket (#340) inherits a burn scenario: mis-seal → gate
  refusal → override → burn → verify passes → pull does not resurrect.
