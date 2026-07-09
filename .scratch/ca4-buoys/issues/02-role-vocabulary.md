# 02 — Role vocabulary & default role
GitHub: #73

Type: grilling
Status: resolved
Blocked by: —

## Question

`role` is a free-form `String` on the attestation today. For buoys, decide:

- The **canonical navigational-role convention** — `reviewed`, `base`, any
  others? (ADR 0022 names `reviewed` and `base` as examples.)
- Whether `loot buoy` **constrains/validates** the role against a known set or
  stays fully free-form (advisory, like attestations are today).
- What **bare `loot buoy`** (no role arg) defaults to (the CA4 ticket suggests
  `reviewed`).

## Notes

Independent of ticket 01 — can be resolved in parallel. Keep it a convention, not
an engine-enforced enum, unless a reason to constrain surfaces.

## Answer

**Blessed roles (documented conventions only):**

- `reviewed` — a trusted peer vouched for this change (sign-off).
- `base` — a landmark to build / rebase a dock from (integration base).

These are the two roles ADR 0022 names; documenting exactly two keeps the
vocabulary honest (no speculative `released`/`tested` roles until a real need
appears).

**Free-form, not constrained.** `loot buoy` resolves *whatever* role string it is
given; the blessed roles are documentation, not an enforced enum. Rationale:
symmetric with `attest`, whose `role` is already a free-form `String` with no
validation (`crates/loot-core/src/attestation.rs`); this keeps `attest` the sole,
uncoupled write-verb and avoids an enum that would need format-gated migration
every time a role is added. The resolver treats `role` as an opaque match key.

**Bare `loot buoy` defaults to `reviewed`** — matching `attest`'s existing default
(`crates/loot-cli/src/main.rs:803`), so `loot attest <change>` and `loot buoy`
center on the same role and share muscle memory.

**Known footgun (accepted, out of scope):** because both sides are free-form, a
mistyped role at attest time (`reviewd`) silently produces a change the resolver
never finds. The right fix is a warning at *attest* time on a non-conventional
role — but `attest` shipped under ADR 0018/S4 and is out of this chunk's scope.
Recorded as a candidate future enhancement, not a CA4 ticket.

