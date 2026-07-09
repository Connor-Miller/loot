# CA4 — Buoys: navigational-role resolver over the attestation lane

**Type:** AFK · **Priority:** near · **Source:** ADR 0025 (buoy resolver), ADR
0022 (concurrent-agent model); grill-with-docs 2026-07-06; wayfinder
`.scratch/ca4-buoys/` 2026-07-09.

> Spec sharpened by the `.scratch/ca4-buoys/` wayfinder map. All design decisions
> are pinned — see ADR 0025 for the full rationale. This ticket is now
> implementation-ready and AFK.

## What to build

`loot buoy [role]` — a **derived, read-side** resolver over the shipped
attestation lane (ADR 0018 / S4). A buoy is "the newest change attested with a
navigational role by a trusted peer." No new write-verb: `attest` stays the only
writer.

### Resolver semantics (ADR 0025)

Resolve `role` to a change over the **whole change graph**:

1. **Candidate set** — changes `c` where: `c` is present locally; some attestation
   `a` has `a.change_id == c`, `a.role == role`, and `a.signature` verifies against
   `a.attester`; and `a.attester` is **trusted** = in the peer registry
   (`.loot/peers`) **or** the local identity's own pubkey (self-trust allowed).
2. Attestations naming a change not held locally are excluded (revealed by
   `--verbose`).
3. **Result = maximal elements of the candidate set under the ancestor partial
   order** (drop any candidate that is an ancestor of another):
   - one maximal → **that is the buoy**;
   - several → **ambiguous** (list them, pick none);
   - none → **no buoy**.

The resolver is a **pure function** of `(change_graph, attestation_log,
peer_registry, local_pubkey, role)` — no disk, keys, or clock. Put it in
`loot_core` (e.g. `buoy::resolve`) beside the converge classifier; it needs an
ancestor/reachability test over `change_graph` (the `reachable_from` walk already
encodes this — expose a small `is_ancestor`/reachable helper).

### Roles

Free-form `String` (no enum, no resolver-side validation). Documented conventions:
`reviewed` (peer vouched) and `base` (integration landmark). Bare `loot buoy`
defaults to `reviewed`.

### CLI

`loot buoy [role] [--verbose] [--porcelain | --json]`, format via the existing
`out_fmt()`/`OutFmt` helper. Buoy defines its **own** frozen porcelain (it is not
the per-path merge table), versioned with `FORMAT_MAJOR`:

```
B	<change-id-hex>	<role>      # resolved
A	<change-id-hex>	<role>      # per candidate when ambiguous
                                # no buoy → no lines
```

`--json`: `{"role","status":"resolved|ambiguous|none", "buoy"|"candidates", ...}`
(see ADR 0025). Human default mirrors `loot log`'s attestation display.

**Exit codes:** `0` resolved · `2` no buoy · `3` ambiguous · `1` error.
`cmd_buoy` returns its own `ExitCode` (only the `"buoy"` dispatch arm changes).

## Acceptance criteria

- [ ] `loot buoy [role]` returns the maximal role-attested change (per ADR 0025)
      from a trusted attester; bare `buoy` defaults to `reviewed`.
- [ ] Attestations from identities not in the peer registry (and not self) are
      ignored; attestations with a bad signature are ignored.
- [ ] Two concurrent (incomparable) role-attested changes → exit `3`, both listed;
      no silent pick.
- [ ] No matching attestation → exit `2`, clean "no buoy" report (not an error).
- [ ] A trusted attestation for a change absent locally is excluded from
      resolution and shown only under `--verbose`.
- [ ] `--porcelain` and `--json` emit the ADR 0025 shapes; default human output
      unchanged for scripts that don't pass a flag.
- [ ] No new write-side primitive; `attest` and the attestation lane are unmodified.

## Test plan (Rust — run via the ticket 03 handoff)

- **Unit (loot-core, no I/O):** `buoy::resolve` over a fake graph + fake
  attestation log + fake registry — single maximal, ambiguous pair, none, untrusted
  attester dropped, bad signature dropped, self-attestation counted, ancestor
  collapsed under descendant, missing-change excluded.
- **CLI integration:** `loot attest` a change then `loot buoy` returns it (exit 0);
  concurrent attestations → exit 3; unattested role → exit 2; `--porcelain`/`--json`
  golden output.
- `cargo test -p loot-core` (fast) then full `cargo test`.

## Out of scope (named follow-on)

`loot dock <name> --from-buoy [role]` — requires `create_dock` to base a dock at
an arbitrary change (no such parameter today). Clean additive next chunk; buoys
are inspection-only until it lands.

## Blocked by

- None — attestation lane ships today. Implementation-ready per ADR 0025.
