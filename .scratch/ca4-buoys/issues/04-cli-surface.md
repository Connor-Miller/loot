# 04 — CLI surface & agent-facing output for `loot buoy`
GitHub: #75

Type: grilling
Status: resolved
Blocked by: 01

## Question

Pin the command's contract:

- **Output format.** Human-readable default. Does `buoy` get CA3-style
  `--porcelain` / `--json`? Note CA3 deliberately scoped machine output to the
  *reconciliation* verbs (ADR 0023); `buoy` is a read/resolver verb, so this is a
  fresh decision, not an automatic yes.
- **"No matching attestation" behaviour.** Clean report ("no buoy") vs error, and
  the **exit code** — agents will parse this.
- **`--from-buoy` scope.** Is `loot dock <name> --from-buoy [role]` in scope for
  this chunk, or deferred as an additive convenience? (It soft-depends on CA1,
  which has shipped.)

## Notes

Blocked by ticket 01 — the output columns/fields follow whatever the resolver
semantics settle on.

## Answer

**Command:** `loot buoy [role] [--verbose] [--porcelain | --json]`. `role`
defaults to `reviewed` (ticket 02). `--verbose` reveals trusted attestations whose
change is missing locally (ticket 01). Format selected via the existing shared
`out_fmt()` / `OutFmt {Human, Porcelain, Json}` helper (`--json` > `--porcelain` >
human), reused verbatim from CA3.

**Machine output — buoy's own frozen shape (NOT the reconciliation table).**
`verdict::porcelain` is a per-path merge table (`=`/`M`/`C`/`R`); buoy returns a
change id, not paths, so it defines its own porcelain following the same CA3
principles (one line, leading status char, tab-separated, no repeated keys, frozen
+ versioned with `format::FORMAT_MAJOR`, ADR 0019/0023):

- Resolved → one line: `B<TAB><change-id-hex><TAB><role>`  (`B` = buoy)
- Ambiguous → one line per maximal candidate: `A<TAB><change-id-hex><TAB><role>`
- No buoy → no lines (the exit code carries the signal)

**`--json`:**
- Resolved → `{"role":"reviewed","status":"resolved","buoy":"<hex>","attesters":["<hex>",...]}`
- Ambiguous → `{"role":"reviewed","status":"ambiguous","candidates":[{"change":"<hex>","attesters":["<hex>",...]}, ...]}`
- No buoy → `{"role":"reviewed","status":"none"}`

**Human default:** resolved → print the change id (short + role + attester names,
mirroring `loot log`'s attestation display); ambiguous → list the candidates with
a `resolve by attesting one` hint; no buoy → `no buoy for role 'reviewed'`.

**Exit codes (agent-distinguishable, no parsing):**

- `0` — resolved (id on stdout)
- `2` — no buoy (role has no trusted, locally-present attested change)
- `3` — ambiguous (>1 maximal candidate)
- `1` — error (bad args, IO, etc.) — unchanged, consistent with the rest of loot

Implementation note: `cmd_buoy` returns its own `ExitCode` rather than the generic
`Result<(), String>` → 0/1 path in `main`; the `"buoy"` dispatch arm returns it
directly (small, verb-local; the other 30 verbs are untouched).

**`--from-buoy` — DEFERRED (out of this chunk).** `loot dock <name> --from-buoy
[role]` is a clean follow-on: `create_dock` has no base-at-change parameter today
(`crates/loot-cli/src/main.rs` `cmd_dock` → `ws.create_dock(name, at)`), so it
needs an engine capability to base a new dock at an arbitrary change. Recorded as
the natural next chunk after CA4. Consequence: buoys are **inspection-only** until
it lands (an orchestrator/human reads `loot buoy` and acts manually).

**ADR note:** adding machine output to `buoy` (a non-reconciliation verb) is a
deliberate deviation from ADR 0023's scope note ("avoid adding machine output to
the ~25 non-reconciliation verbs"). The final spec (ticket 05) must call this out
and amend/supersede that note — buoy is agent-facing by design, so porcelain/json
belong here.

