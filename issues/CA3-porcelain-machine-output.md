# CA3 — Porcelain + JSON output for reconciliation verbs

**Type:** AFK · **Priority:** near · **Source:** docs/adr/0023-agent-facing-machine-output.md; grill-with-docs 2026-07-06

## What to build

Make an agent a first-class driver of reconciliation. The converge classifier
already returns a typed per-path verdict (`converge.rs::classify` ->
`BTreeMap<PathBuf, MergeOutcome>`); today the CLI discards it at the `println!`
boundary. Lift it to a serializable value and emit it in machine formats from the
reconciliation verbs that exist today — `apply`, `conflicts`, `status` — with
`dock merge` (CA2) emitting through the same serializer once it lands.

Default machine format is **porcelain**: one path per line, a leading status char
(`=` converged, `M` merged, `C` conflict, `R` relayed), tab-separated columns
(`status  path  base_change  incoming_change`), no repeated keys — token-lean for
agents and human-glanceable. `--json` is the opt-in fallback for paths containing
a tab or newline, where JSON escaping is clean. The default (no flag) stays the
current human text.

The verdict record is versioned alongside the format gate (ADR 0019 / S1) so the
contract can evolve; note that once agents parse porcelain, the column order and
status chars are a frozen contract (ADR 0023).

## Acceptance criteria

- [ ] `--porcelain` on `apply`, `conflicts`, `status` emits one line per path with status char + tab-separated columns; each `MergeOutcome` maps to a documented status char.
- [ ] `--json` emits the same verdict as structured records, correctly escaping a path containing a tab or newline.
- [ ] Default output (no flag) is unchanged human text.
- [ ] Porcelain and JSON are two encoders over one lifted verdict value (no divergent logic).
- [ ] The verdict record carries a version tag under the format gate (ADR 0019).

## Blocked by

- None — can start immediately (targets verbs that exist today; `dock merge` output folds in with CA2).
