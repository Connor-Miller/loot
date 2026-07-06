# Agent-facing machine output: porcelain-first, scoped to reconciliation verbs

## Status

accepted

## Context

An AI agent driving loot must learn a reconciliation outcome as *data*, not by
scraping prose. Today the converge classifier (`converge.rs::classify`) returns a
typed `BTreeMap<PathBuf, MergeOutcome>` — Converged / Merged / Conflict /
RelayedUnmerged per path — but the CLI throws that structure away at the
`println!` boundary: `cmd_apply` walks the map and prints human lines, `loot
conflicts` lists paths, `loot resolve` takes a hand-authored file. That is a
person-at-a-terminal loop. An agent hitting a `Conflict` has to parse stdout and
cannot cleanly decide "re-drive against the new base" vs "escalate."

There is no central output layer to hang this on: `main.rs` is ~1100 lines with
~100 ad-hoc print sites, each `cmd_*` printing its own way.

## Decision

### Surface the converge verdict as structured output on the reconciliation verbs

Add a machine-output mode to the verbs where agents actually need it — `apply`,
`dock merge`, `conflicts`, `status` — emitting the per-path verdict the
classifier already computes: `{outcome, path, base_change, incoming_change}`.
This surfaces an existing typed value; it is not new logic.

### Porcelain-first, with `--json` as a fallback

The default machine format is **line-oriented porcelain**: one path per line, a
leading status char, tab-separated columns, no repeated keys:

```
C	src/auth.rs	ab12	cd34
M	src/util.rs	ab12	ef56
=	README.md	ab12	ab12
```

(`=` converged, `M` merged, `C` conflict, `R` relayed.) The verdict stream is
*homogeneous tabular* data — every row the same shape — which is the worst case
for JSON, which re-emits every field key on every row (~3–4x the tokens here).
Porcelain has zero repeated keys, parses with `split('\t')`, and is
human-glanceable, so one format serves both readers. This follows git's
`--porcelain` precedent: a stable machine format need not be JSON.

`--json` is offered as an opt-in fallback for the one case porcelain handles
poorly — paths containing a tab or newline, where JSON's escaping is clean. Both
are thin encoders over the same `MergeOutcome` map, so the second format is cheap
once the map is lifted to a serializable value.

### Scoped, not global

The mode is added only to the reconciliation verbs, **not** to all ~25 commands.
A global structured-output layer would mean a result type per command, a renderer
refactor across every print site, and — the real cost — a *stable serialization
contract for every command forever*. Nothing today needs machine output from
`log` or `manifest`; agents need it from reconciliation. The global renderer is a
later refactor to do only if that need becomes real.

## Considered alternatives

**JSON as the only machine format.** One format, bulletproof escaping. Rejected
as the default: on homogeneous per-path verdicts it repeats field keys every row,
inflating token cost for the exact consumer (agents) we are optimizing for. Kept
as the opt-in fallback.

**A global `--format` across the whole CLI now.** Consistent, but a multi-day
cross-cutting refactor plus a permanent contract-stability tax over 25 commands,
for value concentrated in ~4. Rejected as premature; the targeted change is ~1
day and self-contained.

**A custom binary/compact encoding.** More compact still, but agents parse it
less reliably than tab-delimited text and it loses human-glanceability. Porcelain
captures most of the token win while staying trivially parseable by both.

## Consequences

- Agents become first-class drivers of reconciliation: read the verdict, decide
  to re-drive or escalate, or write a resolution programmatically.
- The porcelain column order and status chars become a **frozen contract** once
  agents depend on them — the reason this is an ADR. Changes are breaking and
  must be versioned.
- Scope stays small (~4 verbs, one flag, two encoders over an existing map); the
  global renderer is explicitly deferred.
- The verdict record should be versioned alongside the format-versioning gate
  (ADR 0019 / S1) so the contract can evolve safely.
