# Dogfood pilot: one loot-only working day
GitHub: #56

Type: prototype
Status: resolved
Blocked by: —

## Question

Drive one real working day's edits through loot alone (scratch copy of this repo is fine) and record **every** gap that breaks the ritual: snapshot/describe/new/log/checkout, push/pull against a local relay. Expected finds: no ignore mechanism (does `target/` get sealed into every snapshot?), missing diff, status opacity. Output: a gap list as a linked markdown asset, each gap tagged blocking / annoying / cosmetic — this is the evidence that unlocks or keeps parked the DX tail from the triage ticket.

## Answer

Ran the full loot-only working day on Windows (scratch copy of this repo, 80 files): init → attributes → snapshot/describe/new → docks → local relay → second identity → concurrent edits → conflict resolution. Full gap list: **[docs/dogfood/2026-07-07-pilot.md](https://github.com/Connor-Miller/loot/blob/218cab558bbb1c1050ce4677be7a2df747a9ea79/docs/dogfood/2026-07-07-pilot.md)** (committed on `cm/CA2-dock-merge`, lands on main with the CA2 merge).

**Headline: the thesis held where the seal was right (bob's clone correctly never saw `docs/private/`), but two security-grade attributes bugs make *getting* the seal right a minefield:**

- Forward-slash globs fail open to Public on Windows (#61)
- Editing .lootattributes silently demotes restricted → Public; a typo is a disclosure (#62 — bob read the "restricted" secret)

**Gates for daily driving:** no ignore mechanism (#64 — one `status` sealed 38 MB of `target/` junk), no diff anywhere (#1/#13), spurious conflict on unedited content (#65), `gc` regression (#66). **Confirmed from the DX tail:** #1, #3, #7, #13, plus pull-verdict noise → evidence posted to CA3 (#51). **Not needed at this scale:** S5, S6, #26.

**What worked:** docks round-trip flawless, `status -m` ceremony genuinely better than git's, sync fast (0.13 s snapshot, 0.23 s push), honest disclosure messaging. Newly filed: #61–#67.
