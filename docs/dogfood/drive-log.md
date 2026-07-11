# Dogfood drive log — 5 loot-first working days

The running log for **section A** of the milestone evidence
([../evidence/loot-hosts-loot.md](../evidence/loot-hosts-loot.md)): five
consecutive working days where **every change to this repo is finalized in loot
and pushed to the relay the same day**, with git as backup only. Divergence and
friction are logged per day — that log *is* the dogfood data, not a failure
report.

## The daily ritual

Work normally (git commits as usual — git keeps the issues and a backup). Once
per working day, run the helper from the repo root (PowerShell):

```powershell
pwsh tools/loot-day.ps1 -Day <N> -Message "<what changed today>"
```

It snapshots the working tree into loot (`loot status -m`), finalizes it
(`loot new`), pushes to the relay (`loot push`), appends a dated section below
with the mechanical facts, and prints the row to paste into the evidence
table's section A. Then fill that day's **friction:** line (one honest sentence —
what diverged or hurt, or `none`) and paste the row.

A day *counts* iff the day's work is finalized in loot and pushed the same day.
One loot change per day is fine (git commits may batch); loot is the primary
record.

## Smoothing — friction already pre-empted

The #56 pilot's blockers are all fixed, so the drive should be low-friction:

- **No giant seals** — `.lootignore` excludes `target/`, `test-repos/`,
  `.claude/`, `.scratch/` (#64).
- **Cheap re-pushes** — snapshot reuses unchanged `(oid, visibility)`, so push
  is O(delta), not O(repo) (#98).
- **Seals hold on Windows** — forward-slash globs normalize (#61); implicit
  demotion is refused (#62).
- **No spurious conflicts** on untouched content (#65); `loot gc` is back if
  loose objects pile up (#66).
- **Keep the binary current** — rebuild `target\release\loot.exe` from `main`
  after any `FORMAT_MAJOR` change (the relay is on **v5**; a v5 client cannot
  push to a v4 relay, and vice versa).

If a push stalls, re-run it (it is resumable). If a conflict appears, `loot
conflicts` then `loot resolve <path> <file>`.

## Day entries

<!-- loot-day.ps1 appends one section per day below this line. -->

## Day 1 - 2026-07-10

- loot change: `c670cc2b` "embargo CLI (#88) + attack demo (#89) + section-B evidence + maroon propagation fix + drive setup"
- pushed: 14 object(s) to the relay
- git backup HEAD: `3afdc7a` "Section-B agent evidence: sealed-path + grant/maroon demos; fix maroon propagation (#103)"
- loot head at start of day: `7784bcac` "hard embargo engine/wire lands (#14, format v5)" — the last finalized loot change; loot was 3 PRs behind git (#88/#89/#103 had landed via git only)
- friction: loot drifted 3 PRs behind git during the milestone tooling build-out (I was driving with git while building loot's own evidence). Day 1 caught it up in a single O(delta) push — 14 objects for a large multi-PR diff (#98 working as intended), no conflicts, `docs/pitch/` stayed sealed. The only snag was in the new `loot-day.ps1` helper, not loot: PowerShell 5.1 parses a no-BOM script as ANSI, so em-dashes in the source broke it — fixed by keeping the helper ASCII-only.
## Day 2 - 2026-07-10

- loot change: `a8cafda5` "ferry the git bridge (#114-118) + concurrent-agents epic close-out (#126-131) into loot"
- ferry: ingested 4 git commit(s), projected 0 loot change(s)
- pushed: 146 object(s) to the relay
- git backup HEAD: `2dafa29` "Reconcile CONTEXT.md + ADR statuses to shipped reality (#124) (#131)"
- loot head at start of day: 8c37c7c7  catch up: sign-resolutions fix lands (PR #118)  [1/105 sealed]  [logged by dbf3dbe6…]
- friction: mechanically clean — the day's work (the CA epic close-out) had landed on git main via GitHub PRs, so the git-clean tree skipped the snapshot and the ferry carried it across: 4 commits ingested, 0 conflicts, 0 projected back (purely git→loot this day), `docs/pitch/` stayed sealed. Resumable push moved 146 objects in 5 batches. Same underlying shape as day 1 — loot still *follows* git rather than leads, because the milestone's own work is being driven through git — but no divergence pain and nothing to resolve. One cosmetic helper nit (not loot): `loot-day.ps1` double-printed the `ferry:` prefix in the log line because loot's own output already carries it; trimmed here, worth a one-char fix in the helper before day 3.