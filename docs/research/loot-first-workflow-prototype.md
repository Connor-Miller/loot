# Prototype — a day driven loot-first, git downstream

> Wayfinder prototype for [#153](https://github.com/Connor-Miller/loot/issues/153)
> on map [#148](https://github.com/Connor-Miller/loot/issues/148). A rough,
> throwaway artifact: a scripted transcript of the **loot-first** daily loop once
> WIP-projection (#149), PR-reconciliation (#150), ferry-authority (#151), and the
> dock-to-PR lifecycle (#152) are all in. The point is to catch a **seam** while
> it is still cheap to move — before the workflow doc (#154) and the shipped
> tooling (#155). Nothing here is built; output is hand-composed to be *faithful
> to loot's real formats* (`short()` = 8 hex chars; `status`/`docks`/`ferry`
> shapes from `loot-cli/src/main.rs`), with the four new lines (`--with-wip`,
> `land`) marked as **proposed**.

## Conventions this prototype uses

- **version id** — content+author hash, 8 hex chars, e.g. `3f9a1c02` (rewrites on
  every snapshot). **change id** — the durable handle, reverse-hex letters, e.g.
  `qsouzmpr` (minted once, carried across snapshots). Both per map #132.
- **`loot` core stays git-agnostic.** loot never calls `gh`. A thin PowerShell
  orchestrator (the `tools/loot-day.ps1` successor, shown as `loot-day …`) owns
  every GitHub call. The transcript shows the underlying loot verbs the
  orchestrator runs, so the seams are visible.
- The private mirror `.loot/git-mirror/mirror.git` stays **local-only**; every
  `→ github` line is a **single-ref push with an inline URL** (no stored remote),
  and the pushed closure is sealed-free by construction (#149).

---

## Scene A — a same-identity dock task (the common case)

A trusted lane (the dev, or a docking agent): unsigned WIP is reviewed, the dev
approves, loot finalizes and lands.

### 1-3. Open a lane, work, project for review

```console
$ loot dock feat-embargo-cli
on dock 'feat-embargo-cli' — re-materialized its working tree here

# ...edit crates/loot-cli/src/embargo.rs...

$ loot ferry --with-wip                                    # PROPOSED (#149)
ferry: snapshotted working change 3f9a1c02 (change qsouzmpr) on 'feat-embargo-cli'
ferry: up to date (nothing to ingest or project)
ferry: projected WIP → review/feat-embargo-cli (provisional, 1 commit; no signature)
ferry: review/feat-embargo-cli → github (14 objects; sealed paths omitted)

$ loot-day review --dock feat-embargo-cli --title "embargo CLI (#88)"
gh pr create --head review/feat-embargo-cli --base main --fill
opened https://github.com/Connor-Miller/loot/pull/201  (change qsouzmpr)
```

The PR shows one commit, `Loot-Provisional: true`, no `Loot-Signature` — GitHub
marks the commit **Verified** (SSHSIG by loot's key) but the missing signature
trailer is the machine-checkable "not finalized yet."

### 4. Dev requests a change → revise → re-project

```console
# PR review comment: "rename the flag to --reveal-at"
# ...edit...

$ loot ferry --with-wip                                    # PROPOSED (#149/#150)
ferry: snapshotted working change a8cafda5 (change qsouzmpr) on 'feat-embargo-cli'
ferry: appended WIP → review/feat-embargo-cli (provisional, +1 commit, round 2)
ferry: review/feat-embargo-cli → github (3 objects)
```

Same **change id** `qsouzmpr` (durable), new **version id** `a8cafda5`. The
commit is **appended**, not force-pushed (#150), so the PR shows *"changes since
your last review."* Idempotent: no new commit if the tree is unchanged.

### 5-6. Approve → finalize → land (reachability-merge)

```console
# dev approves PR #201 on GitHub

$ loot-day land --pr 201                                   # PROPOSED (#150/#152)
land: pr #201 reviewDecision=APPROVED
land: finalizing on 'feat-embargo-cli' (change qsouzmpr)
finalized working change; the next mutating verb starts a fresh one
land: projected 7c1de0a4 → main (1 signed commit)
land: main → github (fast-forward, 3 objects)
land: review/feat-embargo-cli → 7c1de0a4 (collapsed); pr #201 merged by reachability
land: reaped provisional marks + branch for change qsouzmpr
land: pushed 3 object(s) to the relay
landed: change_id=qsouzmpr version_id=a8cafda5 main=7c1de0a4 pr=#201 status=merged
```

`loot new` is git-quiet (#149); the land is the *next* ferry step. The signed
commit lands on `main`, the PR head is pointed at it, and GitHub flips the PR to
**Merged** by reachability — no merge button, no merge commit (#150).

### 7. Log the day

```console
$ loot-day log --day 3
day 3: 1 change landed (qsouzmpr), 0 residual ingested, git projected downstream.
        loot LED; git main == projection(loot tip).
```

---

## Scene B — a cross-identity clone agent (the ADR 0018 asymmetry)

A keyring-separated agent (`crew`, in `..\loot-crew\crew`). Its unsigned WIP
**cannot cross the relay** (ADR 0018), so it finalizes first and the dev's bridge
runs the *integration* review (#152).

```console
# in the agent's clone
crew$ loot status -m "gc regression fix (#66)"
working change 5b2e77a1 — "gc regression fix (#66)"
crew$ loot new
finalized working change; the next mutating verb starts a fresh one
crew$ loot push
pushed 9 object(s) to the relay
```

```console
# on the dev's machine — the single bridge surfaces agent work as a PR
$ loot-day surface-agents                                  # PROPOSED (#152)
pull: pulled 1 change(s) from relay  (crew: 5b2e77a1 "gc regression fix (#66)")
surface: staged crew 5b2e77a1 in inbox dock 'crew-inbox'
surface: projected → review/crew/5b2e77a1 (signed; integration review)
surface: review/crew/5b2e77a1 → github
opened https://github.com/Connor-Miller/loot/pull/202  ([crew] gc regression fix)

# dev reviews the SIGNED change (not raw WIP — the asymmetry), approves #202
$ loot-day land --pr 202
land: pr #202 reviewDecision=APPROVED
land: integrating crew 5b2e77a1 into the harbor
merged dock 'crew-inbox' into 'home':
  fast-forward — crew's change applied onto the harbor tip
land: projected 91a0c3f5 → main; pr #202 merged by reachability
landed: change_id=(crew) version_id=5b2e77a1 main=91a0c3f5 pr=#202 status=merged
```

Revision rounds for a clone agent are **new signed changes** (edit → `loot new`
→ `loot push`); the bridge re-surfaces them onto the same PR. The agent never
touches GitHub or a mirror — it only speaks loot to the relay.

---

## Scene C — the residual, and the guard rail (#151)

```console
# someone fixes a typo directly on github.com main (break-glass / external)
$ loot ferry
ferry: ingested 1 git commit(s), projected 1 loot change(s)
ferry: README.md — git-origin edit absorbed as an unauthored change onto main
```

```console
# the co-located checkout warns on a direct commit (warn, not block — #151)
$ git commit -m "quick fix" README.md
loot: warning — committing directly to git main is off the loot-first path.
      git main is a projection of loot; the next `loot ferry` will ingest this.
      prefer: loot dock <task> → loot ferry --with-wip → PR.
      (proceeding anyway; use the loot flow next time)
[main a1b2c3d] quick fix
```

---

## The verb surface (what the agent actually types)

| step   | same-identity dock                              | cross-identity clone                         |
|--------|-------------------------------------------------|----------------------------------------------|
| start  | `loot dock <task>`                              | (already in the clone dir)                   |
| work   | edit files                                      | edit files                                   |
| review | `loot ferry --with-wip` → `loot-day review`     | `loot new` → `loot push`; dev: `loot-day surface-agents` |
| revise | edit → `loot ferry --with-wip` (appends a round)| edit → `loot new` → `loot push` (new signed change) |
| land   | `loot-day land --pr <n>`                        | `loot-day land --pr <n>` (dev-side)          |

Core loot verbs touched: `dock`, `ferry --with-wip` (**new mode**), `new`,
`push`, `pull`, `dock merge`. Everything GitHub-shaped (`gh pr create/merge/close`,
approval polling) lives in `loot-day`, never in loot core.

---

## Seams surfaced (the payoff of prototyping cheap)

1. **`loot ferry --with-wip` is doing a lot** — snapshot + finalized round-trip +
   WIP projection + branch push in one verb. Worth asking for #155: split the WIP
   lane into a distinct `loot review-export`/porcelain so a plain `loot ferry`
   stays the finalized-only round-trip, or keep one overloaded verb behind the
   `loot-day` wrapper? *Verb-granularity decision, deferred to the build.*

2. **A PR ↔ change_id/dock ledger is required.** `loot-day land --pr 201` must map
   PR 201 → dock `feat-embargo-cli` → change `qsouzmpr` to know what to finalize
   and land. Nothing in #149-152 owns this map; it needs a small local ledger
   (e.g. `.loot/git-mirror/pr-map`). **New artifact for #155.**

3. **`land` must target a dock explicitly, not the ambient one.** With parallel
   docks, the agent's *current* dock may not be the PR's dock. `land` has to
   `loot new` on the PR's specific dock (via the ledger, seam 2) — otherwise it
   finalizes the wrong lane. **Correctness constraint for #155.**

4. **The clone bridge needs a staging spot.** Scene B invented an `inbox dock`
   (`crew-inbox`) to hold a pulled signed change before merging into the harbor.
   #152 said "converge_heads / dock merge" but didn't name *where* the pulled
   change lands first. **Bridge-local structure to pin in #154/#155** — likely one
   inbox dock per agent, dropped after integration.

5. **The approval *loop* vs the *signal*.** #152 pinned the signal
   (`reviewDecision == APPROVED`); the transcript shows a **manual** `loot-day
   land --pr N`. For an autonomous agent with no human driving the land, something
   must *poll* — a `loot-day watch` background loop, or a CI/webhook. **Trigger-loop
   decision for #155** (respecting the "no standing loops" preference — likely
   an explicit `land`/`watch` the dev starts, not an always-on daemon).

6. **Verified-but-provisional on GitHub.** A WIP review commit is SSHSIG **Verified**
   yet deliberately unsigned-in-loot. Reviewers might read "Verified" as "blessed."
   Minor, but the workflow doc (#154) should state that Verified = integrity only;
   the loot landing is what blesses. *Doc note, not a code change.*

**None of these reopen #149-152** — they are integration details that belong to
the tooling build. The four design decisions compose into a coherent daily loop;
the verb surface is small (`dock`, `ferry --with-wip`, `new`, `push`, plus the
`loot-day` orchestrator) and reads cleanly.
