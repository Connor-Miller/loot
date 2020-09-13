# The loot-first workflow: loot leads, git is downstream

How work reaches `main` in this repo: every change **originates and finalizes in
loot**, and git `main` is a mirror **projected downstream** from loot. The GitHub
PR is a *review view*, not the merge target — loot is the merger. Read this before
driving a working day here; it sits beside [identity.md](identity.md) (who agents
are) and describes what everyone does day to day.

> **Status (2026-07-11): LIVE.** Map [#148](https://github.com/Connor-Miller/loot/issues/148)
> closed with #155's live run; `loot ferry --with-wip` and the `loot-first`
> orchestrator are the shipped surface, and this repo runs loot-first (the
> git-first `tools/loot-day.ps1` is deprecated). The orchestrator is now the Rust
> `loot-first` binary — #218 replaced `tools/loot-first.ps1` (deleted), reading
> loot state in-process rather than scraping `loot` stdout. The prototype
> transcript is
> [../research/loot-first-workflow-prototype.md](../research/loot-first-workflow-prototype.md).

## Why

The #54 dogfood drive showed loot *following* git — work landed via GitHub PRs and
the ferry only caught loot up afterward. This inverts the polarity so loot leads.
It builds on the jj-ergonomics trio (map #132: auto-snapshot, stable `change_id`,
oplog) which made loot *pleasant* to lead in; this workflow is how you *actually*
lead in it.

## The two ids (map #132)

Every change carries two identifiers, shown throughout:

- **version id** — content+author hash, 8 hex digits (`3f9a1c02`). Rewrites on
  every snapshot.
- **change id** — the durable handle, reverse-hex letters (`qsouzmpr`). Minted
  once, carried across snapshots and rewrites. This is what ties a review branch,
  its PR, and the eventual landed commit together.

## The daily loop (same-identity work)

The common case — the dev, or a trusted agent docking into the dev's store. One
code path; **every change lands through a PR** (you self-approve your own).

1. **Open a lane.** `loot lane new --ticket <n>` (ADR 0034/0035, #232) — a
   sealed working directory over the store, spawned from the primary; work from
   the printed dir. `loot lanes` reports every live lane (tip, in-flight PR,
   dirty/clean, heartbeat) — check it before acting on shared state. Cheap; a
   lane hosts one in-flight change → PR at a time; parallel work = more lanes.
   (`loot dock <task>` — the ADR 0022 in-place switch — survives in the primary
   until the harbor, #229.)
2. **Work.** Edit. The working change accrues by auto-snapshot (map #132); you
   never run a manual `status -m` before finalize. **`loot describe -m
   "<subject>"` is the first verb on dirty work** — it captures *without*
   finalizing, and names the change while you still remember what it does. Skip
   it and step 6 refuses (#174): `new` is capture-then-finalize, so on a dirty
   tree it would otherwise sign your edits in one stroke, straight past this
   lane, under the `(working change)` placeholder.
3. **Project for review.** `loot ferry --with-wip` snapshots the dock's WIP and
   projects it to a sealed-free branch named for the *position* —
   `review/<lane-id>` from a lane, `review/<dock>` on the primary (#281, so
   concurrent lanes never share a ref) — then a single-ref push publishes it to
   GitHub; `loot-first review` opens the PR. The PR reviews **unsigned** WIP.
4. **Revise.** On a review comment, edit and re-run `loot ferry --with-wip`. It
   **appends** a commit to the branch (same `change id`, new `version id`), so
   GitHub shows *"changes since your last review."*
5. **Approve.** Approve the PR on GitHub.
6. **Finalize.** `loot new` signs the change (ADR 0018) and starts the next one.
   This is **git-quiet** — no mirror I/O, so parallel lanes never contend here.
   It **refuses an un-described change** (#174) — the message it signs is
   permanent, and becomes the subject of the commit projected onto `main`. Name
   it with `describe -m` (step 2) or `new -m "<subject>"`; the refusal keeps your
   captured edits and withholds only the signature.
7. **Land.** `loot-first land --pr <n>` detects the approval
   (`reviewDecision == APPROVED`, or the self-authored fast path — GitHub forbids
   approving your own PR), runs the **pre-land gate** (`cargo test` — review
   approved *projected WIP*, so nothing has yet proven the commit about to land
   builds; `--skip-tests` is the break-glass for non-code lands), finalizes the
   lane (a no-op if step 6 already ran — a bare `loot new` mints no empty
   change), projects the one **signed** commit onto `main`, and
   collapses the PR head onto it. GitHub **auto-closes the PR on the zero-diff
   collapse** — that close *is* the landing signal (live finding of the #155 run;
   see below), and the tool attaches a pointer comment (change id → landed sha)
   as the audit trail. No merge button, no merge commit. The provisional branch
   is reaped. A `landed: change_id=… main=<sha> pr=#<n> status=…` verdict is
   emitted.

## The review-projection mechanic

- **Building the PR** (#149): the review commit carries `Loot-Change-Id` +
  `Loot-Author` + `Loot-Provisional`, and **no** `Loot-Signature`. The git commit
  is SSHSIG-signed (so GitHub shows **Verified**), but the *missing* signature
  trailer is the machine-checkable "not finalized yet." Sealed paths are omitted
  from every projected commit, so the branch's whole object closure is safe to
  push to GitHub.
- **Landing the PR** (#150, amended by the #155 live run): a finalized commit can
  never share the provisional commit's oid (it adds the signature, drops the
  provisional marker). Every GitHub *merge button* would rewrite oids or add a
  merge commit loot would have to ingest — so we don't use it. Instead loot lands
  the signed commit on `main` and collapses the PR head onto it. #150 predicted a
  reachability-based **Merged** flip; the live run falsified that — GitHub
  **auto-closes** a PR whose head is force-pushed to an already-landed commit
  (zero diff) instead of marking it Merged. The auto-close is therefore the
  landing signal, and the pointer comment carries the audit trail (PR ↔ change id
  ↔ landed sha). `main` still gets exactly **one clean commit per change**.

## Cross-identity agents (clones)

A keyring-separated agent (ADR 0026) works in its own clone and syncs via the
relay. Because **only signed history crosses the relay** (ADR 0018), its unsigned
WIP can't reach the dev — so the flow differs:

- The agent works, `loot new` (signs), `loot push` (relay).
- The dev's **single bridge** pulls the signed change, stages it, and surfaces it
  as a `review/<agent>/<cid>` PR for **integration review** (`loot-day
  surface-agents`).
- The dev reviews the **signed** change (the one principled asymmetry — a clone's
  review is post-finalize, not of raw WIP), approves, and `loot-day land`
  integrates it into the harbor and onto `main`.
- Revision rounds are **new signed changes** (edit → `loot new` → `loot push`); the
  bridge re-surfaces them onto the same PR.

The gate for a clone sits **before its change enters `main`** — the right gate for
cross-identity work. The agent never touches GitHub or a mirror; it only speaks
loot to the relay.

## Ferry authority: loot leads

loot was always the merge authority (git never merges). Loot-first flips two
things: the **default direction** (loot→git projection is primary; git→loot ingest
is the exception) and **who feeds GitHub `main`** (loot's single-ref push, not the
checkout's `git push`).

**Invariant: `git main == projection(loot dock tip)`.** Every ferry pass
**ingests any git-origin commit before it projects**, so loot's projection is
always a fast-forward over the current git `main` — which is why the land above is
a clean FF.

The **git→loot residual** — the ways git `main` can move without originating in
loot — all absorb through the same converge+ingest path:

- **A direct edit on github.com** (a browser typo fix) — ingested as an unauthored
  change (or authored-self if the git author maps to the dev).
- **An external contributor's PR** merged on GitHub the normal way — ingested
  unauthored, preserving their git author.
- **A loot PR merged with GitHub's own button** instead of `loot-first land` — the
  content originated in loot, but the squash mints a *new* commit the mirror has
  never seen, so it ingests like any other break-glass land (#297). It is the
  commit, not the content, that must be ingested.
- **A break-glass local commit** (see guard rails) — same ingest.

When one of these lands while you have local work, the ferry folds your line in
with a merge — which **signs your work** to make it a merge parent. So it needs a
name first: an un-described working change makes `ferry` (and `lane merge`, and
the `adopt` catch-up) refuse, pointing at `describe -m` (#275). Nothing is lost —
the capture happens, the disk is untouched, and re-running after naming completes
the pass. Edits you never captured take two passes, because naming *is* capturing.

A genuine same-path conflict is held at its last clean state in git (ADR 0028) and
surfaced by `loot conflicts`; that change can't land until you resolve it in loot.

## Parallel work and landing

- **Which lane?** Trusted work **docks** (same identity, shared store — reviewed
  as unsigned WIP, no per-agent GitHub setup). A keyring-separated agent **clones**
  (see above). The rule is trust: a dock shares the store's keyring, so anything
  that must be sealed from an agent requires a clone.
- **Landing serializes at the harbor.** `main` tracks the harbor (the integrator
  line). The harbor is an **on-demand lock**, not a daemon (#229, ADR 0036):
  `loot-first land` takes a brief shared-store lock (`.loot/git-mirror/harbor.lock`)
  across the git-`main`-critical section — ferry's projection, the FF push, the
  PR-head collapse — and releases it. A concurrent land from another lane blocks
  on the lock, then ferries against the `main` this one moved, so its converge is
  against the *landed* tip and its push is a clean fast-forward. Two lanes
  finalizing at once thus land one behind the other, `main` stays linear, and the
  two-writer fork the CA epic fixed cannot reappear. If a change conflicts with
  what landed while the lane worked, the land **bounces** — nothing is pushed, the
  signed change is safe, and you reconcile (`loot resolve …`) and re-run `land`.
  And a land that does not actually move `main` now **refuses** rather than
  reporting a false `landed:` (the #195 guard) — unless git proves the line was
  *already* projected by an earlier bare `loot ferry` and only the push + PR
  collapse are owed (mirror `main` strictly ahead of `origin/main` and carrying
  this land's signed tip), in which case the land proceeds instead of wedging
  (#349).

## Abandonment

- Reject a **docking** PR → `loot abandon <version-id>` (map #132) drops the dock's
  working change; the ferry reaps the review branch + its provisional marks by
  `change_id`. Nothing was signed, so nothing traveled.
- Reject a **clone** PR → the bridge closes the PR and deletes the review branch;
  the agent's signed change stays **unintegrated** on the relay (it never entered
  `main`).

## Guard rails — what NOT to do

- **Don't commit straight to git `main`.** git `main` is a projection of loot. A
  direct commit is **break-glass**, not routine: a pre-commit hook warns you (it
  does *not* hard-block — break-glass must stay possible), and the next ferry
  ingests the commit. **GitHub's own merge/squash-merge button is break-glass
  too** — it mints a commit on GitHub `main` that the remoteless mirror never sees,
  so run `loot ferry` after one *even when the content originated in loot* (it is
  the commit, not the content, that must be ingested — #297). Recovery from a
  skipped ferry is in [concurrent.md](concurrent.md#a-break-glass-git-commit-landed-on-main--loot-ferry).
  Prefer the dock → PR flow.
- **Never give the mirror a remote.** `.loot/git-mirror/mirror.git` is local-only
  and holds sealed `docs/pitch/` in **plaintext** (ADR 0028). No `git remote add`,
  no `--all`/`--mirror` push, ever. Publishing to GitHub is always a **single-ref
  push with an inline URL** of a sealed-free branch (`main` or `review/*`).
- **Sealed content never leaves.** Projection omits sealed paths from every commit
  (no filename, no bytes). The branches pushed to GitHub are sealed-free by
  construction — but only because projection is the *only* path to GitHub. Don't
  invent a second path (e.g. pushing the mirror wholesale) that would bypass it.
- **"Verified" ≠ blessed.** A WIP review commit shows GitHub **Verified** (SSHSIG
  integrity) while deliberately unsigned in loot. Verification means "loot's key
  produced this commit," not "this is finalized." The loot landing is what blesses.

## See also

- [concurrent.md](concurrent.md) — running several agents at once: one lane each,
  what serializes at the harbor, and the drift discipline.
- [identity.md](identity.md) — agents are clones (ADR 0026).
- ADRs: 0018 (signed authored history), 0022 (docks/harbor), 0026 (agent
  identity), 0028 (git bridge / ferry), 0023 (machine output).
- Map [#148](https://github.com/Connor-Miller/loot/issues/148) and its tickets for
  the reasoning behind each decision.
