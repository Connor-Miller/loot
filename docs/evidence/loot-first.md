# Evidence: a working day driven loot-first

The destination proof for wayfinder map #148 ("flip the agentic workflow
loot-first, git downstream"), ticket #155. This document **is** the day's unit
of work: it originated in loot's working tree, was reviewed on GitHub as a PR
built from **projected unfinalized loot WIP**, and landed by `loot new` — with
git `main` projected downstream. If you are reading it on git `main`, the
workflow worked: no git commit ever created this file.

## What "loot-first" means here (docs/agents/workflow.md)

- The working change accrues in loot (auto-snapshot); `loot ferry --with-wip`
  projects it to a sealed-free `review/<dock>` branch as **provisional**
  commits — `Loot-Provisional`, no `Loot-Signature` (the missing signature is
  the machine-checkable "not finalized"), still SSHSIG-signed for integrity.
- The PR is a review *view*. Approval → `loot new` (finalize + sign, git-quiet)
  → the next ferry projects the one signed commit onto `main` and reaps the
  provisional lane.
- The orchestrator (`tools/loot-first.ps1`) publishes by **single-ref push
  with an inline URL** — the private mirror never gains a remote — and points
  the PR head at the landed sha so GitHub marks the PR **Merged by
  reachability**: no merge button, no merge commit, loot is the merger.

## The run (2026-07-11)

1. **Catch-up (the #151 residual, working as designed).** GitHub `main` held
   9 commits loot had not ingested (the jj-ergonomics build and this
   milestone's own tooling — the last git-first changes there will ever have
   to be). One plain `loot ferry` ingested all 9 with zero conflicts; `loot
   push` published the catch-up — after redeploying the relay to format v6,
   the first live v6 push (43 objects).
2. **Round 1 caught a real leak — the run's central finding.** The first
   `review` pass (PR #161) put `docs/pitch/` into a **public** PR diff. The
   projection filtered on *readability*, and the dev's own mirror identity
   can read restricted content (ADR 0028's full-readable-tree contract) — so
   "sealed-free by construction" was false exactly for the identity doing
   the publishing, and the same flaw would have hit `main` itself on the
   first land. Contained same-hour (PR closed, branch deleted; the dangling
   diff on GitHub's side is accepted residual, logged on ticket #155).
   **Fix, same day:** publication is now a **public-delta** — the git parent
   tree plus the change's delta restricted to `Visibility::Public` — so
   sealed content never publishes *even when readable*, and published
   history is git-shaped for free (loot-only paths like `.scratch/` no
   longer spray the diff). Shipped as "Publication is a public-delta, never
   the readable tree" (PR #163, `7ea6ee0`), with tests pinning the exact
   leak class.
3. **Round 1, take two.** With the fix live, `review` projected a clean
   one-file diff and opened the fresh PR.
4. **Round 2.** This section updated with the live PR number — the revision
   **appended** a second provisional commit to the same durable change lane,
   so the reviewer sees "changes since your last review" (#150).
   *(filled in during round 2 of the live run)*
5. **Land.** On approval, `loot-first.ps1 land` finalized, ferried, pushed
   `main`, collapsed the PR head to the landed sha, and pushed the relay.
   The `landed:` verdict is recorded on ticket #155.

## Friction found live (dogfood data, not failure)

- **The leak above is the headline**: a live run falsified a design
  assumption two design reviews and a green test suite had all blessed —
  the unit tests only sealed content *from* the identity, never *to* it.
  Same lesson as the concurrent-agents epic: only a real run catches the
  gap between "reviewed" and "true."

- **Self-approval is impossible on GitHub** — you cannot approve your own PR,
  so the uniform "every change lands through a PR" rule (#152) needed a
  self-authored fast path in `land`: author == viewer and no
  `CHANGES_REQUESTED` counts as the approval signal. A second identity (an
  agent reviewer, or the dev reviewing an agent) uses the real
  `reviewDecision == APPROVED` gate.
- **Format-version coupling**: the first loot-first day collided with the
  FORMAT_MAJOR 5→6 bump — the v6 client could not push until the relay was
  redeployed (idempotent `setup:loot`, one command). Worth remembering that a
  format bump means "redeploy the relay the same day."
- **Single-lane v1**: the mirror's `main` tracks the home dock, so this run
  drove the lane in `home` directly. A named-dock lane lands through the
  harbor (`loot dock merge`) before projection — the orchestrator does not
  automate that hop yet; it is the known follow-up.
- **`pwsh` vs `powershell`**: the tooling docs said `pwsh`; this machine has
  only Windows PowerShell 5.1. The scripts run fine under 5.1 (by design,
  ASCII-only) — invoke as `powershell -File` or `& .\tools\loot-first.ps1`.

## Verdict

Every box of the map's destination is exercised by this file's own history:
originated in loot, reviewed as projected unsigned WIP, landed by loot
finalize, git `main` projected downstream, relay pushed the same day. loot
led; git followed.
