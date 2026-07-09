# Backlog triage against the milestone
GitHub: #55

Type: task
Status: resolved
Blocked by: —

## Question

Classify every open issue (#1–#26 tail, S5–S9 #36–#40, CA2–CA4 #50–#52) as **on-path** (label/milestone it), **parked** (post-milestone, say why), or **dropped** — measured against the map's destination (loot hosts loot, wayfinder map #54).

Provisional read from the charting session, to verify not rubber-stamp: on-path — CA2/CA3/CA4, #14 hard embargo, #8 TLS-or-alternative, daily-driver verbs #1 diff, #2 new -m, #3 pull auto-surface, #7 status detail. Parked — S6–S9, #10–#13, #15–#26 tail unless the dogfood pilot produces evidence. Also: #9 duplicates S5 (#36) — merge them; decide whether S5 itself is on-path or evidence-gated.

## Answer

Every open execution issue classified against the map's destination (loot hosts loot, ADR 0024), using the Dogfood pilot's evidence (docs/dogfood/2026-07-07-pilot.md). Mechanics: **GitHub milestone ["loot hosts loot"](https://github.com/Connor-Miller/loot/milestone/1) membership = on-path**; open without milestone = parked (rationale below); dropped = closed.

### On-path (16, in the milestone)

**Seal-trust cluster (the pilot's security findings — first priority):** #61 fail-open globs, #62 silent demotion, #63 mis-seal remedy (at minimum the pre-finalize visibility gate half), #65 spurious conflict, #66 gc regression, #67 unknown flags.
**Daily-driver cluster (pilot-confirmed):** #64 .lootignore, #1 diff, #13 diff --conflict, #7 status delta, #3 pull auto-surface, #21 init attributes template (cheap mitigation for the #61/#62 class).
**Agent leg:** CA2 #50, CA3 #51, CA4 #52.
**Thesis leg:** #14 external escrow (hard embargo is in-milestone; design comes from wayfinder's Hard embargo mechanism ticket #59).

### Conditional (open design tickets decide; not milestoned yet)

- #8 TLS — Relay on the VPS (#57) may choose reverse-proxy/tunnel instead; #57's resolution milestones or closes it.
- #15 embargo-status — Hard embargo mechanism (#59) may reshape what "embargo state" even is; #59 decides.
- #4 whoami --pubkey — Agent identity model (#58) decides if bootstrap scripting needs it.

### Parked (evidence-gated; unpark with a pilot-style finding)

#2 (status -m already covers the ceremony), #5, #6, #10, #11, #12, #16 (rotation deferred per ADR 0016), #19, #20, #22, #23, #24, #25, #26 + S5 #36, S6 #37 (pilot: transfer not a cost at this scale), S7 #38 (VPS uses fs backend), S8 #39, S9 #40.

### Dropped

#9 — closed as duplicate of S5 #36.

**Drift verdict made concrete:** the S-epic's remaining slices are all parked on evidence; the milestone consists of seal-trust, daily-driver, agent, and thesis work only.
