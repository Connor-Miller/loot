# Wayfinder map: thesis-proof milestone — loot hosts loot
GitHub: #54

## Destination

**loot hosts loot.** This repo's daily development runs on a loot relay on the VPS, with the dev and AI agents as distinct identities in one repo: at least one restricted path agents cannot read, a grant/maroon cycle exercised for real, and one **hard-embargoed** change whose key is withheld by an external escrow (adversary-proof, not honest-clock) — demonstrating that visibility and permissions are properties of content and changes, not of the repository. git dual-runs throughout (GitHub keeps issues + backup); divergence pain is dogfood data.

## Notes

- Charted 2026-07-07 in a wayfinder grilling session prompted by a drift check. Verdict: the S-epic (lore-borrows) and DX tail had drifted toward feature-borrowing; the CA epic is *retroactively on-path* — docks/harbor/porcelain/buoys are how agents participate as identities. Decision record: ADR 0024.
- Standing decisions (do not re-litigate): thesis-proof milestone over backlog-triage-only; hard embargo (#14) is **in** the milestone; dual-run with git (no boat-burning); GitHub is the wayfinder tracker (`docs/agents/issue-tracker.md`).
- Execution issues are **not** wayfinder tickets. The agent leg runs through existing issues CA2 #50, CA3 #51, CA4 #52.
- Skills to use per ticket type: /grilling + /domain-modeling (grilling), /prototype (prototype), /research (research). Update CONTEXT.md and docs/adr/ inline as ticket resolutions land decisions.
- Repo conventions: solo dev, Windows 11, VPS work only via idempotent scripts in the `scripts` repo (PowerShell).

## Decisions so far

- [Backlog triage against the milestone](https://github.com/Connor-Miller/loot/issues/55) — GitHub milestone "loot hosts loot" = on-path (16 issues: seal-trust #61-#67 cluster, daily-driver #64/#1/#13/#7/#3/#21, agent CA2-CA4, thesis #14); #8/#15/#4 conditional on open design tickets #57/#59/#58; S-epic remainder + DX tail parked on evidence; #9 closed as dup of S5
- [Dogfood pilot: one loot-only working day](https://github.com/Connor-Miller/loot/issues/56) — ritual almost livable (docks, status -m, sync all good); gated by 2 security-grade attributes bugs (#61 fail-open globs on Windows, #62 silent visibility demotion), no ignore (#64), no diff (#1/#13), spurious conflict (#65), gc regression (#66); DX evidence for triage in docs/dogfood/2026-07-07-pilot.md; S5/S6/#26 not needed at this scale
- [Relay on the VPS: transport decision + idempotent deploy](https://github.com/Connor-Miller/loot/issues/57) — nginx + Let's Encrypt TLS + ufw reverse proxy (loot serve on 127.0.0.1:4000, allowlist enabled per ADR 0014); idempotent `scripts/setup-loot.js` (VPS deploy key → rustup → cargo build → loot-relay systemd → edge); not yet run on the VPS

## Not yet specified

- **Key provenance chains** — grants prove who, not authority-to-grant. May sharpen once agents-as-identities is real (many grants flying around).
- **git interop bridge** — dual-run divergence pain will tell us what the bridge actually needs to do.
- **Relay announcement / selective delivery** — who holds which key, so bundles can be targeted. Waits on real multi-identity traffic.
- **Multi-human collaboration** — everything in this milestone is one human + agents; a second human keyholder is a different trust texture.
- **Soft advisory claims** — only if agent thrashing actually shows up (see CONTEXT.md Open/undecided).
- **Zero-knowledge host as a product** — the post-milestone pitch ("the host that cannot read your code"); parked until the milestone proves it on ourselves.

## Out of scope

(none recorded)
