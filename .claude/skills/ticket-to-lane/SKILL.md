---
name: ticket-to-lane
description: Claim a loot ticket and spawn its sealed work lane. Use when the user says "work on #N", "claim #N", "start on #N", or otherwise asks to begin a numbered issue — assigns it, spawns the lane, and cd's you in so all work happens in the lane, never the primary.
---

# ticket-to-lane

**Purpose.** Automate the claim ritual every loot working session starts with
(docs/agents/issue-tracker.md): assign the ticket, spawn its sealed lane over
the shared store, and land the cwd inside that lane. Without this, agents spawn
lanes from inside other lanes (refused) or forget to assign.

**Trigger phrases.** `work on #N` · `work on ticket #N` · `claim #N` ·
`start on #N` · `pick up #N`.

**Type: AFK.** Runs end to end without a human. One HITL stop only: if the
ticket is already assigned to someone else (step 2).

**The binary.** Use `C:\Users\conno\source\repos\loot\target\release\loot.exe`
(the loot on PATH is stale). Below it is written `loot` for brevity.

## Steps

Run steps 1–4 **from the primary directory** (`C:\Users\conno\source\repos\loot`) —
lane spawn is primary-only. Never mutate the primary tree; these are read-only
reads plus one registry-writing spawn.

1. **Read the ticket.**

   ```
   gh issue view <n> --repo Connor-Miller/loot
   ```

   Note title, body, and any `**Blocked by #<n>**` lines. If a blocker is still
   open, stop and report it — the ticket is not ready.

2. **Check assignment, then claim.** If the ticket is already assigned to
   someone other than you, **stop and report** — do not steal it. Otherwise:

   ```
   gh issue edit <n> --repo Connor-Miller/loot --add-assignee @me
   ```

3. **Verify you are in the primary, and the repo is keyed.** Spawn is refused
   from inside a lane, and requires a keyed repo.

   - In the primary directory, confirm `.loot/lane-id` is **absent** (its
     presence, or `.loot/store`, means you are already in a lane — abort and
     move to the primary before spawning).
   - Confirm `.loot/id` **exists**. If it is missing, the repo is not keyed:
     **stop and report that the `mint-agent-identity` skill must run first.**

4. **Spawn the lane.**

   ```
   loot lane new --ticket <n> --porcelain
   ```

   The handle is ticket-derived (`t<n>`, suffixed until free). Parse the printed
   tab-separated `L` row and take **field 4** as the lane path:

   ```
   L <TAB> <handle> <TAB> <name> <TAB> <path> <TAB> <base-oid> <TAB> <tip-oid> <TAB> <pr> <TAB> clean|dirty <TAB> <heartbeat> <TAB> <status>
   ```

   The path may carry a `\\?\` extended-length prefix (e.g.
   `\\?\C:\Users\conno\source\repos\loot-lanes\t402`); strip the leading `\\?\`
   before using it with `cd`.

5. **Enter the lane.** All subsequent work happens here until the ticket lands:

   ```
   cd <path from field 4>
   ```

6. **Report.** State the lane handle, the lane path, and the tip oid (field 6),
   plus a one-line restatement of what the ticket asks. From here on, follow
   docs/agents/workflow.md (describe → ferry --with-wip → new → land).

## Guardrails

- **Steps 1–4 are primary-only.** `loot lane new` refuses from inside a lane.
  Verify `.loot/lane-id`/`.loot/store` are absent before spawning (step 3).
- **Never run a mutating loot verb in the primary working tree** beyond the
  spawn itself (bug #436) — no `new`/`describe`/`undo` there. `loot lanes`
  observation is read-only and safe.
- **Do not spawn if already assigned to another agent** (step 2 HITL stop) or
  if a blocker is open (step 1).
- **Keyed-repo gate:** no `.loot/id` → hand off to `mint-agent-identity`, do
  not proceed.
- **Handle collisions are automatic** — `--ticket <n>` suffixes the handle
  until free; don't invent your own name.
- Observe the claim board any time with `loot lanes --porcelain` (read-only;
  never refreshes another lane's heartbeat).
