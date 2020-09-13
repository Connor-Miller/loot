---
name: diagnose-push-rejected
description: Triage why `loot push` was rejected by walking loot's three rejection causes (relay allowlist / malformed-or-stale-format envelope / repo drift). Use when the operator says "push rejected", "push failed", "relay refused", or a push loops on an error instead of publishing.
---

# diagnose-push-rejected

Explain, in one line, **why `loot push` was rejected by the relay** — and print
the exact fix, or the operator escalation, for the cause that matched.

A rejected push has three very different causes, and an agent that hits one with
no guidance typically **retries in a loop** — which never helps, because two of
the three are relay-side (an operator has to act) and the third needs a `loot
pull` first, not another push. This skill disambiguates them.

- **relay allowlist** — this identity's pubkey is not on the relay's allow list,
  so the relay refuses to stow. *(Fix is operator-side.)*
- **malformed / stale-format envelope** — a wire format-version mismatch (usually
  the relay is behind and cannot read what this build wrote). *(Fix is a relay
  redeploy — operator-side.)*
- **repo drift** — the local graph is behind the relay tip. *(Fix is safe to run:
  `loot pull`, then re-push.)*

## Triggers

Run this when the operator says any of:

- "push rejected" / "push failed" / "relay refused"
- "`loot push` keeps erroring" / a push loops on the same error
- "relay rejected push (…)" pasted from a failed run

## Type: AFK

Runs unattended. **Every diagnostic step below is read-only** (reading the
rejection text, `loot remote list`, `loot whoami --pubkey`) — safe to run in a
loop without operator input. The **fixes split by cause**:

- Causes **(1) allowlist** and **(2) format mismatch** are **relay-side / operator
  config** (`push` is a disclosure barrier and the relay's allow list is not a
  local loot file — see below). **Diagnose, print the escalation, and STOP** — do
  not retry the push.
- Cause **(3) repo drift** is safe: `loot pull` (fetch + merge + converge) then
  re-`loot push` is non-destructive and idempotent. This one the skill **may run**.

### Setup (once, before the tree)

The real binary is
`C:\Users\conno\source\repos\loot\target\release\loot.exe` (the `loot` on PATH is
an older build). Run every command from the **lane / repo working directory** you
were pushing from — never edit or run verbs in another position's tree (bug #436).
Verify a subcommand with `loot <verb> --help`.

Two facts you need throughout:

- **This identity's pubkey** — `loot whoami --pubkey` (bare OpenSSH line). This is
  the value an operator adds to the relay's allow list.
- **The target relay** — `loot remote list` (name → url). `loot push` resolves its
  target as: explicit URL > `--remote <name>` > `origin`. Confirm *which* relay
  refused before escalating.

**The allowlist itself is not a local file.** It is the set of pubkeys the relay
process was started with (`loot serve --allow <pubkey> …`, provisioned from the
`scripts` repo) — relay-side operator config, with **no** local loot command that
reads it. So step 1 can confirm your pubkey and the target, but the allow list can
only be changed on the relay.

## The one fact the whole tree turns on

Every rejection surfaces as a single error line of the shape:

```
relay rejected <verb> (<HTTP code>): <message>[<hint>]
```

(`<verb>` is `push` or `wants` — the object-negotiation round runs *before* the
stow, so a format mismatch can surface on `wants` first.) **The cause is in that
line.** Get the exact text — re-run `loot push` once and capture it verbatim, or
have the operator paste it — then branch on the code and message.

## Decision tree

Walk the branches **in order** and stop at the first that matches.

### 1. Format mismatch? — message contains `unsupported format version`

If the message contains **`unsupported format version`** (on either `push` or
`wants`, typically `400 Bad Request`), the relay could not read the wire format
this build wrote. Every client verb sends bytes marked with the *current*
`FORMAT_MAJOR`, so a version rejection means **the relay is behind**, not that
this build is stale (the client even appends a hint saying so — #361/#431).

- Diagnosis: `The relay is on an older wire format and cannot read what this loot build wrote.`
- Fix — **operator, relay-side. Do not retry the push.** Redeploy the relay:
  `npm run setup:loot` from the `scripts` repo (this is a relay redeploy, not a
  client upgrade). After the operator confirms the redeploy, one re-push verifies.

### 2. Allowlist? — `(401 Unauthorized): signature verification failed` on `push`

A `401` on the `push` (stow) step with **`signature verification failed`** is the
allowlist branch. **Caveat you must state:** the relay collapses an
allowlist-miss and a genuine bad signature into the *same* error — the envelope
unwrap returns `BadSignature` whether the signature was invalid **or** the pubkey
simply is not on the allow list (`unwrap_envelope`, loot-identity). So the text
alone cannot tell them apart; resolve it by ruling out a real key problem:

- Confirm the identity is intact: `loot whoami --pubkey` returns a valid OpenSSH
  line (an identity with a broken/rotated key is the genuine-bad-signature case —
  the operator re-`peer add`s the new pubkey; see `loot id rotate`, ADR 0016).
- Confirm the target: `loot remote list` — is this the relay that should know you?
- If the key is intact and the relay is the right one, the overwhelmingly likely
  cause is **the allowlist**.
  - Diagnosis: `The relay refused this identity — its pubkey is almost certainly not on the relay's allow list.`
  - Fix — **operator, relay-side. Do not retry the push.** Hand the operator this
    identity's pubkey (`loot whoami --pubkey`) to add to the relay's allow list
    (a `--allow <pubkey>` line where the relay is provisioned, `scripts` repo).
    Re-push only after they confirm the key was added.

### 3. Repo drift — anything else, or a push that "worked" but forked

If the error is **not** a format mismatch and **not** a `401`, or the push
appeared to succeed but your line **forked** the relay tip (a later `loot pull` /
`loot log` shows work on the relay you never had), treat it as **repo drift** —
the local graph is behind the relay tip.

Note the honest shape here: relay `stow` is **append-only** (it never merges), so
being behind does **not** usually produce a hard rejection the way (1)/(2) do — a
push of forked history is *accepted* and simply forks the DAG on the relay.
"Repo drift" is therefore the **residual** branch: the safe, always-correct move
when the rejection is not one of the two operator-side causes above.

- Diagnosis: `The local graph is behind the relay tip (drift); reconcile before re-publishing.`
- Fix — **safe to run:**

  ```
  loot pull        # fetch + merge + converge the relay's changes into your line
  loot push        # re-publish onto the reconciled tip
  ```

  `loot pull` is key-gated ciphertext (safe by construction). If the pull surfaces
  a conflict, it is a genuine merge to resolve (`loot conflicts` / `loot resolve`)
  — hand that off; re-push once resolved.

### One more shape you may see (not one of the three)

A `413 Payload Too Large` is a **fourth**, distinct cause: one bundle exceeds the
relay's request-body limit (a pre-#309 relay caps at 2 MiB, or a single object
outgrows the limit). The client appends its own hint. The fix is again
operator-side — upgrade the relay — not a client retry. Report it as out of this
skill's three-cause scope.

## Output contract

Emit exactly two lines per run:

```
diagnosis: <one-line reason, naming the branch that matched>
fix: <the exact command, or the operator escalation, for that branch>
```

## STOP conditions

- Causes **(1)** and **(2)** (and the `413` shape): **stop after the diagnosis
  line.** The fix is operator-side; retrying the push cannot help.
- Cause **(3)**: you may run `loot pull` then re-push, but stop and escalate if
  the pull surfaces a conflict.

## See also

- `CONTEXT.md` — Push envelope, Remote, Relay, Stow, Network sync
  (`serve`/`push`/`pull`), Identity keypair, Peer registry.
- `docs/agents/workflow.md` — how work reaches the relay and `main`.
- Wire surfaces: `crates/loot-net/src/lib.rs` (`relay_rejected`, the hint text),
  `crates/loot-identity/src/lib.rs` (`unwrap_envelope`, the allowlist check).
