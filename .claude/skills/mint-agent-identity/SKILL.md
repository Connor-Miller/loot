---
name: mint-agent-identity
description: Run the once-per-identity ceremony that gives an AI agent its own loot identity (ADR 0026) — clone the relay into a keyring-separated dir, mint a keypair, register the pubkey as a peer, and add it to the relay allowlist. Triggers on "new agent identity", "mint agent", "set up agent clone".
---

# mint-agent-identity — the new-agent-identity ceremony

> ## ⚠️ HUMAN-IN-THE-LOOP — NOT AUTOPILOT
> This ceremony creates a **new trusted identity** on the relay and in this
> repo's peer registry. Two decisions are the human's alone: **trusting the new
> pubkey** (`loot peer add`) and **adding it to the relay allowlist**
> (`scripts/.setup.env`, an operator step). Do the clone + keypair yourself, then
> **stop and hand the pubkey and the two registration steps to the human** — you
> are here to run the mechanics and to make sure no step is forgotten, not to
> grant an agent write access on your own judgment.

## Purpose

An agent identity in loot **is a persistent clone directory plus its keypair**
(ADR 0026, `docs/agents/identity.md`). Identity is not per-session: ceremony
happens **once at minting**, and every later ephemeral session just starts in
the clone dir and inherits it (session ≠ identity). Keyring separation is
structural — a clone never receives restricted keys by construction, which is
why an agent is a *clone* and not a dock (every dock over one store shares that
store's identity and keyring, so a dock "is" the dev).

The ceremony is **rare but ceremony-heavy**, and every step is silent when
skipped. The one most often missed is the **relay allowlist** (step 4): without
it the clone mints, pulls, and looks healthy, then `loot push` is rejected by
the relay with nothing else obviously wrong. This skill exists to run all four
steps in order and to make that last one impossible to forget.

## Triggers

Invoke when the human says any of: "new agent identity", "mint agent", "mint an
agent", "set up an agent clone", "give the agent its own identity", or otherwise
asks to bring a new AI identity onto the relay.

## Type: HITL

The clone + `whoami` are mechanical and you run them. The **peer-trust** and
**relay-allowlist** steps are human/operator decisions — surface the pubkey and
stop there. Do **not** self-approve either.

## The binary

Use the repo's release build, **not** the `loot` on `PATH` (that copy is a stale
pre-fix engine): `C:\Users\conno\source\repos\loot\target\release\loot.exe`.
Build it first (`cargo build --release -p loot-cli`) if it is missing. Confirm
the verbs with `<binary> help` (look for `clone`, `whoami`, `peer add`). Below it
is written `loot` for brevity.

## The fast path (automation)

`tools/new-agent.ps1` already scripts **steps 1–3** and then prints the exact
allowlist line for step 4:

```powershell
./tools/new-agent.ps1 <name>            # e.g. crew
```

It clones the relay into a sibling `..\loot-crew\<name>`, pulls the new pubkey
out of `loot whoami`, runs `loot peer add <name> <pubkey>` in this repo, and
prints the two remaining operator steps (allowlist + `npm run setup:loot`). Use
this when it fits. The numbered steps below are the same ceremony done by hand —
run them when the script does not fit (custom parent dir, an existing relay, or
when you need to inspect each step), and read them regardless so you understand
what the script did and can finish step 4.

## Steps

### 1 — Clone the relay into a fresh, keyring-separated dir

```
loot clone https://relay.millerbyte.com <dir> --identity <name>
```

`clone` composes `init` (a **fresh** keypair for `<name>`) + `remote add origin`
+ `pull` + `surface`, so it ends with a materialized working tree. Requirements:

- `<dir>` must be a **new, empty** directory (relay URLs carry no project name;
  a non-empty dir is refused). Convention is a sibling `..\loot-<name>\<name>`,
  never inside this repo's tree and never a lane.
- `--identity <name>` names the new identity; omit it only if a global-config
  default identity is set. The keypair lands at `<dir>\.loot\id` (private, 0600)
  and `<dir>\.loot\id.pub`.

A fresh clone is a **relay** by default: it receives ciphertext and can read
only public or already-granted content; sealed paths (e.g. `docs/pitch/`,
restricted to the dev) are skipped at surface time. That is expected — grants
happen on demand later, never at bootstrap.

### 2 — Read the new identity's public key

Run **inside the clone dir**:

```
loot whoami --pubkey
```

`--pubkey` prints the **bare OpenSSH line only** (`ssh-ed25519 AAAA… name`),
paste-ready for both the peer-add (step 3) and the allowlist (step 4). Plain
`loot whoami` prints the same key with surrounding context if you want to
eyeball it. This pubkey is the globally-stable identity — the nickname is only a
local label — so it is what both registration steps key on.

### 3 — Register the pubkey as a peer (HITL — trust decision)

In the **existing repo(s)** the agent will exchange changes with (this dev repo,
and any other clone that must issue grants to or accept grants from the agent):

```
loot peer add <name> <pubkey>
```

This is loot's `known_hosts`: it binds the local nickname to the pubkey so
grants can be *issued* to the agent (sealed to the right key) and *accepted*
from it (a grant from an unregistered pubkey is quarantined, not applied). It is
a **trust decision** — the human confirms this pubkey really is the intended
agent, ideally verified out-of-band. Do not add a peer the human has not vouched
for. (`tools/new-agent.ps1` does this add for you in *this* repo; other repos
that need to trust the agent must run it too.)

### 4 — Add the pubkey to the RELAY ALLOWLIST (operator step — THE ONE PEOPLE FORGET)

> ## 🚨 EASIEST STEP TO MISS — CAUSES SILENT PUSH FAILURES
> This is **not a local `loot` command.** The relay enforces a server-side
> allowlist (ADR 0014 push envelope): it verifies each push's signature and
> checks the pubkey against `LOOT_ALLOW_PUBKEYS` before stowing. A clone whose
> key is missing here mints fine, pulls fine, and surfaces fine — then **every
> `loot push` is rejected by the relay** with no local symptom. When an agent
> "can pull but can't push," this is almost always the cause. Do this step every
> time and confirm it landed.

The allowlist is managed in the **`scripts` repo**, not in loot:

1. Append the agent's pubkey (from step 2) to `LOOT_ALLOW_PUBKEYS` in
   `scripts/.setup.env` — **comma-separated, keeping every existing key.**
2. Redeploy the relay so it picks up the new key, from the `scripts` repo in
   **PowerShell** (per the global rule that VPS/relay work goes through the
   idempotent scripts, never ad-hoc SSH):

   ```powershell
   npm run setup:loot
   ```

Both are **human/operator actions** — editing the secrets file and redeploying
the relay are outside loot and outside this repo. Hand the pubkey over and stop
here for the human to complete them; do not attempt to edit `scripts/.setup.env`
or run the deploy on the agent's behalf.

### 5 — Verify the clone can reach the relay

Only after step 4 has actually been applied (allowlist edited **and**
`npm run setup:loot` run), from **inside the clone dir**:

```
loot push
```

A push that the relay **accepts** is the proof the whole ceremony worked — it
exercises the keypair (signature), the remote (`origin` from clone), and the
allowlist all at once. If it is **rejected**, the allowlist step (4) has not
taken effect: re-check that the exact pubkey is in `LOOT_ALLOW_PUBKEYS` and that
`npm run setup:loot` was rerun. Do not debug this as a loot bug first — it is the
allowlist until proven otherwise.

## Do / Don't

- **Do** run the clone + `whoami --pubkey` yourself, then hand the pubkey and the
  two registration steps to the human.
- **Do** treat the **relay allowlist** as a required, easy-to-miss step and
  verify it with a real `loot push` (step 5).
- **Do** use `tools/new-agent.ps1` when it fits — it covers steps 1–3 and prints
  the step-4 line.
- **Don't** self-approve `loot peer add` (a trust decision) or edit
  `scripts/.setup.env` / run the relay deploy (operator steps).
- **Don't** clone into this repo's tree or a lane — the clone is its own
  standalone identity dir (convention: sibling `..\loot-<name>\<name>`).
- **Don't** expect bootstrap grants — public content arrives with the clone;
  restricted keys are granted on demand (`loot grant`) later, never at minting.
- **Don't** confuse minting with a session: mint once; later sessions just start
  in the clone dir and inherit the identity.
