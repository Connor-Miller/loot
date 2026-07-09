# Relay on the VPS: transport decision + idempotent deploy
GitHub: #57

Type: grilling
Status: resolved
Blocked by: —

## Question

Two halves, one session. (1) **Decide** how `loot serve` (plain HTTP, open relay) is safely exposed for daily push/pull from the dev machine: native TLS (#8), reverse proxy (Caddy/nginx, matches existing VPS patterns), or SSH tunnel — plus whether the ADR 0014 push-envelope allowlist is enabled. (2) **Do it**: an idempotent setup script in the `scripts` repo (PowerShell entry point, setup-bots/setup-millerbyte pattern) that provisions the relay and survives re-runs. Resolution records the chosen transport and the script name.

## Answer

**Transport:** nginx reverse proxy + Let's Encrypt TLS + ufw — matching `setup-millerbyte`/`setup-acuity`. `loot serve` stays plain HTTP on `127.0.0.1:4000`; only nginx is public and terminates TLS. Rejected native TLS (#8) — it duplicates what certbot already solves on this VPS — and the SSH tunnel — an always-on relay is what ephemeral agents push/pull against.

**Push allowlist:** enabled (ADR 0014 push-envelope). The relay accepts stows only from `LOOT_ALLOW_PUBKEYS` (dev's `loot whoami` key now; agent keys added once **Agent identity model** lands). The relay stays zero-knowledge either way; this just gates *write* access on a public endpoint.

**Script:** `scripts/setup-loot.js` (committed `281baa3`), PowerShell-run per the repo convention, idempotent (re-run = fetch + rebuild + restart). Provisions: a VPS→GitHub read-only deploy key on the loot repo, rustup + build-essential, a `cargo build --release` of the `loot` binary → `/usr/local/bin`, a hardened `loot-relay` systemd service (`ProtectSystem=strict`, allowlist wired in), and — with `SETUP_EDGE=true` — the nginx + certbot + ufw edge with a 512m body limit for large sync bundles.

**Remaining (execution, not a wayfinder ticket):** the dev runs `node setup-loot.js --SETUP_EDGE=true …` from PowerShell after adding a DNS A record for the relay host and putting the dev pubkey in `LOOT_ALLOW_PUBKEYS`. The **Milestone evidence checklist** will confirm the relay is live end-to-end.
