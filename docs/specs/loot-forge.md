# Spec: GitHub for loot — the public multi-tenant forge on loot.millerbyte.com

**Status:** hand-off-ready. Single source of truth for the *build map* that turns
`loot.millerbyte.com` from a release-shell (ADR 0037) into a public multi-tenant
forge. Assembled by the terminal ticket of map
[GitHub for loot (#461)](https://github.com/Connor-Miller/loot/issues/461); every
decision below is already resolved on a closed ticket — this document **collects**
them, it does not re-open them. Backed by
[ADR 0041](../adr/0041-public-multi-tenant-loot-forge.md). Each section cites the
ticket that owns its detail.

## 0. What we are building

A **public, multi-tenant "GitHub for loot"**: visualize code, store repos, grant
permissions — a TanStack Start frontend over a re-architected, horizontally-scalable
store, preserving loot's four differentiators as first-class:
zero-knowledge encryption, path-scoped grants/embargo, lanes/harbor, content-addressed
DAG history. No code from the *chart* map is production except the two engine changes
in §2; everything here is for the **build** map to implement.

## 1. Visibility model — the keystone (#462, #472, #471)

Four tiers on one axis (**can the untrusted server read the plaintext?**):

| Tier | Server reads plaintext? | Who reads | Mechanism |
|------|-------------------------|-----------|-----------|
| **Published** | **Yes** | anon / world / CDN / crawlers | key revealed to reserved `@world` grantee in the clear |
| **Internal** | No (plaintext, but access-gated) | anyone with repo access | plaintext object, not sealed (renamed from `Public`) |
| **Restricted** | No | named key-holders | zero-knowledge, client-decrypt |
| **Embargoed** | No (until reveal) | all, after `reveal_at` | timed sealed grant (ADR 0027) |

**Publish is a grant, not a storage path.** `SealedObject` is unchanged. A standing
`.lootattributes` **`published`** keyword reveals each matched object's key to `@world`.
Per-path globs (`**` = whole repo), auto-applies to future commits, reuses the
demotion / mis-seal guard (ADR 0038). **Unpublish is forward-only** — the UI must never
imply already-revealed bytes can be un-revealed.

## 2. Engine changes (the only mandated non-throwaway code) (#472, #471)

These are real, small, and land in the loot engine ahead of / alongside the forge:

1. **Rename `Public → Internal`** — the `.lootattributes` keyword, the `Visibility`
   enum, `CONTEXT.md`'s glossary, and all tests. Pure rename; no behavior change.
2. **The `published` keyword + `@world` reserved grantee** — a new standing attribute
   that issues an in-the-clear grant to `@world` on match, gated by the existing
   demotion guard; unpublish removes the standing attribute (forward-only).

A build-map ticket should sequence (1) before (2) to keep the enum change isolated.

## 3. Storage & scale — the two-tier store (#467, #464, #463)

The current relay is single-node, append-only, and has **no path/tree read-query API**
(#464) — it cannot back a forge. Stand up a two-tier store (Mononoke shape, #463):

- **Blob tier — S3/R2 object storage.** Ciphertext blobs, content-addressed, idempotent
  writes, CDN-frontable. Lazy per-object fetch (Sapling/Mononoke pattern).
- **Metadata tier — a transactional DB.** Change graph & tips, refs, the **grant-log**,
  **published-keys**, embargo schedule, tenant records, and the **username→pubkey
  directory**.
- **Read/query API over DB + lazy blob fetch** — the missing read path (#464). Serves
  trees/paths/history without a full client-side pull.
- **Reads by tier:** Published = decrypt-on-render + edge cache (single source of truth);
  Private = auth-gated ciphertext read (server checks grant-log, **never decrypts**) +
  client-decrypt.
- **Scale:** horizontal — idempotent blob puts + DB transactions replace the single-node
  harbor lock. Tenant isolation = key-prefix + `tenant_id`. **Burn = tombstone + CDN
  purge** (ADR 0038). No cross-tenant dedup (random keys — honest).

The existing CLI relay stays for CLI sync; the forge store is a new backend, not a
mutation of the relay.

## 4. Identity & onboarding (#465)

- **Clerk** = account/session (reuse the millerbyte gateway); custodies **no** key
  material.
- **Crypto identity = seed-rooted keypair**: 32-byte seed → WASM `Identity.fromSeed`.
  Seed via **passkey PRF** or a **passphrase-wrapped server blob** (server stores
  ciphertext only).
- Profile maps Clerk user → pubkey(s). Recovery = **BIP39**; **Clerk recovery ≠ key
  recovery**; **no escrow**. Rotation = loot new-id + re-grant wave (ADR 0016).
- New **username→pubkey directory** (discovery, not trust) — lives in the metadata DB.

## 5. Rendering (#466)

One TanStack Start app, single route tree, shell **always SSR**; the content region
branches in the loader on resolved visibility:

- **Published** → SSR-on-demand + **content-addressed edge cache** (immutable addrs
  cache forever; only mutable tips revalidate/SWR). SSG stays for marketing/docs. The
  render tier runs the **SDK server-side** to decode/decrypt Published bytes.
- **Private** → **client-decrypt inside the SSR shell**, `noindex` gate; never plaintext
  server-side or to a crawler.
- Settings/permissions → authed, client-only.
- **Hard rule:** auth-aware caching — never serve one identity's decrypted view to
  another.

## 6. Permissions & sharing UX (#468)

Prototype: [wireframes gist](https://gist.github.com/Connor-Miller/aece00aa2ac62919fa4d03bae778e833).
Principle: **grants are keys, not rows** — the UI never fakes instant/complete revoke.
Six surfaces, all on loot's real verbs + per-path visibility (no repo-ACL fiction):
per-path **Access panel**; **Share-a-path** (grant key + directory **fingerprint-verify**);
honest **Revoke** (forward-maroon vs hard-rotate — neither retracts fetched bytes);
**Embargo scheduler**; **Publish/unpublish** (demotion-consent gate + the standing
`published` attribute); **Quarantine review** (a human trust act).

## 7. Contribution workflow (#469)

Prototype: [wireframes gist](https://gist.github.com/Connor-Miller/9d00341c2d3f81e2dd1596f6b05cda94).
Anti-git: **no branches** — a contribution is a **lane** hosting **one durable change
id**. The **"PR" is a review *projection*** of unsigned/provisional WIP, not the merge
target. **Land ≠ merge**: projects one *signed* commit, harbor-serialized; GitHub-style
auto-close is the land *signal*. One **vs-harbor strip**: up-to-date · behind → **carry**
(auto) · `!` divergent · conflict → **bounce** (`loot resolve`). Public contributors go
**cross-identity**: a **signed** change integrated post-finalize, provenance preserved.

## 8. History & code visualization (#470)

Prototype: [3-view gist](https://gist.github.com/Connor-Miller/fc5631a05ec701e0507ca1d1c21b2238).
Ship the **Change Ledger** (view B) as default (change-as-unit + version stack) and fold
in the **Zero-Knowledge DAG** (view C) visibility banding; **Harbor & Lanes** swimlanes
(view A) is secondary (serves §7). The code panel is variant-independent and honest about
the server-unreadable. **Five truths never faked:** change ≠ commit; divergence shown
(`!`); carry ≠ rebase; ferry = a git crossing, not a merge; sealed = honestly unreadable
server-side.

## 9. Build sequencing (for the build map to slice)

A suggested order — the build map owns the real slicing:

1. **Engine (§2):** `Public → Internal` rename, then `published`/`@world`. Small, unblocks
   vocabulary everywhere.
2. **Store (§3):** blob tier + metadata DB + read/query API. The heavy lift; everything
   web-facing sits on it.
3. **Published read path (§5):** SSR-on-demand + edge cache over the store — the
   anonymous forge, no auth needed. **A shippable Published-only v1.**
4. **Identity (§4):** Clerk + seed-rooted keypair + directory — enables authored writes and
   own-private read.
5. **Private read + collaboration (§6/§7):** **blocked on #383** (see Deferred). Until #383,
   only own-private reads work; collaborator-private and the full contribution loop wait.
6. **Visualization (§8):** the Ledger/DAG/Swimlanes views over the store's history API.

## 10. Deferred (fog the build map inherits)

- **SDK cross-session grant delivery ([#383](https://github.com/Connor-Miller/loot/issues/383))
  — the hard dependency.** A private key is held only by its author; a browser cannot yet
  receive another party's private-content key. Blocks all collaborator-private read (§6/§7).
  Sequence it first, or ship Published-only (step 3) and land private later.
- **Server-side search & indexing** — Published only (server-plaintext at render, indexable
  over the metadata DB + decrypted text); Private is client-side-only or unsupported.
- **Orgs / teams** over loot's flat identity model.
- **Abuse / moderation / content policy** for anonymous public hosting.
- **Billing / quota enforcement** for multi-tenant storage.
- **GitHub import / migration** path.
- **Social layer** — issues, review comments, notifications on the web.
- **CI / actions** equivalent — likely out of scope entirely.
