# 41. GitHub for loot: a public, multi-tenant code forge on loot.millerbyte.com

## Status

accepted (forge map [#461](https://github.com/Connor-Miller/loot/issues/461),
terminal ticket [#471](https://github.com/Connor-Miller/loot/issues/471)). This
ADR locks the *architecture*; the buildable detail a later build map walks lives
in [`docs/specs/loot-forge.md`](../specs/loot-forge.md). No production code ships
from this decision — the map produced only throwaway prototypes (linked from its
tickets). Builds on ADR 0037 (the product site this replaces the shell of),
0034/0035/0036 (lanes/harbor), 0016/0027/0038 (grants, embargo, burn), 0040 (the
WASM SDK core), and millerbyte ADR 0006/0010 (TanStack Start SSG + `@millerbyte/ui`).

## Context

Today `loot.millerbyte.com` is a static release-shell that proxies GitHub for
downloads (ADR 0037). The destination is a **public, multi-tenant "GitHub for
loot"** — a place to visualize code, store repos, and grant permissions — with a
TanStack Start frontend, at multi-tenant scale.

loot is not git, and the forge must not flatten it onto git/GitHub abstractions.
Four differentiators have to survive as **first-class**, not decoration:

1. **Zero-knowledge encryption** — the server never sees plaintext of private content.
2. **Path-scoped grants / embargo** — a real grant/embargo/maroon/quarantine model, not repo-level ACLs.
3. **Lanes / harbor workflow** — the contribute story, not fork+PR.
4. **Content-addressed DAG history** — loot's change/DAG model, not a git commit graph.

The **keystone tension**, present in almost every ticket: zero-knowledge storage,
anonymous public read, and SEO/SSR are in direct conflict. A zero-knowledge server
*cannot* serve plaintext to an anonymous crawler; a forge that indexes nothing and
renders nothing server-side is not a forge. The map's job was to draw that boundary
precisely, then build everything else on the drawn line.

The map resolved ten tickets ([#462–#472](https://github.com/Connor-Miller/loot/issues/461));
this ADR is their synthesis. Prior art (#463) confirmed loot is **unique in
access-by-encryption** (Radicle = replication-allowlist, Perkeep = capability-URL,
Tangled/Forgejo = plaintext + ACL) — so the private model has no design to clone and
had to be invented; the two transferable patterns are Tangled's **App View** split
and Mononoke/Sapling's **lazy per-object fetch over an S3 blob store**.

## Decision

### The keystone: a first-class `Published` tier that deliberately breaks zero-knowledge, per path

Visibility is drawn along one honest axis — **can the untrusted server read these
bytes?** Exactly one tier answers yes:

- **Published** (`@world`) — the *only* tier the server, CDN, and anonymous readers
  may read in plaintext. Mechanism (#472): a standing `.lootattributes` **`published`**
  keyword reveals each object's key to a reserved **`@world`** grantee *in the clear*.
  `SealedObject` is unchanged — publish is a **grant**, not a second storage path — so
  it reuses the existing grant machinery and the demotion / mis-seal guard (ADR 0038).
  Per-path via globs (`**` = whole repo), auto-applies to future commits, and
  **unpublish is forward-only** (already-revealed bytes stay revealed — the UI must
  never pretend otherwise).
- **Internal** — plaintext readable by anyone with repo access, but **not** the
  anonymous world. (This is a rename of loot's current **Public** tier; see Vocabulary.)
- **Restricted** — readable only by named identities (key holders); zero-knowledge,
  decrypted client-side only.
- **Embargoed** — encrypted to all, key withheld until a reveal time (ADR 0027);
  zero-knowledge until reveal.

Everything except Published is zero-knowledge: the server holds ciphertext, checks
the grant-log to gate *reads*, and never decrypts (#462). This makes the tension a
**deliberate, per-path, guarded** disclosure rather than an architectural compromise.

### Vocabulary (this ADR's naming mandate, #471)

The forge's four tiers are **Published · Internal · Restricted · Embargoed**.
"Published" (world-plaintext) and the CLI's old "Public" (identity-readable
plaintext) are near-synonyms that mean different things, so **loot's `Public` tier is
renamed `Internal`** across `.lootattributes`, the engine, `CONTEXT.md`, and the UI;
`Published`/`@world` is the new world tier. **`Restricted` is kept** (not renamed to
"Private") — it already means named-key-holders throughout the codebase and the churn
buys nothing. The rename of `Public → Internal` is a real, tracked engine change the
build map must sequence.

### Identity: Clerk for accounts, seed-rooted keypairs for crypto (#465)

- **Clerk** owns account/session (reusing the millerbyte gateway) and custodies **no**
  key material.
- The **crypto identity is a seed-rooted loot keypair**: a 32-byte seed → WASM
  `Identity.fromSeed`. The seed is obtained via **passkey PRF** or a
  **passphrase-wrapped server blob** (the server stores ciphertext only).
- A profile maps a Clerk user → pubkey(s). Recovery is a **BIP39** phrase;
  **Clerk recovery ≠ key recovery**, and there is **no escrow** — private-content
  hard-loss is honest (Published content is unaffected). Rotation reuses loot's
  new-id + re-grant wave (ADR 0016). A new **username→pubkey directory** provides
  discovery (not trust).

### Rendering: one TanStack Start app, shell always SSR, content branches on visibility (#466)

A **single route tree**. The shell is *always* SSR. The content region branches in the
loader on the resolved visibility:

- **Published → SSR-on-demand + a content-addressed edge cache.** Immutable object
  addresses cache forever; only mutable tips revalidate (SWR). SSG stays for
  marketing/docs. The render tier runs the **SDK server-side** to decode/decrypt
  Published bytes.
- **Private (Internal/Restricted/Embargoed) → client-decrypt inside the SSR shell**, behind
  a `noindex` gate — never plaintext to the server, never to a crawler.
- Settings/permissions are always authed, client-only. **Auth-aware caching is a hard
  correctness rule** — a cache that serves one identity's decrypted view to another is
  a zero-knowledge breach.

### Storage: a two-tier store built for multi-tenant scale (#467)

Adopt the Mononoke shape:

- **Ciphertext blobs → S3/R2 object storage**, content-addressed, idempotent writes,
  CDN-frontable.
- **Mutable metadata → a transactional DB** (change graph/tips, refs, grant-log,
  published-keys, embargo schedule, tenant records, the username→pubkey directory).
- A **read/query API over the DB + lazy blob fetch** — this closes the gap #464 found:
  today's relay has a sync API and a grant mailbox but **no path/tree read-query API**
  (clients pull and decode everything client-side), which cannot back a forge.
- **Published** = decrypt-on-render + edge cache (single source of truth).
  **Private** = auth-gated ciphertext reads (server checks the grant-log, never
  decrypts) + client-decrypt. The relay scales **horizontally** — idempotent blob puts
  plus DB transactions replace the single-node harbor lock. Tenant isolation is
  key-prefix + `tenant_id`; **burn = tombstone + CDN purge** (ADR 0038); no cross-tenant
  dedup (random keys — honest).

### Permissions UX: grants are keys, not rows (#468)

The UI is built on loot's real verbs and per-path visibility — **no repo-ACL fiction.**
Because a grant is a **key** that has already left, the UI **never fakes
instant/complete revoke**: revoke is either forward-maroon or hard-rotate, and neither
retracts bytes already fetched. Six surfaces (per-path Access panel, Share-a-path with
**directory fingerprint-verify**, honest Revoke, Embargo scheduler, Publish/unpublish
behind the demotion-consent gate, Quarantine review as a human trust act).

### Contribution UX: anti-git lanes/harbor on the web (#469)

- **No branches.** A contribution is a **lane** hosting **one durable change id**.
- **The "PR" is a review *projection*** of unsigned/provisional WIP — not the merge
  target.
- **Land ≠ merge**: landing projects one *signed* commit, harbor-serialized; the
  GitHub-style auto-close is the *land signal*, not the mechanism.
- One **vs-harbor strip**: up-to-date · behind → **carry** (auto) · `!` divergent ·
  conflict → **bounce** (`loot resolve`).
- Public contributors go **cross-identity**: they propose a **signed** change,
  integrated post-finalize with provenance preserved.

### History & code visualization: render what git has no pixel for (#470)

Ship the **Change Ledger** view as default (change-as-unit + version stack) and fold in
the **Zero-Knowledge DAG** view's visibility banding; the Harbor & Lanes swimlanes view
is secondary (it serves the contribution story). Five truths are **never faked**:
change ≠ commit (change-id + author identity + per-path visibility); divergence shown
(one id, two live versions → `!`, never silently resolved); carry ≠ rebase; ferry = a
git *crossing*, not a merge (sealed paths never cross); sealed = honestly unreadable
server-side (client-decrypt only if key-holder).

## Considered alternatives

- **Store Published as plaintext objects (reuse the old `Public`/`Internal` tier) instead
  of a `@world` grant.** Rejected (#472): a second storage path forks content-addressing
  and bypasses the demotion guard. Modeling world-read as a grant keeps `SealedObject`
  uniform and one guarded publish path.
- **A separate read replica / GraphQL layer that decrypts private content server-side to
  index it.** Rejected: it *is* the zero-knowledge breach the whole map exists to avoid.
  Private is client-decrypt-only; server-side search is Published-only (Fog).
- **Repo-level Public/Private toggle (GitHub's model).** Rejected: it flattens loot's
  path-scoped grant/embargo model — the second differentiator — into an ACL.
- **Fork + PR contribution.** Rejected: it flattens lanes/harbor. The web contribution is
  a lane + a review projection, not a branch.
- **Escrow private keys for account recovery.** Rejected (#465): custody breaks
  zero-knowledge. Hard-loss of private content is honest; Published survives.
- **Keep the VPS relay as the forge backend unchanged.** Rejected (#464/#467): it is
  single-node, append-only, and has no read-query API — it cannot back a multi-tenant
  forge. The two-tier store supersedes it for the forge (the CLI relay stays for CLI sync).

## Consequences

- **Private collaboration is gated on SDK cross-session grant delivery
  ([#383](https://github.com/Connor-Miller/loot/issues/383)).** A browser can read
  Published content today, and an author can read *their own* private content, but a
  collaborator cannot read *another party's* private content until #383 lands. #383 is
  therefore a **hard build dependency** for the private-read + collaboration story
  (#465/#468/#469) — the build map must sequence it first, or ship a Published-only v1.
- **A real engine change: `Public → Internal` rename** (`.lootattributes` keyword,
  visibility enum, `CONTEXT.md`, tests) plus the `@world` reserved grantee and the
  `published` keyword (#472). These are the map's only mandated non-throwaway code.
- **A new storage tier stands up** (S3/R2 + a metadata DB + a read/query API) alongside
  the existing relay — a substantial build, deliberately deferred to the build map.
- **The forge inherits ADR 0037's manual `vercel --prod` deploy** and the
  `@millerbyte/ui` cross-repo edge until GitHub→Vercel auto-deploy is fixed.
- **Open fog the build map inherits** (see the spec's "Deferred" section): #383 grant
  delivery, orgs/teams over loot's flat identity, server-side search over Published,
  abuse/moderation for anonymous hosting, billing/quota, GitHub import, the social layer
  (issues/reviews/notifications), and CI/actions (likely out of scope).
