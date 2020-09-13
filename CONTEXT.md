# Context: loot

A from-scratch source-control system. Working thesis: **visibility and
permissions are properties of content and changes, not of the repository.**
This is the one git complaint from the source material that nobody has solved;
it is loot's reason to exist.

## Glossary

**loot** — the project / the CLI binary.

**Change** — the reviewable, permission-bearing unit of history (loot's answer
to a git commit). A Change carries a set of paths, each with its own
visibility. Permissions attach here, not to the repo.

**Working change** — the always-present change at the tip that the working tree
*is* (JJ-style, ADR 0006). There is no separate "commit" step: `describe` names
the working change and `new` finalizes it and starts a fresh one on top. Under
implicit auto-snapshot (ADR 0030, #144) every **mutating** verb (`new`,
`describe`, `grant`, `maroon`, `migrate`) captures the tree first, so edits are
never lost between commands and no manual `loot status` is needed; read-only
verbs never snapshot. (`status` still snapshots today — turning it read-only is
S2 #145.) This kills git's add/commit ceremony.

**Snapshot (reconcile)** — turning the current working tree into the working
change, *visibility-aware* (ADR 0006). Against the last change's full tree, at
time `now`: paths the current identity can open are updated/deleted to match the
tree; paths it cannot open are carried forward unchanged (never seen, so never
changed); a write onto a non-visible path is refused (no silent clobber of
sealed content). A path whose plaintext and visibility are unchanged **keeps
its sealed object and address** (#98) — snapshots and pushes are O(delta), not
O(repo). Reuse never mints or moves a key (the object and its key are already
held), so ADR 0004's no-plaintext-dedup stance is untouched; a path the
identity cannot open *now* (e.g. still-embargoed) re-seals fresh. Lives in the
engine (`DagRepo::snapshot`); the Workspace only supplies the tree.

**Workspace** — the CLI module owning the *process-bound ambient repo*: it
discovers `.loot/`, supplies the current identity and the clock, and persists on
mutation. Commands are thin verbs over it; the snapshot invariant and clock
injection live here. See ADR 0006.

**Operation log & undo** *(S4, ADR 0031, #146)* — the safety net under implicit
auto-snapshot. Every **view-changing** command (the mutating verbs above,
`dock`/`dock merge`, `resolve`, `apply`/`pull`/`ferry`, and the barriers below)
records one **operation** in an append-only, repo-wide, **local-only** log at
`.loot/ops`. An operation captures the resulting **view** — the change-graph
heads, each dock's `working`/`tip` pointers, the `conflicts` set, and the
ambient-dock pointer — as raw pointer-file bytes, so restore is a pure pointer
reset that never touches the object store or the append-only graph. `loot undo`
steps the view back one operation, `loot op restore <n>` jumps to any operation
(redo included), `loot op log` lists them; read-only verbs record nothing.
Restoring is itself a *new* operation, so the log grows on undo (redo always has
a landing spot) and **no change is ever deleted** — a signed change survives,
undo just moves the head off it. **Barriers** it will not cross: `push` (a
disclosure to a relay) and the restricted-key ops `grant`/`maroon`/`pull-grants`
are recorded as non-undoable; undo refuses at one and names the real remedy
(reverse it forward), because the keyring/manifest are one-way state a *view*
reset cannot retract. Like the git mark map it is per-machine, never bundled,
and rebuildable-from-nothing (losing it loses undo history, not repo data).
NB: loot has no standalone auto-snapshot op — S2 made `status` read-only, so
every capture rides a mutating verb; that verb *is* the one op (jj's separate
"snapshot" op has no loot analogue).

**Divergent change** *(S3, ADR 0029/0030, #147)* — one durable **change id**
carrying **more than one live version id**: two writers independently rewriting
the same change id (the honest answer to a concurrent amend, not an error). It is
per-change-id, *not* head-counting — two versions of one change id can sit under
a single graph head (e.g. as the two parents of a merge) and may even have
identical trees — so it is detected by scanning every node, never just the heads,
and it is **not** a tree conflict (`resolve`/`dock merge` are untouched). `log`
and `status` render it with a trailing **`!`** on the change id and list each
version; a log whose only multi-head reason is one divergent change stays the
flat listing (routing by *distinct change lines*, not head count, so the "run
`loot apply` to converge" branch never mis-claims a divergence apply can't
collapse). **`loot abandon <version-id>`** (jj-parity `jj abandon`) drops a
version, leaving the other live version(s) under the change id: the node is never
deleted — it stops being a live head and joins a **local-only `.loot/abandoned`**
set the live view filters out. Abandon is one **undoable** operation ([[Operation
log & undo]] captures both the heads and the abandoned set), and it refuses a
non-divergent change so it can never hide a change's sole version. Genuine
tree-*merge* of two versions stays the existing converge path (a different
intent — it produces a new version).

**Liveness** *(decided 2026-07-12, map #215)* — the one home for the rule the
`!` marker renders: **live = in-graph ∧ ¬abandoned ∧ ¬superseded**, plus
"divergent co-versions stay flat" and "a [[Parked working change]] is not a
mergeable line." A loot-core view built per operation from the change graph,
the local abandoned set, and the parked dock pointers; it computes the
superseded scan once and answers `is_live` / `live_of(cid)` / `divergent` /
`superseded`, and owns the [[Head partition]]. Every consumer (converge, ingest
classification, log/status rendering, abandon/edit guards, version resolution)
crosses this one seam — the rule is never re-derived at a call site. (Being
built as #216; the per-line `supersedes` ancestry check stays a separate
DagRepo predicate.)

**Head partition** *(decided 2026-07-12, map #215)* — [[Liveness]]'s answer to
"given these graph heads, what may converge do": `{ ours, stale, flat, fold }`.
`ours` is the line the dock actually materialized (never a parked head — the
#203 footgun made unrepresentable), `stale` are superseded heads to drop
without merging (ADR 0032), `flat` are divergent co-versions and parked working
changes that stay live heads and are never content-merged (#198/#203), `fold`
are the genuinely independent concurrent lines converge merges. Converge is an
executor of the partition, not an owner of the rule.

**Parked working change** *(named 2026-07-12; behavior from #171/#203)* — a
[[Dock]]'s in-progress, unsigned [[Working change]] left behind when the
operator switched away: still that dock's working pointer, still a live head in
the shared graph, resumed in place by the dock's next snapshot. It is in-flight
WIP, not a line: converge never folds it (#203), projection never ships it
(unsigned never travels, ADR 0018), and `loot dock rm` drops it with its dock
(#212). _Avoid_: stray head, orphan WIP.

**Dock** *(CA1 shipped, 2026-07-06)* — an isolated working tree plus its own
[[Working change]] tip, materialized cheaply over the *shared* `.loot/` object
store and change graph. loot's answer to a git worktree, and the isolation unit
for concurrent agents: each agent (or human) *docks* into the repo to get its
own tree and tip without a second clone or any re-fetch of ciphertext. Docks
fork the DAG exactly as concurrent pushes already do (engine.rs, ADR 0011), so
reconciliation reuses the existing converge path — a dock is a local fork
instead of a remote one. CLI: `loot dock <name>` (create-or-switch), `loot
docks` (list). The default dock is `home`, whose process files are the root
`.loot/working`/`tip`/`tree-hash`, so a repo that never docks is unchanged on
disk; named docks live under `.loot/docks/<name>/`. CA1 is the *checkout* model
— one physical working tree a switch re-materializes (auto-snapshotting the
outgoing dock first, so nothing uncommitted is lost); per-dock *physical*
directories for truly simultaneous editing are a later, additive step (the
on-disk format is already dock-agnostic). _Avoid_: worktree, checkout, berth,
slip.

**Buoy** *(CA4 shipped, 2026-07-09)* — a change that
carries a navigational-role [[Attestation]] (e.g. `reviewed`, `base`), used as a
fixed landmark to build from. Not a new primitive: `attest` stays the only
write-verb, and a buoy is the *derived, read-side* concept — "the newest change
attested with role X by a trusted peer." Because attestations are append-only
and signed (ADR 0018), each buoy pins one change immutably and the "current"
buoy is computed, never a mutable ref — so it carries none of the
concurrent-writer race a git tag or branch pointer would. A moored fixed marker,
in contrast to the moving [[Dock]]. _Avoid_: tag, bookmark, branch.

**Harbor** *(CA2 shipped, 2026-07-07)* — the conventional
integrator [[Dock]] that agents converge into and re-base from: a dock with a
well-known name and *no* permissions attached, so it is a coordination
convention, not a gated branch (branches stay a permanent non-goal). Merging is
direct and local — `loot dock merge <name>` applies one dock's tip onto
another's working change in-process, reusing the `apply`/converge path with no
relay hop, because docks share one object store. The relay remains the path for
*remote* agents only. _Avoid_: main, master, trunk.

**Verdict** *(CA3 shipped, 2026-07-07)* — the machine-readable form of a
reconciliation outcome. The [[Convergence classifier]] already computes a
per-path merge outcome; the reconciliation verbs (`apply`, `conflicts`, `status`,
`dock merge`, `pull`, and `ferry`) now emit it as data instead of prose. Default
machine format is **porcelain**: one path per line, a leading status char (`=`
converged, `M` merged, `C` conflict, `R` relayed), tab-separated columns
`status<TAB>path<TAB>base<TAB>incoming`; `--json` is the opt-in fallback for
paths whose bytes (tab/newline) would corrupt columns. Default (no flag) output
is unchanged human text. Scope note (CA3): `base`/`incoming` content addresses
are populated only for a `C` row (the outcome's `ours`/`theirs`); other rows
carry `-`. Widening them to every row means threading both trees through
`apply` and is, per ADR 0023, a *breaking* contract change. `status` is not a
merge, so it has its own shape — `~<TAB>path<TAB>visibility`. The column order
and status chars are a **frozen contract** once agents parse them, versioned
with the format gate (`format::FORMAT_MAJOR`, ADR 0019). CLI: `loot apply --porcelain`,
`loot conflicts --json`, etc. (ADR 0023). _Avoid_: adding machine output to the
~25 non-reconciliation verbs — deliberately out of scope.

**Ferry** *(GB1 shipped, 2026-07-10)* — one deliberate bidirectional loot ↔ git
mirror pass (ADR 0028): ingest git-native commits from the mirrored `main` as
loot changes (sealed at ingest under the *commit's own* `.lootattributes`),
reconcile them into the ambient [[Dock]] with the [[Convergence classifier]]
(loot is the merge authority — git never merges), then project every
travel-worthy change as a git commit carrying `Loot-Change-Id`/`Loot-Author`/
`Loot-Signature` trailers, SSHSIG-signed with the repo key, deterministic dates
(`BASE_EPOCH + generation`). Sealed paths are omitted from git entirely (no
filename, no bytes), so the mirror holds the syncing identity's readable tree —
the git remote must be trusted as much as that identity (**not** a public
host). Every head stays reachable under `refs/loot/heads/*`; `refs/heads/main`
tracks a designated dock. The spine is the mark map (sha ↔ change-id ↔ origin)
in `.loot/git-mirror/`, local-only and rebuildable from trailers. CLI: `loot
ferry [--git-dir <path>] [--dock <name>]`. _Avoid_: sync, mirror-push — a ferry
carries in both directions in one crossing.

**Attestation** — a detachable, signed, advisory marker over a change id:
`sign(change_id || attester || role)` (ADR 0018 / S4). Verified drop-not-fatal
on `apply`/`stow`, never folded into the change id, never affects convergence.
Stored in `.loot/attestations` and carried in the sync bundle. The mechanism
underneath co-author/reviewer sign-offs and [[Buoy]] landmarks. CLI: `loot
attest <change> [role]`.

**Visibility** — the access policy on a unit of content. One of:

- *Public* — readable by anyone who can read the repo.
- *Restricted* — readable only by named identities (key holders).
- *Embargoed* — encrypted to all; key withheld until a reveal time. Models
  embargoed security fixes and delayed-reveal merges.

**Identity** — a keyholder. Visibility is ultimately enforced by who holds the
decryption key for a unit of content. "Permissioning is key management."

**Agent identity** *(decided 2026-07-09, ADR 0026)* — an AI agent exists as a
loot identity via a **persistent clone**: its own repo directory + keypair +
keyring, cloned from the relay, synced by `push`/`pull`. Ceremony happens once
at minting (clone, `peer add`, relay allowlist line); an ephemeral session just
starts in the clone directory — session ≠ identity. One agent identity to
start, minted freely when more are needed. Bootstrap grants: none — public
content arrives with the clone; restricted keys are withheld by construction,
and on-demand grant/maroon is the milestone's audit-trail evidence. The
genuinely-sealed-from-agents path is `docs/pitch/` (restricted to the dev).
[[Dock]]s/[[Harbor]] stay the *same-identity* parallelism tool; a per-dock
identity/keyring split (store as "a relay on your own disk") is a recorded
post-milestone enhancement, not the current model.

**Sealed content** — the module that owns loot's thesis: encryption, visibility,
and embargo behind two operations. `seal(bytes, visibility)` produces a
*Sealed object* plus a freshly-minted content key; `open(sealed, reader, now)`
is the single authorization chokepoint — it enforces embargo (by `now`), then
visibility, then decrypts. Nothing else in the system decides who may read
content. See ADR 0003.

**Escrow** — the lifecycle stage between `seal` and `Keyring` for embargoed
content (ADR 0007). When a `seal` produces an `Embargoed` key, that key goes
into the Escrow — not the Keyring — for every identity including the originator.
`flush_escrow(now)` promotes eligible entries into the Keyring once
`now >= reveal_at`; until then the Keyring holds nothing for that object and
`open` returns `Embargoed`. The Workspace calls `flush_escrow` before every
content-reading operation (`checkout`, `snapshot`). As of format v5 (ADR 0027,
#14) bundles ship **no** escrow section — that lane shipped plaintext keys,
the exact bypass hard embargo closes. The Escrow is originator-side staging
only; peers receive embargoed keys solely from the relay after `reveal_at`,
as timed SealedGrants filed via `apply_sealed_grant` (which itself stages a
not-yet-due grant in Escrow rather than the Keyring, as defense-in-depth
against an early-releasing relay).

**Threat model.** Hard embargo's engine/wire slice is **implemented** (ADR
0027, #14, format v5): embargoed keys have **no bundle lane at all** — the
v1–v4 plaintext escrow section is gone (a v5 reader parses an old section for
cursor correctness and DROPS its keys), and they travel only as **timed
SealedGrants** — ECIES-wrapped per recipient, withheld from the relay's grant
mailbox until the *relay's* clock passes `reveal_at` (the relay never takes a
caller clock; `reveal_at` rides inside the grantor-signed envelope, so it
cannot be altered without breaking the signature). A non-originator holder is
adversary-proof-ed by **absence**: the key bytes are not on their machine —
no lying clock, escrow inspection, or modified binary can read what never
arrived. The claim is **holder**-adversary-proof: residual trust is the relay
operator releasing on time — a distinct role holding only wrapped blobs it
cannot read (drand timelock is the recorded post-milestone hardening). The
*originator's* own local Escrow staging (ADR 0007) remains cooperative/
honest-clock — moot, since the originator already knows the plaintext they
sealed. The CLI surface (#88) is implemented: `loot push` runs a deposit pass
after stowing bundles — one timed SealedGrant per registered peer for every
embargoed path this repo holds the key for, deduped against the Manifest (a
recorded oid→peer grant is never re-deposited, which also makes an interrupted
deposit loop resumable); `loot grant --relay` on an embargoed path inherits the
seal's `reveal_at` (a late-added recipient gets a timed grant, never an early
key); receipt is plain `loot pull-grants` — no new verbs. The attack demo
(#89) is the scripted proof: `docs/evidence/scripts/attack-demo.ps1` runs an
adversarial holder against the live relay — an advanced `LOOT_CLOCK`, direct
`.loot` inspection, and a patched binary (`loot-core` example `patched-client`,
every client time gate removed) all **fail** to read before `reveal_at`, then
the read succeeds after the relay releases; output committed at
`docs/evidence/runs/attack-demo.txt`. With no relay configured, ciphertext
syncs and embargoed keys simply never reach peers — one `Embargoed` label, one
guarantee.

**Sealed object** — ciphertext + nonce + visibility + the *grant ids* (the
identities permitted to hold a key). It deliberately does **not** contain any
content key, so storing or syncing a Sealed object can never leak a key.

**Keyring** — an identity's private custody of content keys (`oid -> key`), held
separately from Sealed objects. `open` reads from the keyring; a relay simply
has no keyring entry and therefore cannot decrypt. Keys live here and only here.

**`.loot/`** — a repo's on-disk state (ADR 0005): `identity` (the ambient
keyholder), `repo` (sealed objects + change graph), and `keyring` (this
identity's keys, LOCAL-ONLY — never bundled). Written/read by the engine's
`save`/`load`; the CLI is process-per-command and round-trips through it.

**RepoStore** — the single source of truth for the `.loot/` layout: where every
artifact lives under the directory, plus the small process-file encodings
(`working`, `tree-hash`). Path construction for `identity`, `graph`, `keyring`,
`escrow`, `manifest`, `purges`, `conflicts`, `working`, `tree-hash`, `config`,
`objects/`, and the keypair/peers files lives in one place (`loot_core::store`,
ADR 0017) rather than as string literals scattered across the engine, the
Workspace, and loot-identity. It owns *layout, not policy* — which identity, when
to snapshot, and what a change means stay with the engine and the Workspace;
RepoStore is only the filesystem adapter between logical artifacts and paths. The
`objects/` subdirectory is still written by `persist_codec` (ADR 0012) and the
keypair/`peers` files by loot-identity (ADR 0014); RepoStore names their paths so
the layout has one documented home.

**`.lootattributes`** — a gitattributes-style file mapping path globs to
visibility (`.env restricted=alice`, `*.md public`). The Workspace reads it on
snapshot to seal each path; unmatched paths default to Public. This is the
user-facing surface of the thesis — where you declare a file private. Two
safeguards (#62, 2026-07-09): the file is **versioned** like any other path
(policy travels to peers and clones — a fresh keyholder clone without the
rules would otherwise re-seal restricted content Public), and a snapshot that
would **demote** a path's visibility (Restricted/Embargoed → wider than the
tree already records) **refuses** (a typed `RepoError::Demotion`) unless that
path is passed via the global **`--allow-demote <path>`**. Under implicit
auto-snapshot (ADR 0030, #144) the guard rides every mutating verb's capture,
so `--allow-demote` is a global on any snapshotting verb (`new`, `describe`,
`grant`, `maroon`, `migrate`, `status`), not a `status`-only flag. Widening a
Restricted identity set is not guarded — `grant`/`maroon` own that audit trail.

**`.lootignore`** *(#64, 2026-07-09)* — a gitignore-style file excluding paths
from [[Snapshot (reconcile)]]: one glob per line, `#` comments, the **same
dialect as `.lootattributes`** (full relative path; `*` stops at `/`, `**`
crosses it) — deliberately *not* full gitignore semantics (no negation, no
implicit any-depth matching; use `**/target/` for that). A trailing `/`
ignores the whole subtree (`target/` ≡ `target/**`) and the walk **prunes**
there — ignored build output is never even read. An ignored path simply isn't
part of the tree the engine reconciles, so ignoring an already-snapshotted
readable path drops it from the working change on the next `status` — the
remedy for the pilot's 38 MB `target/` mis-seal. The policy files themselves
(`.lootattributes`, `.lootignore`) are never ignorable and stay versioned
(#62's rationale: policy travels).

**loot (the CLI)** — the first product crate (`loot-cli`, binary `loot`):
`init`, `status`, `describe`, `new`, `checkout`, `log`, `bundle`, `apply`. Thin
verbs over the [[Workspace]]; the JJ-style working change replaces git's
add/commit ceremony. Demonstrated end-to-end: a sealed `.env` checks out for its
keyholder and is silently skipped for anyone else, from the same repo and change
— and a non-keyholder's re-snapshot carries it forward rather than deleting it.

**Sync (`bundle`/`apply`)** — one-way transport via a bundle file (ADR 0001
realized in the CLI). `loot bundle <file>` writes ciphertext plus *only* the
keys for `ANYONE`-granted content (restricted keys never travel). `loot apply
<file>` merges idempotently and prints each path's outcome: *converged* (new or
identical), *merged*, *conflict*, or *relayed* — the last being the novel role,
where a non-keyholder carries ciphertext it cannot read. Demonstrated: Bob
applies Alice's bundle and stores her sealed `.env` as ciphertext he can't
decrypt.

**Frame** — the typed, tag-resolved form of a bundle on the wire, and the single
value the engine matches on. There are three: *Sync* (tag 0, carries purge
events + the change/object/key body — the plaintext escrow section is gone as
of v5, ADR 0027), *Grant* (tag 1, a targeted key
handoff whose key rides in the body), and *SealedGrant* (tag 3, the content key
ECIES-wrapped to a recipient pubkey, carried beside the body with a `reveal_at`
— `0` untimed; nonzero makes it a relay-withheld timed grant). All wire framing
— the tag byte, the Sync purge prefix, the Grant grantee prefix, the SealedGrant
`[pubkey·wrapped·oid·reveal_at]` header, and every length/offset — lives behind
`bundle_codec::Frame::{decode, encode}`; the engine does no byte arithmetic. Both
`apply` (keyholder merge) and `stow` (relay ingest) decode to a `Frame` and match;
`stow` accepts only *Sync*. A `SealedGrant`'s wrapped key is surfaced verbatim and
never unwrapped inside the engine — unsealing is the caller's injected closure
(ADR 0014/0015). The low-level body codec (`encode`/`decode`) is the module's
private plumbing beneath the `Frame` seam.

**Object** — a content-addressed unit of stored bytes. In the encrypted-DAG
model, objects are encrypted independently (see *Sealed object*) and addressed
**solely** by the hash of their *ciphertext*. There is no plaintext-derived
identity; equal plaintext sealed under different keys is stored separately.

**Content address** — `blake3(nonce || ciphertext)`. The only identity an object
has. Two objects share an address only if their ciphertext is byte-identical,
which reveals nothing a relay didn't already hold — so address-equality dedup is
safe. Plaintext-equality dedup was removed because it leaked an equality oracle
to relays (ADR 0004).

**Sync** — bringing two repos into agreement. Now an *evaluation axis* of the
bake-off, not a deferred concern. The semantics under test: two machines edit
concurrently while offline, then reconcile and must **converge**.

**Convergence unit** — the granularity at which concurrent edits reconcile:
**per-content, decrypt-then-merge**. Peers who both hold the key for a unit of
content perform a fine-grained merge of it; a peer who lacks the key cannot
merge that content and may only **relay** its ciphertext. This splits peers
into two roles *per path*: *merger* (keyholder) and *relay* (non-keyholder).
See ADR 0001.

**Convergence classifier** — the module that decides, per path, what happens
when an incoming change meets the local tree: *Converged* (disjoint or
identical), *Merged*, *Conflict*, or *RelayedUnmerged*. It is a pure function
of (local tree, incoming change, merge-base tree, a *Key oracle*) — it owns
the ADR 0001 rule and touches no storage or disk, so it is unit-testable with
a fake oracle. The **merge base** (#65, 2026-07-09) is the nearest common
ancestor's full tree, supplied by the caller (`apply` walks the incoming
chain's parents into the local graph; `dock merge` asks the graph directly):
because changes carry full trees and a snapshot may re-seal content under a
fresh address without a real edit (routine before #98's unchanged-path reuse;
still possible whenever a peer re-seals content it holds, e.g. a visibility
change), address inequality does *not* mean both sides edited — a side
whose plaintext equals the base is untouched since the fork and the other
side simply wins. Only genuinely double-edited content reaches the line-set
heuristic (and, when undecidable, *Conflict*). No base known (disjoint
history, unopenable base) falls back to the two-way comparison.

**Key oracle** — the narrow seam the classifier uses to ask the repo for
plaintext: `open(oid, now) -> Option<bytes>`. `None` *is* the relay role (this
identity can't open the content now); `Some(plaintext)` is what the merger uses
to tell a clean *Merged* from a *Conflict*. The classifier never sees keys or
ciphertext — only this oracle.

**Grant** — a key handoff event: the act of making an existing content key available to a new identity. Grants travel as targeted bundles (the grantor controls delivery by choosing who receives the bundle); the key itself rides sealed to the recipient's pubkey (ECIES, ADR 0014). A grant is **signed by the grantor** (the push envelope, ADR 0014) so the recipient and every downstream peer can verify who issued it — an unauthenticated grant would let any party forge audit history. The grantee is identified by **pubkey**, not local name: the key is sealed to that pubkey and `apply` accepts the grant iff the recipient's own key unseals it (the cryptographic unseal *is* the authorization gate; there is no name compare). Names are local nicknames resolved to pubkeys via the [[Peer registry]] before a grant is ever issued. The primitive underlying marooning and visibility migration. CLI: `loot grant <path> <identity>`.

**Manifest** — an append-only record of grant events (`oid`, `grantee_pubkey`, `grantor_pubkey`, `granted_at`), separate from the change graph. Travels in bundles alongside objects and escrow entries so every peer has a complete audit trail of who granted what to whom. Both parties are recorded as **pubkeys** (the only globally-stable identity; names are local), resolved to friendly names only at display time. Carries only the *fact* of a grant, never the key itself. The grantor pubkey is bound by the grant's signature, so the trail is forge-evident. Named for a ship's manifest recording what cargo was loaded and by whom.

**Maroon** — to cut off an identity's access to a path. Two levels:

- *Forward maroon* (`loot maroon <path> <identity>`) — re-seals content under a new key, re-grants remaining authorized identities (each receives a targeted grant bundle), publishes a new Change. The CLI **finalizes (signs) that re-seal change**, so it propagates via push/bundle — an unsigned re-seal is treated as a working change and never travels (ADR 0018), which would strand the maroon on the originator. The marooned identity retains the key for any past versions they already hold. Natural for "you may read the old code but not future updates." Implemented (ADR 0010).
- *Hard maroon* (`loot maroon --hard <path> <identity>`) — forward maroon plus a published purge event signaling all cooperating peers to remove the marooned identity's Keyring entry for the affected OID. Best-effort operational guarantee: cooperating machines purge; offline or modified-binary peers cannot be forced. Models the "person left the org" case. Implemented (ADR 0009, ADR 0010).

**Visibility migration** — promoting or demoting a path's Visibility as a first-class operation with history. Implemented as grant + maroon over the affected identity set: promoting `Restricted` → `Public` re-seals under a new ANYONE-granted key; demoting `Public` → `Restricted` re-seals under a new Restricted key and grants only the named identities. Falls out of grant and maroon working correctly — not a separate primitive.

**Relay** — a node that stores and forwards sealed content it cannot read (the non-keyholder role from ADR 0001). It holds **no restricted keys** — those never travel in a sync bundle (ADR 0003), so a relay can never read restricted content. It does forward public keys (non-secret by definition) so downstream peers receive readable public content. **A host is a relay that never sleeps** — a laptop, a `loot serve` box, and a future hosted service are the same protocol role, differing only in uptime. This makes a loot host a *zero-knowledge code host*: it physically cannot read private code, the thing a plaintext host like GitHub structurally cannot offer. Services that need plaintext (CI, server-side diff/search) are not ambient repo permissions but explicit, audited [[Grant]]s to a service Identity.

**Stow** — the relay's ingest operation (`DagRepo::stow`, ADR 0011): accept a bundle, store its sealed objects and add its change-nodes to the graph append-only, record grant facts in the Manifest, and *never* merge, decrypt, or touch a working tree. Nautical to the domain — you stow sealed cargo in the hold without opening it, and the Manifest records what was stowed. Distinct from `apply` ("merge into my working change"): a pure relay only ever calls `stow` (on push) and `bundle` (on pull). Concurrent pushes produce a forked DAG with multiple tips; forks are collapsed only by keyholder peers when they pull and `apply`.

**Identity keypair** — an ed25519 keypair generated at `loot init` (or backfilled via `loot keygen`), stored as `.loot/id` (private, mode 0600) and `.loot/id.pub` (OpenSSH public key line) (ADR 0014). The keypair serves two purposes: signing push envelopes so relays can verify authenticity, and (via a derived x25519 key) sealing grant bundles to a recipient's public key so relay delivery of grants becomes safe. Identity strings (`"alice"`, `"@relay"`) remain the primary identifier everywhere; the keypair is the credential that backs the name. Peer public keys are registered in `.loot/peers` via `loot peer add <name> <pubkey>`.

**Peer registry** — a repo's local map of nickname to public key, stored in `.loot/peers` as `name = <openssh-pubkey-line>` pairs, managed via `loot peer add/remove/list` (ADR 0014). It is the `known_hosts` of loot: the place you record "this pubkey is who I call alice" after verifying it out-of-band. Two roles: it resolves a name argument to a pubkey when *issuing* a grant (sealing to the right key), and it gates *accepting* a grant — a grant from a pubkey not in the registry is quarantined, not applied (ADR 0015). Names are purely local; the registry is what binds them to the globally-stable pubkey.

**Identity portability** — moving the *same* identity to another machine via `loot id export <file>` / `loot id import <file>` (ADR 0016). The exported file is always passphrase-wrapped (OpenSSH native encryption) because it travels and is the highest-risk artifact; the in-repo `.loot/id` stays unencrypted at rest (filesystem perms 0600). Distinct from *rotation* (a new key while staying the same identity to peers), which is deferred — likely modeled as "new identity + re-grant wave" reusing [[Grant]] and [[Maroon]] rather than cryptographic key-succession.

**Push envelope** — a 97-byte header wrapping every push body: `[0x01][pubkey 32][signature 64][bundle...]` (ADR 0014). The relay verifies the signature and checks the optional allowlist before stowing. The same envelope also wraps sealed grant bundles so the recipient can verify the grantor (ADR 0015). Transport-agnostic by design — works over any future transport, not just HTTP.

**Remote** — a named relay URL stored in `.loot/config` as `name = url` (ADR 0013). Managed via `loot remote add/remove/list`. `loot push` and `loot pull` resolve their target as: explicit URL > `--remote <name>` > `origin` default. Analogous to git's remotes; the name `origin` is the conventional default but nothing is special about it in the engine.

**Global config** — user-level defaults at `$XDG_CONFIG_HOME/loot/config` (falling back to `~/.config/loot/config`), same `key = value` format as the repo `.loot/config`. Holds cross-repo identity defaults so commands like `clone` and `init` need not retype `--identity` every time. Resolution: explicit flag > global config. Scope is deliberately narrow — currently just `identity`; remotes stay per-repo (an `origin` means different URLs in different projects). Once a repo exists, its `.loot/identity` is authoritative and the global default no longer applies.

**Clone** — `loot clone <url> <dir> [--identity <name>]`: the batteries-included front door for getting a repo onto a fresh machine. Composes existing primitives — init (fresh identity, from `--identity` or [[Global config]]) + remote add origin + pull + surface — so it ends with a materialized working tree, like `git clone`. A fresh cloner is a [[Relay]] by default: they receive the ciphertext but can read only public or already-granted content; sealed paths are skipped at surface time with a hint to request a [[Grant]]. Requires an explicit target dir (relay URLs have no natural project name); errors if the dir is non-empty. Bringing an *existing* identity to a new machine is a separate concern (identity portability), not clone.

**Network sync (`serve`/`push`/`pull`)** — the transport layer over `bundle`/`stow`/`apply` (ADR 0011). `loot serve` runs an open relay (HTTP, two endpoints: `POST /stow` for push, `POST /negotiate` for pull). `loot push [<url>]` is a deliberate *disclosure* act — it publishes the changes the relay lacks; `loot pull [<url>]` fetches the changes the local repo lacks and `apply`s them into the working change. Both resolve the target relay via the [[Remote]] config when no URL is given (one shared resolver: explicit URL > `--remote <name>` > `origin` — `grant --relay` and `pull-grants` use it too). Push and pull are distinct verbs because their security intent differs even though the mechanics are symmetric: a pull receives key-gated ciphertext (safe by construction); a push persists sealed content to another node. File-based `bundle`/`apply` are retained as the offline/sneakernet path.

**Grant discovery (`grants` / `pull-grants`)** — three honest verbs with distinct contracts so network I/O never creeps into offline commands. `loot status` stays strictly local (snapshot + report, no network). `loot grants` makes a deliberate network call to *peek* the relay mailbox — reports the pending count without draining ("2 grants pending at origin"). `loot pull-grants` is the mutating fetch: it drains the mailbox, verifies each grant's grantor signature, applies those from registered peers (quarantining unknown grantors, ADR 0015), and files the unsealed keys. This is pull-based discovery — the recipient must run `loot grants` to learn what is waiting; true push notification needs relay-initiated delivery infrastructure and is out of scope.

**Loose object storage** — each SealedObject persists as its own content-addressed file at `objects/<hex-address>`, written once and immutably via atomic rename (ADR 0012). Dedup is "does the file exist"; a push writes only the new objects (O(delta), not O(store)), killing the whole-repo-rewrite bottleneck for relays. Concurrent writes to disjoint objects are lock-free (distinct filenames); only the small graph metadata is serialized. Git's loose-object model, made natural by content addressing.

## Deliberately out of scope (for now)

- **jj-style ergonomics** (auto-snapshot working copy, stable change-ids,
  oplog) — **specced** (map #132) and **built** (map #142, all slices landed):
  stable change-ids (ADR 0029, S0 #143), implicit auto-snapshot + demotion guard
  (ADR 0030, S1 #144), reconciled read-only verb surface (S2 #145), operation log
  & undo (ADR 0031, S4 #146 — see [[Operation log & undo]]), and the
  divergent-change marker + `loot abandon` (S3 #147 — see [[Divergent change]]).
  The trio is now part of loot's surface, not out of scope. See
  `docs/research/jj-ergonomics.md` (research) and
  `docs/research/jj-ergonomics-prototype.md` (verb-surface proof). Remaining fog
  (map #142): lock-free divergent-*operations*, per-dock undo granularity, the
  git-bridge change-id trailer.
- **git interop bridge.** Important eventually; not part of the first slice.

These are excluded from the *foundation* so the first slice ships fast and
nothing built on top forces a teardown.

## Foundation (decided — ADR 0002)

The foundation is the **encrypted content-addressed DAG**, now the canonical
engine at `loot_core::engine` (`DagRepo`, re-exported as `loot_core::DagRepo`).
Decided by running the bake-off, not by argument: under per-content encryption
the CRDT degrades to last-writer-wins and silently dropped concurrent edits
(0 of 4 survived), while the DAG surfaced conflicts (safe) and was ~4.5x faster
at 50k files. See ADR 0002 and `docs/bakeoff/index.html` for full methodology.

The engine is built from deep modules: `sealed` (encryption/visibility/embargo,
ADR 0003), `converge` (the merge classifier, ADR 0001), and the engine-private
`object_store` + `change_graph`. `crates/spike-dag` is now a thin shim that
re-exports the engine so the bake-off keeps its DAG-vs-CRDT symmetry.

`crates/spike-crdt` is **retained but non-canonical** — the benchmark record,
not part of the product. `crates/loot-bench` and both spike shims stay in the
tree so the decision is reproducible (`cargo test --release`).

## Open / undecided

- **External-service escrow (hard embargo enforcement).** DECIDED 2026-07-09
  (ADR 0027) and implemented (#14 engine/wire, #88 CLI): embargoed keys travel
  as timed SealedGrants the relay withholds until `reveal_at`; the plaintext
  bundle escrow section is removed (breaking, `FORMAT_MAJOR`). Remaining open
  here is only the post-milestone hardening: **drand timelock (tlock)** to
  remove even the relay-operator trust — composable later by timelocking the
  SealedGrant payload to a drand round.

- **Relay announcement.** A relay peer declaring its relay status so senders
  can discover who holds a key before bundling — enabling selective delivery
  rather than ship-everything. Independent of key management; deferred until
  grant/revocation are working.

- **Key provenance chains.** A grant proves *who* issued it (signature, ADR 0015)
  but not that the grantor legitimately held the key, traced to the content's
  originator. Eve can sign a valid grant for content she holds but had no
  authority over; we accept this. A real fix needs an originator-authority model
  (not yet defined) plus a back-reference on each grant to the grant that
  authorized the grantor. The ADR 0015 signature + Manifest structure are the
  foundation it would build on. Deferred — speculative until originator authority
  is defined.

- **Object-level sync negotiation.** Sync negotiates at the *change-id* level:
  the client sends its tips, the relay ships every change the client lacks plus
  the full object closure. This can re-transmit ciphertext the receiver already
  holds when object sharing crosses change boundaries (the receiver discards
  known addresses on `apply`, so it is correct, just not minimal). Acceptable
  for the first slice. **Revisit with scaling benchmarks**: if over-shipping
  shows up as a real cost, add a content-address "wants" round (client filters
  the relay's offered addresses down to the ones it is missing before bytes
  move). The wire format already carries everything, so this is additive.

- **Embargoed merges across repos.** Accepting a change from a peer but keeping
  the diff embargoed until a scheduled reveal. Requires a multi-remote model
  (not yet defined). Deferred until the network layer exists.

- **Soft advisory claims (concurrent agents).** A later-phase mitigation for
  agents thrashing on the same paths: an append-only "working-on `<paths>`"
  record other agents read and voluntarily avoid — advisory, no enforcement, the
  same grain as attestations. Explicitly **not** a lock (file locking is a
  dropped, binary-first concern). Deferred: the concurrent-agent model is
  optimistic by default (docks fork, the harbor serializes, conflicts surface as
  porcelain verdicts), and work-assignment is the orchestrator's job, not loot's.
  Add only if real thrashing shows up. See the concurrent-agents design, 2026-07-06.
