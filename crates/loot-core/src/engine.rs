//! The canonical loot engine: an encrypted content-addressed DAG.
//!
//! Graduated from the bake-off winner (ADR 0002). `DagRepo` is a thin
//! composition of an [`ObjectStore`] (content-addressed ciphertext), a
//! [`ChangeGraph`] (history), a [`custody::Custody`] (this identity's key
//! custody, #323), and the policy modules [`crate::sealed`] and
//! [`crate::converge`]. It holds no storage or merge logic itself — it wires
//! the modules to the [`Repo`] seam.
//!
//! Properties carried over from the spike that proved the model:
//!   - each object is encrypted independently; visibility == key possession
//!   - addressing is by CIPHERTEXT hash only; no plaintext-derived identity, so
//!     the store leaks no plaintext-equality oracle (ADR 0004)
//!   - in memory the store is a log-structured `Vec` + index; on disk objects are
//!     loose, content-addressed files written incrementally (ADR 0012)
//!
//! Encryption, visibility, and embargo live in [`crate::sealed`] (ADR 0003);
//! the merger/relay convergence rule lives in [`crate::converge`] (ADR 0001).

mod change_graph;
mod custody;
mod object_store;
mod persist_codec;

use crate::attestation::{Attestation, AttestationLog};
use crate::bundle_codec::{BundleBody, Frame};
use crate::converge;
use crate::escrow::Escrow;
use crate::manifest::Manifest;
use crate::sealed::{self, ContentKey, SealedObject, ANYONE};
use crate::{Change, MergeOutcome, Oid, Repo, RepoError, SyncBundle, Visibility};
pub(crate) use change_graph::ChangeNode;
pub use change_graph::change_signing_message;
use change_graph::{compute_change_id, mint_change_id, ChangeGraph};
use crate::store::{read_replaced, RepoStore};
pub use custody::{MaroonResult, MigrateResult};
use custody::{decode_manifest, decode_purges, encode_manifest, encode_purges, Custody};
use object_store::{ObjectStore, Stored};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic per-process counter feeding [`atomic_write`]'s staging name.
static METADATA_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` atomically: stage to a unique sibling temp file in
/// the same directory, then `fs::rename` it over `path`. A crash mid-write or a
/// concurrent writer therefore never leaves a torn or truncated file — a reader
/// always sees the whole prior-or-next version, never a partial one (#252). The
/// temp name is unique per (process, call) so two writers of the same `path`
/// cannot clobber each other's staging file, and staging in the *same*
/// directory keeps the rename atomic (a cross-device rename is not).
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let n = METADATA_TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{}.{}.{}.tmp", file_name, std::process::id(), n));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Returned by `gc`: how many loose objects were (or, on a dry run, would be)
/// pruned, and the total bytes they occupied on disk (ADR 0012, #66).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Number of unreferenced object files pruned.
    pub pruned: usize,
    /// Total on-disk size of the pruned object files, in bytes.
    pub bytes: u64,
}

/// Returned by `verify` (#19): the loose object store's integrity census.
/// Clean means every object file's content re-hashes to its filename and every
/// referenced address has a file on disk.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Object files whose re-hashed content matches their address.
    pub ok: usize,
    /// Addresses whose file exists but is undecodable or re-hashes to a
    /// different address (bit rot, truncation, tampering).
    pub corrupt: Vec<Oid>,
    /// Addresses referenced by a change but with no file on disk, each with
    /// the referencing sites (#335) — a bare address says *that* something is
    /// lost; the referencing change and path say *what*.
    pub missing: Vec<MissingObject>,
    /// Absent addresses an operator already accepted as lost (#335,
    /// `--accept-loss`): reported for the record, but not a failure —
    /// acknowledged loss must not drown out NEW damage.
    pub lost: Vec<Oid>,
}

impl VerifyReport {
    /// Acknowledged losses are clean: the ledger exists precisely so a store
    /// with known-unrecoverable history can gate CI on integrity again.
    pub fn is_clean(&self) -> bool {
        self.corrupt.is_empty() && self.missing.is_empty()
    }
}

/// One missing address with every (change, path) site that references it
/// (#335). Sites are in the shared graph's stored order, deduped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingObject {
    pub addr: Oid,
    pub referenced_by: Vec<MissingRef>,
}

/// A site referencing a missing object: the change, the path within it, and
/// the change's message — enough to judge whether the lost content matters
/// (a superseded historical version vs. a path live history still needs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingRef {
    pub change: Oid,
    pub path: PathBuf,
    pub message: String,
}

/// One change in a [`LogGraph`]: its id, message, and which heads can reach it
/// (as indices into [`LogGraph::heads`]). A change reachable from exactly one
/// head is unique to that head's lineage; one reachable from several is shared
/// ancestry across the divergence.
#[derive(Clone, Debug)]
pub struct LogNode {
    pub id: Oid,
    pub message: String,
    /// Indices (into `LogGraph::heads`) of the heads that can reach this change,
    /// ascending. Never empty for a change in the graph.
    pub reachable_from: Vec<usize>,
}

/// Structured history for rendering `log` when the graph has diverged into
/// multiple heads (ADR 0001, issue #18). `changes` is in reverse-topo order
/// (children before parents), so a head appears before its ancestors.
#[derive(Clone, Debug)]
pub struct LogGraph {
    /// The current heads (tips), in stable ascending order.
    pub heads: Vec<Oid>,
    /// Every change with its head-reachability, children-first.
    pub changes: Vec<LogNode>,
}

/// The DAG engine. Composes storage, history, key custody, and policy behind
/// the [`Repo`] interface.
pub struct DagRepo {
    root: PathBuf,
    identity: String,
    /// This identity's ed25519 public key, folded into new change ids to attribute
    /// authored history (S3, ADR 0018). `None` until the workspace sets it from the
    /// loaded keypair; unauthored changes then keep their legacy (pre-0018) ids.
    author: Option<[u8; 32]>,
    /// Key custody: keyring, embargo escrow, grant manifest, and purge log
    /// (#323) — extracted into [`custody::Custody`], which the verbs in
    /// `custody.rs` (`grant`, `maroon`, `migrate`, ...) mutate directly.
    custody: Custody,
    objects: ObjectStore,
    graph: ChangeGraph,
    /// Paths with unresolved conflicts from the last `apply`, keyed by path,
    /// value is (our oid, their oid). Populated from `MergeOutcome::Conflict`
    /// during `apply`; cleared entry-by-entry as `resolve` is called (ADR 0001).
    conflicts: BTreeMap<PathBuf, (Oid, Oid)>,
    /// Detachable, advisory attestations over changes (S4, ADR 0018). Travels in
    /// bundles; verified-and-dropped on ingest; never affects a change id.
    attestations: AttestationLog,
}

/// **Object & key-routing helpers** (R3, #179): the shared entitlement/dedup
/// logic every ingest path (`put`, `apply_sync`, `stow`, sealed-grant apply)
/// funnels through — `store` decides whether a freshly-opened key belongs in
/// [`custody::Custody`]'s keyring or its escrow (ADR 0007), and `entitled` is
/// its private gate. `object` is the read-side counterpart. These stay here
/// (not in `custody.rs`) because they are shared with the Reconcile and
/// Sync-negotiation faces, not custody-exclusive (#323). A couple of small
/// tree/visibility reads the CLI uses directly ride alongside; the actual
/// custody verbs — grant, sealed grant, maroon, migrate, escrow flush — moved
/// to [`custody`].
impl DagRepo {
    /// Whether this identity is entitled to hold the key for content with these
    /// grant ids — used to decide what to file into the local keyring.
    fn entitled(&self, grant_ids: &[String]) -> bool {
        grant_ids.iter().any(|g| g == ANYONE || g == &self.identity)
    }

    /// Store a SealedObject and route its key to the right custody (ADR 0007):
    /// - Embargoed content: key goes to `escrow` (not Keyring) for ALL identities.
    /// - Everything else: key goes to `keyring` iff entitled.
    ///
    /// If dedup collapsed us onto an existing address, the minted key seals
    /// discarded ciphertext and must not be filed anywhere.
    fn store(&mut self, addr: Oid, obj: SealedObject, key: Option<ContentKey>) -> Oid {
        let entitled = self.entitled(&obj.grant_ids);
        let reveal_at = if let Visibility::Embargoed { reveal_at } = obj.vis {
            Some(reveal_at)
        } else {
            None
        };
        let stored = self.objects.put(addr, obj);
        let stored_addr = stored.addr().clone();
        if let Some(k) = key {
            if matches!(stored, Stored::New(_)) && entitled {
                if let Some(t) = reveal_at {
                    // Embargoed: key stays out of the Keyring until flush (ADR 0007).
                    if !self.custody.escrow.holds(&stored_addr) {
                        self.custody.escrow.insert(stored_addr.clone(), k, t);
                    }
                } else if !self.custody.keyring.holds(&stored_addr) {
                    self.custody.keyring.insert(stored_addr.clone(), k);
                }
            }
        }
        stored_addr
    }

    fn object(&self, oid: &Oid) -> Result<&SealedObject, RepoError> {
        self.objects.get(oid)
    }

    /// The stored visibility of the object at `oid`, if the object is held.
    /// Lets the CLI inherit an embargoed seal's `reveal_at` when issuing a
    /// grant for it (ADR 0027: a late-added recipient gets a timed grant,
    /// never an early key).
    pub fn visibility_of(&self, oid: &Oid) -> Option<Visibility> {
        self.objects.get(oid).ok().map(|o| o.vis.clone())
    }

    /// The OID for `path` in the current tree, or `NotFound` if absent.
    pub fn current_tree_oid(&self, path: &Path) -> Result<Oid, RepoError> {
        self.graph.current_tree()
            .get(path)
            .map(|(oid, _)| oid.clone())
            .ok_or(RepoError::NotFound(Oid([0; 32])))
    }

    /// The most recently recorded `(oid, visibility)` for `path`, across all
    /// of history — not just the current tree (`loot embargo-status`, #15).
    /// A path that predates a deletion, or one this dock's heads don't (yet)
    /// carry, is still explainable rather than a bare "not found".
    pub fn path_history_entry(&self, path: &Path) -> Option<(Oid, Visibility)> {
        self.graph.path_in_history(path)
    }

}

/// The fallback subject `resolve` mints when no ours-line subject is
/// derivable (#337). loot-first's land gate refuses a working change carrying
/// this prefix (#316) and keeps its own copy of the string
/// (`crates/loot-first/src/orchestrator.rs`) — change one, change both.
const RESOLVE_FALLBACK_PREFIX: &str = "resolve conflict at ";

/// Opens the suffix a subject-inheriting resolution appends (#337):
/// `"<subject> (conflict resolution: <path>)"`. Also what the inheritance walk
/// strips from a sibling resolution's message so chained resolutions never
/// stack suffixes.
const RESOLUTION_SUFFIX_OPEN: &str = " (conflict resolution: ";

/// loot-cli's placeholder for a never-described working change
/// (`workspace.rs`, `UNDESCRIBED_MESSAGE`) — a finalized bare one is a real
/// state history has carried. Inheriting it would mint an undescribed subject
/// that evades loot-first's placeholder gate (#316), so the walk skips it
/// like the resolve placeholder. Same deliberate cross-crate string coupling
/// as [`RESOLVE_FALLBACK_PREFIX`]: change one, change both.
const UNDESCRIBED_SUBJECT: &str = "(working change)";

/// **Reconcile & relay face** (R3, #179): what happens when lines of history
/// meet — the conflict set and its resolution, the relay's append-only `stow`,
/// and the `apply_sync` machinery under the classifier (ADR 0001/0011).
impl DagRepo {
    /// The subject a resolution change inherits (#337): the nearest
    /// describable change on the ours line, found by walking first-parent
    /// edges from `base`. Structural nodes never name the work and are
    /// skipped: merges (2+ parents — the conflicted reconcile itself, and any
    /// converge fold beneath it; their first parent IS the ours side, by
    /// `merge_tips`' parent order) and placeholder-subject legacy resolutions.
    /// A sibling resolution's own suffix is stripped, so resolving several
    /// paths in sequence inherits the same bare subject each time. `None`
    /// when the walk exhausts — the caller falls back to the placeholder.
    fn inherited_resolution_subject(&self, base: &Oid) -> Option<String> {
        let mut cur = base.clone();
        // Bounded: a pathological first-parent chain must not stall resolve.
        for _ in 0..64 {
            let node = self.graph.get(&cur)?;
            if node.parents.len() <= 1 {
                let msg = node.message.as_str();
                if !msg.starts_with(RESOLVE_FALLBACK_PREFIX) && msg != UNDESCRIBED_SUBJECT {
                    let subject = match msg.rfind(RESOLUTION_SUFFIX_OPEN) {
                        Some(i) if msg.ends_with(')') => &msg[..i],
                        _ => msg,
                    };
                    if !subject.is_empty() {
                        return Some(subject.to_string());
                    }
                }
            }
            cur = node.parents.first()?.clone();
        }
        None
    }
    /// All unresolved conflicts from the last `apply`, keyed by path.
    /// Each value is `(our_oid, their_oid)`.
    pub fn conflicts(&self) -> &BTreeMap<PathBuf, (Oid, Oid)> {
        &self.conflicts
    }

    /// Resolve a conflict at `path` by providing the resolution bytes. Seals the
    /// resolution under `vis`, records a resolution change, and removes the path
    /// from the conflict set. Returns `(resolution change id, resolution content
    /// oid)`.
    ///
    /// `base` is the tip the resolution builds on. `Some(tip)` parents the
    /// resolution on that single tip and bases its tree on that line — a dock
    /// resolves onto its own conflicted merge change and advances it (ADR 0022),
    /// rather than folding in every head. `None` keeps the pre-dock behavior
    /// (parent on all heads, base on the merged `current_tree`).
    ///
    /// The resolution's message inherits the ours-line subject with a
    /// `(conflict resolution: <path>)` suffix (#337) — see
    /// [`inherited_resolution_subject`]; when no subject is derivable it falls
    /// back to the `resolve conflict at <path>` placeholder, which loot-first's
    /// land gate refuses to publish as a commit subject (#316).
    ///
    /// [`inherited_resolution_subject`]: DagRepo::inherited_resolution_subject
    pub fn resolve(
        &mut self,
        base: Option<&Oid>,
        path: &Path,
        resolution: &[u8],
        vis: Visibility,
        now: u64,
    ) -> Result<(Oid, Oid), RepoError> {
        if !self.conflicts.contains_key(path) {
            return Err(RepoError::Backend(format!(
                "no conflict recorded at {}",
                path.display()
            )));
        }

        let new_oid = self.put(resolution, vis.clone())?;

        // Build the resolution on `base`'s line (the dock's conflicted merge tip)
        // so it lands there and advances it; `None` reconciles against all heads.
        let (mut new_tree, parents) = match base {
            Some(tip) => (self.graph.tree_at(tip), vec![tip.clone()]),
            None => (self.graph.current_tree(), self.graph.heads()),
        };
        let message = base
            .and_then(|tip| self.inherited_resolution_subject(tip))
            .map(|subject| {
                format!("{subject}{RESOLUTION_SUFFIX_OPEN}{})", path.display())
            })
            .unwrap_or_else(|| format!("{RESOLVE_FALLBACK_PREFIX}{}", path.display()));
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), vis));
        let change = Change {
            id: Oid([0; 32]),
            parents,
            message,
            tree: new_tree,
        };
        let change_id = self.record(change)?;

        // Clear the resolved conflict.
        self.conflicts.remove(path);

        let _ = now;
        Ok((change_id, new_oid))
    }

    /// Stow a bundle append-only: store its sealed objects and add its
    /// change-nodes as new tips, without merging, decrypting, or touching a
    /// working tree (ADR 0011). This is the **relay** ingest path — the node
    /// holds ciphertext it cannot read and forwards it for keyholders. Purge
    /// events are accumulated so they continue to propagate on the next
    /// `bundle`. Convergence is deferred to whoever pulls and holds keys.
    ///
    /// Only sync bundles (tag 0) are stowable. A grant bundle (tag 1) is a
    /// targeted key handoff with no meaning for a keyless relay, so it is
    /// rejected rather than silently dropped.
    pub fn stow(&mut self, bundle: &SyncBundle) -> Result<(), RepoError> {
        // A relay only ever stows Sync frames; a Grant/SealedGrant is a targeted
        // key handoff with no meaning for a keyless relay, so reject it.
        let Frame::Sync { purges, body } = Frame::decode(&bundle.0)? else {
            return Err(RepoError::Backend(
                "a relay can only stow sync bundles (tag 0), not grant bundles".into(),
            ));
        };
        let BundleBody { changes, objs, keys, attestations } = body;

        // Reject any change with a missing/invalid author signature before we
        // store anything — a keyless relay still enforces authorship (ADR 0018).
        for node in &changes {
            verify_authored_change(node)?;
        }

        // Ingest attestations: verify each, drop invalid (advisory, never fatal),
        // keep the rest so they keep forwarding downstream (S4, ADR 0018).
        for att in attestations {
            if att.verify() {
                self.attestations.insert(att);
            }
        }

        // Store ciphertext, retaining any keys that rode along so they keep
        // forwarding downstream. Only ANYONE-granted, non-embargoed (public)
        // keys ever travel in a sync bundle — RESTRICTED keys never do
        // (ADR 0003), and embargoed keys lost their bundle lane entirely
        // (ADR 0027, v5). So the relay's "keylessness" for private content is
        // automatic: it cannot receive those keys here, and thus can never
        // read the content. Public keys are non-secret by definition;
        // carrying them lets the relay forward readable public content.
        for (addr, obj) in objs {
            let key = keys.get(&addr).copied();
            self.store(addr, obj, key);
        }
        // Accumulate purge events so they keep propagating downstream. A relay
        // is never the marooned identity for its own keyring (it holds none),
        // so there is nothing to remove locally.
        for p in purges {
            if !self.custody.purges.contains(&p) {
                self.custody.purges.push(p);
            }
        }
        // Append change-nodes as new tips. Concurrent pushes legitimately fork
        // the graph; keyholders collapse the forks on pull.
        for node in changes {
            self.graph.insert(node);
        }
        Ok(())
    }

    /// Merge a parsed sync bundle into our working change — the keyholder path
    /// shared by `apply`. Honors purges against our own keyring, ingests objects
    /// and keys, classifies each incoming change against our pre-apply tree via
    /// the ADR 0001 convergence rule, and records conflicts.
    fn apply_sync(
        &mut self,
        purges: Vec<(Oid, String)>,
        body: BundleBody,
        now: u64,
        abandoned: &std::collections::BTreeSet<Oid>,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        let BundleBody { changes, objs, keys, attestations } = body;

        // Reject any change with a missing/invalid author signature before we
        // mutate state (ADR 0018 — validity is always enforced, not a toggle).
        for node in &changes {
            verify_authored_change(node)?;
        }

        // Ingest attestations: verify each, drop invalid (advisory, never fatal),
        // and merge the rest (S4, ADR 0018).
        for att in attestations {
            if att.verify() {
                self.attestations.insert(att);
            }
        }

        // Honor purge events: if we are the marooned identity, remove the old key.
        for (purge_oid, marooned) in &purges {
            if marooned == &self.identity {
                self.custody.keyring.remove(purge_oid);
            }
        }

        // Our tree before applying, used to detect concurrent same-path edits.
        let local_before = self.graph.current_tree();

        // Ingest SealedObjects, filing only the public (non-embargoed) keys that
        // rode along. Embargoed keys have no bundle lane at all (ADR 0027, v5):
        // they reach a peer only as a relay-withheld timed SealedGrant, after
        // the relay's clock passes reveal_at. No Restricted key can be here.
        for (addr, obj) in objs {
            let key = keys.get(&addr).copied();
            self.store(addr, obj, key);
        }

        // Classify every incoming change against our pre-apply tree using the
        // shared ADR 0001 classifier. We are the KeyOracle: it asks us for
        // plaintext, we answer via sealed::open. The classifier owns the rule.
        //
        // Each change is classified with its merge base (#65): the nearest
        // ancestor we already hold, found by walking the incoming batch's
        // parent links into our graph. Changes carry full trees, so a pulled
        // chain re-raises every path its author never touched — without the
        // base, those classified as conflicts whenever our line had moved on.
        let batch: BTreeMap<&Oid, &ChangeNode> = changes.iter().map(|n| (&n.id, n)).collect();
        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        // One Liveness view for the whole batch (#216) — built before any
        // insert, so it reflects exactly what we held when the bundle arrived.
        // The caller's abandoned set rides in: an incoming co-version of a
        // locally-abandoned version is NOT divergence-forming (the abandoned
        // side isn't live) and classifies normally.
        let liveness = self.liveness(abandoned, &[]);
        for node in &changes {
            // An incoming co-version of a change id we already hold live is
            // not an independent line meeting ours — it is (or exposes)
            // divergence, one two-writer event the durable handle already
            // carries as the `!` marker (#198/#203, amending ADR 0032).
            // Classifying its tree against ours would mint a phantom per-path
            // conflict that converge no longer merges away; `loot abandon`
            // is the settle. The node still ingests below: divergence is
            // data, not an error. A version the incoming node supersedes is
            // exempt — that is the clean-replacement path, classified as
            // today.
            let forms_divergence = node.change_id.is_some_and(|cid| {
                liveness
                    .live_of(&cid)
                    .iter()
                    .any(|held| held != &node.id && !node.predecessors.contains(held))
            });
            if forms_divergence {
                continue;
            }
            let base_tree = self.incoming_base_tree(node, &batch);
            let per_change =
                converge::classify(&local_before, &node.tree, base_tree.as_ref(), self, now);
            for (path, outcome) in per_change {
                let slot = outcomes.entry(path).or_insert(MergeOutcome::Converged);
                *slot = converge::worst(slot.clone(), outcome);
            }
        }

        // Populate the conflict map from Conflict outcomes.
        for (path, outcome) in &outcomes {
            if let MergeOutcome::Conflict { ref ours, ref theirs } = outcome {
                self.conflicts.insert(path.clone(), (ours.clone(), theirs.clone()));
            }
        }

        for node in changes {
            self.graph.insert(node);
        }

        Ok(outcomes)
    }

    /// The merge-base tree for an incoming change (#65): the nearest ancestor
    /// this repo already holds, walking parent links through the incoming
    /// `batch` for nodes not yet ingested. A change we already hold is its own
    /// base, so a re-delivered chain classifies as wholly untouched. `None`
    /// for disjoint history (a root chain we have never seen).
    fn incoming_base_tree(
        &self,
        node: &ChangeNode,
        batch: &BTreeMap<&Oid, &ChangeNode>,
    ) -> Option<BTreeMap<PathBuf, (Oid, Visibility)>> {
        let mut queue: std::collections::VecDeque<&Oid> = std::collections::VecDeque::new();
        let mut seen: std::collections::BTreeSet<&Oid> = std::collections::BTreeSet::new();
        queue.push_back(&node.id);
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if let Some(known) = self.graph.get(id) {
                return Some(known.tree.clone());
            }
            if let Some(n) = batch.get(id) {
                queue.extend(n.parents.iter());
            }
        }
        None
    }

}

/// **Persistence & gc face** (R3, #179): the `.loot/` round-trip — save/load
/// via the RepoStore (the layout's single owner, ADR 0017), loose-object gc
/// (ADR 0012). No policy: what a change means lives in the other faces.
impl DagRepo {
    /// Every content address in the live set for `gc`: anything referenced by
    /// any change in the graph — across ALL changes, not just the current heads,
    /// and including working changes (every dock's in-progress node rides in the
    /// loaded graph, ADR 0022) — plus the sides of unresolved conflicts.
    /// Anything in the object store outside this set is unreachable (ADR 0012).
    fn referenced_oids(&self) -> BTreeSet<Oid> {
        let mut live = BTreeSet::new();
        for node in self.graph.in_order() {
            for (oid, _vis) in node.tree.values() {
                live.insert(oid.clone());
            }
        }
        // Unresolved conflict sides are already graph-covered (both changes are
        // recorded, append-only), but keep them explicitly live so gc stays
        // correct if that invariant ever loosens.
        for (ours, theirs) in self.conflicts.values() {
            live.insert(ours.clone());
            live.insert(theirs.clone());
        }
        live
    }

    /// Prune loose objects not referenced by any change in the graph (ADR 0012,
    /// #17, restored in #66). Content-addressing makes this exact: an object
    /// whose address no ChangeNode names can never be needed, so deleting it is
    /// loss-free. Walks the on-disk object store under `dir` and removes every
    /// unreferenced file; with `dry_run` it only reports what would be pruned.
    /// On a real run the in-memory store is compacted to match, so a subsequent
    /// `save` stays consistent.
    ///
    /// Objects referenced by non-HEAD changes are retained — the whole reachable
    /// history is preserved, only truly orphaned objects go. `dir` is the same
    /// `.loot/` directory passed to [`Self::save`]/[`Self::load`].
    ///
    /// The live set is rooted in the **whole shared store**, not this dock's
    /// loaded graph (#263/#265): the load is lineage-filtered (ADR 0022), so a
    /// change landed from a lane and never adopted here is exactly the node a
    /// loaded-graph walk misses — pruning its objects strands the projection
    /// (git-main names a change whose content is gone). So gc re-reads the
    /// shared graph file (every position's finalized nodes) and every
    /// registered lane's working-change blob (an unsigned change's objects are
    /// already sealed into the shared store) as additional roots.
    pub fn gc(&mut self, dir: &Path, dry_run: bool) -> Result<GcReport, RepoError> {
        let store = RepoStore::new(dir);
        let mut live = self.referenced_oids();
        live.extend(disk_rooted_oids(&store)?);
        let (pruned, bytes) =
            persist_codec::prune_orphaned_objects_loose(&store.objects_dir(), &live, dry_run)?;
        if !dry_run {
            self.objects.retain(&live);
        }
        Ok(GcReport { pruned, bytes })
    }

    /// Integrity-check the loose object store (#19). Deliberately an
    /// *associated* function over the on-disk store, never a method on a loaded
    /// repo: a corrupt store is exactly the store `load` dies on (the object
    /// decode fails), so verify must not require a successful load. Read-only:
    /// re-decodes every file under `objects/`, re-hashes its content against
    /// the filename (the content address, [`sealed::SealedObject::address`] —
    /// corruption is exact, never heuristic), then confirms every address
    /// rooted on disk — [`disk_rooted_oids`] plus the primary's own
    /// working-change blob — has a file. Useful after a disk incident or
    /// suspicious relay behaviour. Unresolved conflict sides need no extra
    /// root: both sides' changes are recorded in the graph (ADR 0001).
    pub fn verify(dir: &Path) -> Result<VerifyReport, RepoError> {
        let store = RepoStore::new(dir);
        let mut nodes = disk_rooted_nodes(&store)?;
        // The primary is lane #0 and not in the registry; its in-progress
        // working change lives at the shared root's own `working-change`.
        if let Some(blob) = store.read_working_change() {
            nodes.extend(persist_codec::decode_nodes(&blob)?);
        }
        let scan = persist_codec::scan_objects_loose(&store.objects_dir())?;
        // First pass names the absent addresses; the second attaches every
        // referencing (change, path) site so the report says what was lost.
        // An address in the acknowledged-lost ledger is partitioned out of
        // `missing` — reported, but no longer a failure (#335). A ledger
        // entry whose object is present again (or no longer referenced) is
        // simply inert.
        let acknowledged = store.read_lost();
        let absent: BTreeSet<Oid> = nodes
            .iter()
            .flat_map(|n| n.tree.values())
            .filter(|(oid, _)| !scan.present.contains(oid))
            .map(|(oid, _)| oid.clone())
            .collect();
        let (lost, unacknowledged): (Vec<Oid>, Vec<Oid>) =
            absent.into_iter().partition(|a| acknowledged.contains(a));
        let mut refs: BTreeMap<Oid, Vec<MissingRef>> =
            unacknowledged.into_iter().map(|a| (a, Vec::new())).collect();
        for node in &nodes {
            for (path, (oid, _vis)) in &node.tree {
                if let Some(sites) = refs.get_mut(oid) {
                    let site = MissingRef {
                        change: node.id.clone(),
                        path: path.clone(),
                        message: node.message.clone(),
                    };
                    if !sites.contains(&site) {
                        sites.push(site);
                    }
                }
            }
        }
        Ok(VerifyReport {
            ok: scan.present.len() - scan.corrupt.len(),
            corrupt: scan.corrupt,
            missing: refs
                .into_iter()
                .map(|(addr, referenced_by)| MissingObject { addr, referenced_by })
                .collect(),
            lost,
        })
    }

    /// Accept every currently-missing object as lost (#335): append the
    /// addresses `verify` reports missing to the store's acknowledged-lost
    /// ledger, so subsequent verifies stop failing on them while still
    /// catching new damage. An explicit operator action — nothing writes the
    /// ledger implicitly — taken under the store lock (read-modify-write of a
    /// shared file, ADR 0034/#293). Returns the newly acknowledged report so
    /// the caller can show exactly what was accepted, provenance included.
    pub fn accept_loss(dir: &Path) -> Result<VerifyReport, RepoError> {
        let store = RepoStore::new(dir);
        let report = Self::verify(dir)?;
        if !report.missing.is_empty() {
            let _lock = store.lock_shared();
            let mut ledger = store.read_lost();
            ledger.extend(report.missing.iter().map(|m| m.addr.clone()));
            store
                .write_lost(&ledger)
                .map_err(|e| RepoError::Backend(format!("write lost ledger: {e}")))?;
        }
        Ok(report)
    }

    /// Make a landed-but-unadopted lineage visible to this position (#265):
    /// insert into the loaded graph every ancestor of `tip` that the shared
    /// graph file records but the lineage-filtered load (ADR 0022) dropped.
    /// This is how a catch-up verb (`loot adopt`, ferry's reconcile) reasons
    /// about a change another lane landed: the nodes and their objects are
    /// already in the shared store — only this dock's *view* lacked them.
    ///
    /// Inserts parents-before-children (the [`ChangeGraph::reachable_from`]
    /// discipline) so head tracking stays exact; nodes already loaded stop the
    /// walk. Returns whether `tip` is known afterwards — `false` means the
    /// shared graph has no such node (it predates the gc guard above and was
    /// pruned; recovery is ferry's baseline adoption, #263) and the loaded
    /// graph is left untouched.
    pub fn ingest_shared_lineage(
        &mut self,
        store: &RepoStore,
        tip: &Oid,
    ) -> Result<bool, RepoError> {
        if self.graph.get(tip).is_some() {
            return Ok(true);
        }
        let mut pool: BTreeMap<Oid, ChangeNode> = BTreeMap::new();
        for node in read_shared_graph(store)? {
            pool.insert(node.id.clone(), node);
        }
        if !pool.contains_key(tip) {
            return Ok(false);
        }
        fn visit(
            id: &Oid,
            pool: &BTreeMap<Oid, ChangeNode>,
            seen: &mut BTreeSet<Oid>,
            graph: &mut ChangeGraph,
        ) {
            if graph.get(id).is_some() || !seen.insert(id.clone()) {
                return;
            }
            if let Some(node) = pool.get(id) {
                for p in &node.parents {
                    visit(p, pool, seen, graph);
                }
                graph.insert(node.clone());
            }
        }
        let mut seen = BTreeSet::new();
        visit(tip, &pool, &mut seen, &mut self.graph);
        Ok(true)
    }

    /// Persist the whole repo under `dir` (typically `.loot/`): all sealed
    /// objects, the full change graph, and this identity's keyring. The keyring
    /// is written to its own LOCAL-ONLY file — it is custody, not repo content,
    /// and never travels in a bundle (ADR 0003, 0005).
    pub fn save(&self, dir: &std::path::Path) -> Result<(), RepoError> {
        self.save_to(&RepoStore::new(dir))
    }

    /// Dock-aware persist (CA1.5, ADR 0022). The shared artifacts (objects, the
    /// finalized change graph, keyring, escrow, manifest, purges, conflicts,
    /// attestations) live top-level regardless of dock; only this dock's
    /// *lineage state* — its heads and its in-progress working-change node — is
    /// per-dock, so concurrent docks over one store never see each other's
    /// uncommitted work nor entangle their tips.
    ///
    /// The shared graph is an **immutable node store**: we union our lineage's
    /// finalized nodes into whatever is already on disk (other docks' finalized
    /// nodes are preserved, never dropped), excluding any working change. The
    /// working change (authored-but-unsigned) is written to the dock's own
    /// `change` file and promoted into the shared graph only when it is signed
    /// at `loot new` (finalization), matching git's "commit publishes" model.
    pub fn save_to(&self, store: &RepoStore) -> Result<(), RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        let dir = store.dot();
        std::fs::create_dir_all(dir).map_err(io)?;
        // Objects: loose, content-addressed, immutable, atomically written
        // (ADR 0012). Disjoint filenames make concurrent object writes lock-free,
        // so they persist outside the shared-metadata lock below.
        persist_codec::save_objects_loose(&store.objects_dir(), &self.objects)?;

        // --- shared append-only surface: serialize the read-modify-write (#293).
        //
        // Every file here is persisted by reading the whole on-disk version,
        // MERGING our in-memory state into it, and writing the whole file back.
        // The merge is what makes it safe for two lanes to append concurrently
        // (ADR 0034: the shared store is append-only) — a blind overwrite of our
        // *stale* in-memory copy would drop a change another lane just finalized
        // ("reports success but doesn't stick") or a key it just filed (visible
        // content reading back as "content you can't see"). The store lock closes
        // the read-modify-write race window so the merge sees the other writer's
        // already-persisted append; every write is atomic (temp+rename) so a
        // concurrent reader never observes a torn file (#252/#293).
        {
            let _guard = store.lock_shared();

            atomic_write(&store.identity(), self.identity.as_bytes()).map_err(io)?;

            // Finalized graph: union on-disk finalized nodes (other lanes'
            // lineages) with ours; working changes are excluded and stored
            // per-lane. Immutable nodes make the union safe (same id ⇒ same bytes).
            let mut finalized = ChangeGraph::new();
            if let Ok(bytes) = std::fs::read(store.graph()) {
                for node in persist_codec::decode_nodes(&bytes)? {
                    if !is_working_change(&node) {
                        finalized.insert(node);
                    }
                }
            }
            for node in self.graph.in_order() {
                if !is_working_change(node) {
                    finalized.insert(node.clone());
                }
            }
            atomic_write(&store.graph(), &persist_codec::encode_graph(&finalized)).map_err(io)?;

            // Keyring: union on-disk keys (a concurrent lane may have filed a key
            // for content it sealed) into ours, then RE-HONOR our purges so a
            // hard-maroon key removal (ADR 0009) is never resurrected by the union.
            let mut keyring = self.custody.keyring.clone();
            if let Ok(bytes) = std::fs::read(store.keyring()) {
                for (oid, key) in persist_codec::decode_keyring(&bytes)?.iter() {
                    if !keyring.holds(&oid) {
                        keyring.insert(oid, key);
                    }
                }
            }
            for (purge_oid, marooned) in &self.custody.purges {
                if marooned == &self.identity {
                    keyring.remove(purge_oid);
                }
            }
            atomic_write(&store.keyring(), &persist_codec::encode_keyring(&keyring)).map_err(io)?;

            // Escrow / manifest / purges / attestations: the same append-only
            // union, so a stale writer never clobbers another's entry.
            let mut escrow = self.custody.escrow.clone();
            if let Ok(bytes) = std::fs::read(store.escrow()) {
                for (oid, entry) in persist_codec::decode_escrow(&bytes)?.iter() {
                    if !escrow.holds(oid) {
                        escrow.insert(oid.clone(), entry.key, entry.reveal_at);
                    }
                }
            }
            atomic_write(&store.escrow(), &persist_codec::encode_escrow(&escrow)).map_err(io)?;

            let mut manifest = self.custody.manifest.clone();
            if let Ok(bytes) = std::fs::read(store.manifest()) {
                manifest.merge(&decode_manifest(&bytes)?);
            }
            atomic_write(&store.manifest(), &encode_manifest(&manifest)).map_err(io)?;

            let mut purges = self.custody.purges.clone();
            if let Ok(bytes) = std::fs::read(store.purges()) {
                for p in decode_purges(&bytes)? {
                    if !purges.contains(&p) {
                        purges.push(p);
                    }
                }
            }
            atomic_write(&store.purges(), &encode_purges(&purges)).map_err(io)?;

            let mut attestations = self.attestations.clone();
            if let Ok(bytes) = std::fs::read(store.attestations()) {
                attestations.merge(&decode_attestations(&bytes)?);
            }
            atomic_write(&store.attestations(), &encode_attestations(&attestations))
                .map_err(io)?;
        }

        // --- lane-owned state (single-writer; ADR 0034). Not under the lock, but
        // written atomically so a concurrent *reader* (another lane's `status` or
        // `loot lanes`) never sees a torn file (#293).

        // This lane's working change (at most one — its tip), out of the shared graph.
        let working: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            .filter(|n| is_working_change(n))
            .collect();
        let working_blob =
            (!working.is_empty()).then(|| persist_codec::encode_nodes(&working));
        store
            .write_working_change(working_blob.as_deref())
            .map_err(io)?;

        // This lane's lineage tips (git's per-worktree ref) and its conflict set.
        store.write_heads(&self.graph.heads()).map_err(io)?;
        atomic_write(&store.conflicts(), &encode_conflicts(&self.conflicts)).map_err(io)?;
        Ok(())
    }
}

/// **Snapshot face** (R3, #179): the working tree becomes the working change —
/// visibility-aware reconcile against the base, in-place rewrite, unchanged-
/// path reuse (#98), the demotion guard (#62), and the eager change-id
/// assignment (ADR 0029/0030).
impl DagRepo {
    /// Visibility-aware snapshot of a working tree into the working change
    /// (ADR 0006). `entries` is the tree the caller can see — `(path, bytes,
    /// intended visibility)` — typically every file the Workspace read from disk.
    /// `working` is the id of the current working change to rewrite in place, or
    /// `None` on the first snapshot. `message` names it; `now` evaluates embargo.
    ///
    /// The working change is rewritten in place (true JJ): the prior working
    /// node is removed first, so reconcile always bases on FINALIZED history.
    /// Reconcile against that base tree:
    ///   - a base path THIS identity can open now: update to match `entries`,
    ///     or delete if absent from `entries` (a keyholder removing own content);
    ///   - a base path it cannot open: carried forward unchanged (never seen);
    ///   - an `entries` path that collides with a base path it CANNOT open:
    ///     refused (no silent clobber of sealed content).
    ///
    /// Returns the new working-change id. Idempotent on an unchanged tree:
    /// a path whose plaintext and visibility are unchanged keeps its sealed
    /// object and oid (#98), so snapshots — and the pushes that ship their
    /// objects — are O(delta), not O(repo).
    pub fn snapshot(
        &mut self,
        base: Option<&Oid>,
        working: Option<&Oid>,
        entries: &[(PathBuf, Vec<u8>, Visibility)],
        message: &str,
        now: u64,
    ) -> Result<Oid, RepoError> {
        self.snapshot_allowing(base, working, entries, message, now, &[])
    }

    /// `snapshot` with an explicit demotion allowlist (#62). A visibility
    /// demotion — an entry re-resolving *more readable* than the tree already
    /// records (Restricted/Embargoed -> Public, Embargoed -> Restricted) — is
    /// refused unless its path is in `allow_demote`: a dropped or mangled
    /// `.lootattributes` line would otherwise re-seal private content publicly
    /// with no ceremony, the fail-open that leaked in the dogfood pilot.
    /// Widening a Restricted identity set is not guarded here — `grant` is the
    /// audited verb for that.
    pub fn snapshot_allowing(
        &mut self,
        base: Option<&Oid>,
        working: Option<&Oid>,
        entries: &[(PathBuf, Vec<u8>, Visibility)],
        message: &str,
        now: u64,
        allow_demote: &[PathBuf],
    ) -> Result<Oid, RepoError> {
        self.snapshot_assigning(base, working, entries, message, now, allow_demote, None)
    }

    /// `snapshot_allowing` with an explicit `assign` change id to mint the fresh
    /// change under (ADR 0029/0030). When `working` is `Some`, its durable
    /// change id is carried across the re-snapshot and `assign` is ignored — a
    /// change keeps one handle while edited. When `working` is `None` (the first
    /// snapshot of a change `loot new` already minted a handle for), `assign`
    /// supplies that eagerly-minted id, so the durable handle printed at `new`
    /// is the same one that lands on the change's first version. `assign = None`
    /// with no working change mints a fresh id (or stays `None`, keyless).
    pub fn snapshot_assigning(
        &mut self,
        base: Option<&Oid>,
        working: Option<&Oid>,
        entries: &[(PathBuf, Vec<u8>, Visibility)],
        message: &str,
        now: u64,
        allow_demote: &[PathBuf],
        assign: Option<[u8; 16]>,
    ) -> Result<Oid, RepoError> {
        // Refuse implicit visibility demotion (#62) BEFORE mutating anything.
        // The "before" picture is the outgoing working tree when there is one —
        // it carries forward everything from base, and a working change is a
        // real change (it pushes) even though it was never finalized.
        let old_tree = match working {
            Some(w) => self.graph.tree_at(w),
            None => match base {
                Some(tip) => self.graph.tree_at(tip),
                None => self.graph.current_tree(),
            },
        };
        let mut demoted: Vec<String> = Vec::new();
        for (path, _, new_vis) in entries {
            if let Some((_, old_vis)) = old_tree.get(path) {
                if demotes(old_vis, new_vis) && !allow_demote.contains(path) {
                    demoted.push(path.display().to_string());
                }
            }
        }
        if !demoted.is_empty() {
            return Err(RepoError::Demotion { paths: demoted });
        }

        // Carry the durable change id across this re-snapshot (ADR 0029): the
        // version id will change, the change id must not. Read it BEFORE dropping
        // the prior working node below. When there is no working node, fall back
        // to `assign` — the handle `loot new` minted eagerly for this fresh
        // change (ADR 0030) — so the printed handle survives to the first version.
        // `None` on both lets `record` mint one.
        let carried_change_id = working
            .and_then(|w| self.graph.get(w).and_then(|n| n.change_id))
            .or(assign);
        // Carry the working node's `predecessors` too (ADR 0032): a reopened
        // change (`loot edit`) records "supersedes X" on its working node, and
        // every re-snapshot must keep that claim so the eventually finalized
        // version carries it. An ordinary working change carries the empty list.
        let carried_predecessors = working
            .and_then(|w| self.graph.get(w).map(|n| n.predecessors.clone()))
            .unwrap_or_default();

        // Drop the prior working change so we reconcile against finalized history,
        // not against our own last snapshot.
        if let Some(w) = working {
            self.graph.remove_head(w);
        }

        // `base` is the dock tip this snapshot forks from (ADR 0022): the new
        // change parents on it and reconciles against *its* line only. `None`
        // preserves the pre-dock behavior exactly — fork from every head and
        // merge their trees — so existing single-line repos are unaffected.
        let (base, parents) = match base {
            Some(tip) => (self.graph.tree_at(tip), vec![tip.clone()]),
            None => (self.graph.current_tree(), self.graph.heads()),
        };
        let by_path: BTreeMap<&PathBuf, &(PathBuf, Vec<u8>, Visibility)> =
            entries.iter().map(|e| (&e.0, e)).collect();

        // Refuse any write that lands on a base path we cannot open: it would
        // silently clobber sealed content we can't even see.
        for (path, (oid, _vis)) in &base {
            if by_path.contains_key(path) && self.get(oid, &self.identity, now).is_err() {
                return Err(RepoError::Backend(format!(
                    "sealed content exists at {}; cannot overwrite content you can't see",
                    path.display()
                )));
            }
        }

        let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();

        // Carry forward every base path NOT visible to us, untouched.
        for (path, entry) in &base {
            if self.get(&entry.0, &self.identity, now).is_err() {
                tree.insert(path.clone(), entry.clone());
            }
        }

        // Seal every working-tree entry (visible by construction — we read it).
        // Absent-but-visible base paths simply don't get re-added => deleted.
        //
        // Reuse the outgoing tree's oid when a path's plaintext AND visibility
        // are unchanged (#98): sealing mints a fresh key+nonce, so re-sealing
        // identical content gives it a new address, and every push ships the
        // whole repo instead of the delta. Reuse never mints or moves a key —
        // the object and its key are already held (we just opened it), and the
        // parent change already referenced this address — so ADR 0004's
        // no-plaintext-dedup stance is untouched: address equality here means
        // "same sealed object carried forward", never "equal plaintext
        // discovered". A path we cannot open *now* (e.g. still-embargoed)
        // re-seals fresh as before.
        for (path, bytes, vis) in entries {
            if let Some((old_oid, old_vis)) = old_tree.get(path) {
                if old_vis == vis
                    && self
                        .get(old_oid, &self.identity, now)
                        .is_ok_and(|old| old == *bytes)
                {
                    tree.insert(path.clone(), (old_oid.clone(), vis.clone()));
                    continue;
                }
            }
            let oid = self.put(bytes, vis.clone())?;
            tree.insert(path.clone(), (oid, vis.clone()));
        }

        let change = Change {
            id: Oid([0; 32]),
            parents,
            message: message.to_string(),
            tree,
        };
        self.record_superseding(change, carried_change_id, carried_predecessors)
    }
}

/// **History & identity face** (R3, #179): the change graph as data —
/// authorship and signatures (ADR 0018), durable change ids and divergence
/// (ADR 0029), per-change reads, attestations (S4), log shapes, and the
/// surface/materialize path that turns a tip back into a tree.
impl DagRepo {
    /// Set this repo's author pubkey (S3, ADR 0018): the workspace calls this
    /// after loading the identity keypair, so new changes fold the author into
    /// their id and can be signed at finalization. Left unset, changes stay
    /// unauthored (legacy ids) — keyless and pre-0018 repos keep working.
    pub fn set_author(&mut self, author: [u8; 32]) {
        self.author = Some(author);
    }

    /// This repo's author pubkey, if set.
    pub fn author(&self) -> Option<[u8; 32]> {
        self.author
    }

    /// Attach the author's signature to a finalized change (`loot new`). The
    /// signature covers the change id and is stored beside the node, so identity
    /// stays a pure function of authored content (ADR 0018). Errors if `id` is
    /// unknown to this repo.
    pub fn attach_signature(&mut self, id: &Oid, signature: [u8; 64]) -> Result<(), RepoError> {
        self.graph.set_signature(id, signature).ok_or_else(|| {
            RepoError::Backend(format!(
                "cannot sign unknown change {}",
                crate::hex::short(&id.0, 8)
            ))
        })
    }

    /// The author pubkey recorded on a change, if any (S3, ADR 0018). `None` for
    /// a legacy/unauthored change or an unknown id. Used by `loot log` to show
    /// authorship, reverse-resolved to a peer name.
    pub fn change_author(&self, id: &Oid) -> Option<[u8; 32]> {
        self.graph.get(id).and_then(|n| n.author)
    }

    /// The durable `change_id` recorded on a change (v6, ADR 0029), or `None`
    /// for a legacy/unauthored change or an unknown id. Finalization reads it to
    /// build the `version_id ‖ change_id` signing message.
    pub fn change_change_id(&self, id: &Oid) -> Option<[u8; 16]> {
        self.graph.get(id).and_then(|n| n.change_id)
    }

    /// Mint a fresh durable change id for the *next* change — but only when this
    /// repo is authored (has a keypair), matching `record`'s rule that an
    /// unsigned change gets no durable handle (ADR 0029). `loot new` calls this
    /// to eagerly hand the fresh change a handle from birth (ADR 0030); a keyless
    /// repo gets `None` and stays legacy.
    pub fn mint_next_change_id(&self) -> Option<[u8; 16]> {
        self.author.map(|_| mint_change_id())
    }

    /// Build the [`Liveness`] view for one operation (map #215, #216): the
    /// one home for live/superseded/divergent/parked and the head partition.
    /// The caller supplies the store-owned inputs — the local abandoned set
    /// and the sibling docks' parked working pointers (the Workspace's job);
    /// pass empty sets where they don't apply (ingest classification, tests
    /// without abandonment). The superseded scan runs once, here.
    pub fn liveness(
        &self,
        abandoned: &std::collections::BTreeSet<Oid>,
        parked: &[Oid],
    ) -> crate::Liveness {
        let nodes = self
            .graph
            .in_order()
            .into_iter()
            .map(|n| (n.id.clone(), n.change_id, n.predecessors.clone()))
            .collect();
        crate::Liveness::compute(nodes, abandoned.clone(), parked.iter().cloned().collect())
    }

    /// Drop a divergent version from this dock's **live heads** (S3, `loot
    /// abandon`): if `version` is a head, remove it and restore its parents as
    /// heads (reusing the working-change rewrite path). The node is *not* deleted
    /// from the object store or the shared graph file — it stops being a live head
    /// (and the caller also records it in the abandoned set for the case where it
    /// is a reachable non-head, e.g. a merge parent). Returns whether it was a
    /// head. Undo restores the head pointer and the abandoned set (ADR 0031).
    pub fn abandon_head(&mut self, version: &Oid) -> bool {
        let was_head = self.graph.heads().contains(version);
        if was_head {
            self.graph.remove_head(version);
        }
        was_head
    }

    /// The parents of a change, or empty if the id is unknown. Lets a caller find
    /// the finalized change a working change forks from — the anchor a dock sits
    /// on when its working change is finalized away (ADR 0022).
    pub fn parents_of(&self, id: &Oid) -> Vec<Oid> {
        self.graph.get(id).map(|n| n.parents.clone()).unwrap_or_default()
    }

    /// Whether any change in this dock's graph names `id` as a parent — the
    /// tip/childless guard for `loot edit` (ADR 0032): v1 refuses to amend a
    /// change with descendants (they'd keep building on the superseded tree).
    pub fn has_children(&self, id: &Oid) -> bool {
        self.graph.in_order().into_iter().any(|n| n.parents.contains(id))
    }

    /// Whether the line at `tip` carries a version that **supersedes** `version`
    /// (ADR 0032): some ancestor of `tip` (inclusive) with the same change id
    /// names `version` in its `predecessors`. This is the fork-collapse test —
    /// "their tip replaces ours" is only true when the replacement is actually
    /// on their line, not merely somewhere in the shared store.
    pub fn supersedes(&self, tip: &Oid, version: &Oid) -> bool {
        let Some(cid) = self.graph.get(version).and_then(|n| n.change_id) else {
            return false;
        };
        self.ancestors_of(tip).iter().any(|a| {
            self.graph
                .get(a)
                .is_some_and(|n| n.change_id == Some(cid) && n.predecessors.contains(version))
        })
    }

    /// The versions a change supersedes (v7, ADR 0032), or empty if unknown —
    /// the finalize paths sign over these alongside the two ids.
    pub fn change_predecessors(&self, id: &Oid) -> Vec<Oid> {
        self.graph.get(id).map(|n| n.predecessors.clone()).unwrap_or_default()
    }

    /// Reopen finalized version `version` as a fresh **working change** that
    /// supersedes it (`loot edit`, ADR 0032): a *sibling* node — parents =
    /// `version`'s parents (clean parentage, never a child of its own prior
    /// version), tree = `version`'s tree carried address-for-address (no
    /// re-sealing), change id carried, and `predecessors = [version]` so the
    /// replacement travels as signed data once finalized. The prior version is
    /// untouched (ADR 0018). The caller guards liveness/divergence/descendants
    /// and cleanliness — this is just the reopen. Errors on an unknown version.
    pub fn reopen_change(&mut self, version: &Oid) -> Result<Oid, RepoError> {
        let node = self
            .graph
            .get(version)
            .ok_or_else(|| RepoError::NotFound(version.clone()))?;
        let (parents, message, tree, cid) =
            (node.parents.clone(), node.message.clone(), node.tree.clone(), node.change_id);
        let change = Change { id: Oid([0; 32]), parents, message, tree };
        self.record_superseding(change, cid, vec![version.clone()])
    }

    /// A change's message, or `None` if unknown. Lets an auto-snapshot preserve
    /// the working change's description instead of overwriting it (ADR 0022).
    pub fn change_message(&self, id: &Oid) -> Option<String> {
        self.graph.get(id).map(|n| n.message.clone())
    }

    /// The author's signature on a change, if attached (S3, ADR 0018). `None`
    /// for an in-progress working change, a legacy/unauthored change, or an
    /// unknown id. The bridge uses this both to carry the signature in a commit
    /// trailer and to skip ephemeral (authored-but-unsigned) changes — the same
    /// "only signed history travels" rule push/bundle apply (GB1, ADR 0028).
    pub fn change_signature(&self, id: &Oid) -> Option<[u8; 64]> {
        self.graph.get(id).and_then(|n| n.signature)
    }

    /// A change's full tree (path -> content address + visibility), or `None`
    /// if unknown. Each finalized change records its complete tree (deletion =
    /// absence), so this is exactly the tree a mirrored commit projects
    /// (GB1, ADR 0028).
    pub fn change_tree(&self, id: &Oid) -> Option<BTreeMap<PathBuf, (Oid, Visibility)>> {
        self.graph.get(id).map(|n| n.tree.clone())
    }

    /// Every change id in the graph, parents before children — the projection
    /// order for the git bridge (GB1, ADR 0028): a change's parents are always
    /// mapped to commits before the change itself is.
    pub fn change_ids_topo(&self) -> Vec<Oid> {
        self.graph.in_order().into_iter().map(|n| n.id.clone()).collect()
    }

    /// Record a change as *unauthored* (legacy id, no author folded in), even
    /// when this repo has an author set. The bridge ingests a git-native commit
    /// whose author is not the syncing identity this way — loot never forges
    /// another identity's authorship (GB1, ADR 0028). Unauthored changes travel
    /// unsigned, exactly like pre-0018 history.
    /// Record a change, optionally *carrying* an existing durable `change_id`
    /// across a re-snapshot (ADR 0029): the version id is recomputed from content
    /// as always, but the change id is preserved so a working change keeps one
    /// stable handle while it is edited. `carried = None` begins a fresh change —
    /// minting a new random change id when authored, or staying `None` for a
    /// keyless repo (an unsigned change gets no durable handle, matching legacy).
    ///
    /// Public because it is the **amend primitive**: recording two versions that
    /// carry the same `change_id` on independent lines is exactly how a divergent
    /// change (S3, ADR 0029) comes to exist — two writers rewriting one change id.
    /// The snapshot path uses it to carry a working change's handle; a future
    /// edit-a-published-change flow (and today's divergence tests) use it directly.
    pub fn record_carrying(
        &mut self,
        change: Change,
        carried: Option<[u8; 16]>,
    ) -> Result<Oid, RepoError> {
        self.record_superseding(change, carried, Vec::new())
    }

    /// `record_carrying` that also names the versions this one **supersedes**
    /// (v7, ADR 0032) — the general form behind `loot edit`: the reopened
    /// working change carries the edited change's handle AND a `predecessors`
    /// entry naming its version, and every re-snapshot carries both forward.
    /// Predecessors are stored canonically (sorted, deduped) and folded into
    /// the version id, so a no-op amend still mints a distinct version.
    pub fn record_superseding(
        &mut self,
        change: Change,
        carried: Option<[u8; 16]>,
        predecessors: Vec<Oid>,
    ) -> Result<Oid, RepoError> {
        // Fold this repo's author pubkey (if set) into the id, so authorship is
        // intrinsic (ADR 0018). The signature is attached later, at finalization
        // (`attach_signature`), not on every working-change rewrite.
        let predecessors = change_graph::canonical_predecessors(&predecessors);
        let id = compute_change_id(self.author.as_ref(), &change, &predecessors);
        let change_id = match carried {
            Some(cid) => Some(cid),
            None => self.author.map(|_| mint_change_id()),
        };
        let node = ChangeNode {
            id: id.clone(),
            parents: change.parents,
            message: change.message,
            tree: change.tree,
            author: self.author,
            signature: None,
            change_id,
            predecessors,
        };
        self.graph.insert(node);
        Ok(id)
    }

    pub fn record_unauthored(&mut self, change: Change) -> Result<Oid, RepoError> {
        let id = compute_change_id(None, &change, &[]);
        let node = ChangeNode {
            id: id.clone(),
            parents: change.parents,
            message: change.message,
            tree: change.tree,
            author: None,
            signature: None,
            // Unauthored (bridge-ingested) changes carry no durable handle: an
            // unsigned change gets none, and whether the git bridge should mint
            // or map one is deferred fog (ADR 0028/0029). They likewise carry
            // no predecessors (ADR 0032).
            change_id: None,
            predecessors: Vec::new(),
        };
        self.graph.insert(node);
        Ok(id)
    }

    /// Drop an unfinalized working change from the graph — the bridge undoes a
    /// capture snapshot that turned out identical to the anchor (GB1, ADR
    /// 0028). The node was never signed, so nothing that travels references
    /// it; `remove_head` restores its parents as heads. No-op otherwise.
    pub fn drop_working(&mut self, id: &Oid) {
        self.graph.remove_head(id);
    }

    /// Whether two changes hold identical trees by *content*: same paths and
    /// visibilities, and per path either the same sealed address or equal
    /// plaintext this identity can open. Sealing mints a fresh key+nonce per
    /// write (#98), so address equality alone cannot see that two separately
    /// recorded changes carry the same bytes — exactly the bridge's case,
    /// where a capture snapshot and an ingested commit both seal the same
    /// pulled content (GB1, ADR 0028). An unopenable pair counts as different,
    /// as is an unknown change id.
    ///
    /// Judges the two changes' **recorded manifests** (each change carries its
    /// complete tree, deletion = absence — [`Self::change_tree`]). `tree_at`
    /// used to build an ancestry-union overlay that kept an ancestor's entry
    /// for a path the child deleted, so a deletion-only change compared
    /// identical to its parent — which silently dropped a described
    /// deletion-only working change at finalize (#289). #288 retired the
    /// overlay (`tree_at` IS the manifest now); reading the nodes directly
    /// here keeps the judgment self-evidently deletion-aware.
    pub fn same_tree_content(&self, a: &Oid, b: &Oid, now: u64) -> bool {
        let (Some(na), Some(nb)) = (self.graph.get(a), self.graph.get(b)) else {
            return false;
        };
        let (ta, tb) = (&na.tree, &nb.tree);
        if ta.len() != tb.len() {
            return false;
        }
        for (path, (oa, va)) in ta {
            let Some((ob, vb)) = tb.get(path) else {
                return false;
            };
            if va != vb {
                return false;
            }
            if oa == ob {
                continue;
            }
            let (Ok(ba), Ok(bb)) =
                (self.get(oa, &self.identity, now), self.get(ob, &self.identity, now))
            else {
                return false;
            };
            if ba != bb {
                return false;
            }
        }
        true
    }

    /// Count `(total, restricted, embargoed)` paths in a tip's tree — the
    /// visibility summary `loot docks` shows per dock (ADR 0022).
    pub fn visibility_summary_at(&self, tip: &Oid) -> (usize, usize, usize) {
        let tree = self.graph.tree_at(tip);
        let total = tree.len();
        let mut restricted = 0;
        let mut embargoed = 0;
        for (_, vis) in tree.values() {
            match vis {
                Visibility::Restricted(_) => restricted += 1,
                Visibility::Embargoed { .. } => embargoed += 1,
                Visibility::Public => {}
            }
        }
        (total, restricted, embargoed)
    }

    /// Merge finalized tip `theirs` into finalized tip `ours`, producing a merge
    /// change parented on both (CA2, ADR 0022/0001). Docks share one object store
    /// and graph, so this is a local fork collapse — no relay, no bundle. The new
    /// change's tree is the ADR 0001 reconciliation of the two lines
    /// ([`converge::merge_trees`]): converged/cleanly-merged paths take the other
    /// (or superset) side, genuine same-path divergences keep *ours* and are
    /// recorded as conflicts (theirs stays reachable via the second parent, for
    /// `loot resolve`), and sealed paths we cannot open are carried forward.
    ///
    /// Reuses the shared convergence rule; adds none. The change is returned
    /// unsigned — the caller finalizes (signs) it, as loot-core stays verify-only
    /// for signatures (ADR 0018). Returns `(merge change id, per-path outcomes)`.
    pub fn merge_tips(
        &mut self,
        ours: &Oid,
        theirs: &Oid,
        message: &str,
        now: u64,
    ) -> Result<(Oid, BTreeMap<PathBuf, MergeOutcome>), RepoError> {
        let our_tree = self.graph.tree_at(ours);
        let their_tree = self.graph.tree_at(theirs);
        // The two tips share a graph, so the merge base is the nearest common
        // ancestor — it keeps a stale side's untouched paths from classifying
        // as conflicts (#65).
        let base_tree = self.graph.common_ancestor_tree(ours, theirs);
        let merged = converge::merge_trees(&our_tree, &their_tree, base_tree.as_ref(), self, now);
        // Record conflicts so `loot conflicts`/`loot resolve` see them, exactly
        // as the apply path does.
        for (path, (o, t)) in &merged.conflicts {
            self.conflicts.insert(path.clone(), (o.clone(), t.clone()));
        }
        let change = Change {
            id: Oid([0; 32]),
            parents: vec![ours.clone(), theirs.clone()],
            message: message.to_string(),
            tree: merged.tree,
        };
        let id = self.record(change)?;
        Ok((id, merged.outcomes))
    }

    /// Verify and record an attestation over a change (S4, ADR 0018). Returns
    /// `true` if it verified and was stored, `false` if the signature was invalid
    /// (dropped — an attestation is advisory and never fatal). Attestations never
    /// affect a change id or convergence.
    pub fn add_attestation(&mut self, att: Attestation) -> bool {
        let ok = att.verify();
        if ok {
            self.attestations.insert(att);
        }
        ok
    }

    /// Attestations recorded over a change, for display (`loot log`/`manifest`).
    pub fn attestations_for(&self, change_id: &Oid) -> Vec<&Attestation> {
        self.attestations.for_change(change_id)
    }

    /// Every recorded attestation, for `loot manifest` display.
    pub fn all_attestations(&self) -> Vec<&Attestation> {
        self.attestations.iter().collect()
    }

    /// Change history in topo order (parents before children), as
    /// `(change id, message)` pairs — the data a `log` command needs without
    /// exposing the change graph's internals.
    pub fn log(&self) -> Vec<(Oid, String)> {
        self.graph
            .in_order()
            .into_iter()
            .map(|c| (c.id.clone(), c.message.clone()))
            .collect()
    }

    /// Like `log`, but also returns per-change file counts by visibility class.
    /// Returns `(id, message, total_files, restricted_files, embargoed_files)`.
    pub fn log_detailed(&self) -> Vec<(Oid, String, usize, usize, usize)> {
        self.graph
            .in_order()
            .into_iter()
            .map(|c| {
                let total = c.tree.len();
                let restricted = c.tree.values()
                    .filter(|(_, v)| matches!(v, Visibility::Restricted(_)))
                    .count();
                let embargoed = c.tree.values()
                    .filter(|(_, v)| matches!(v, Visibility::Embargoed { .. }))
                    .count();
                (c.id.clone(), c.message.clone(), total, restricted, embargoed)
            })
            .collect()
    }

    /// Whether a change's full tree (the same one `log_detailed` sizes)
    /// includes `path` — the predicate `loot log --path` filters on (#6).
    /// `false` for an unknown version id, exactly like an absent path.
    pub fn change_has_path(&self, id: &Oid, path: &Path) -> bool {
        self.graph.get(id).is_some_and(|c| c.tree.contains_key(path))
    }

    /// The live, non-durable **version id** for a working tree, plus whether it
    /// is **empty** (no delta vs `tip`) — the figure read-only `status`/`log`
    /// show for the working change (ADR 0030). Computed WITHOUT sealing or
    /// recording: the would-be tree addresses each path by the blake3 of its
    /// *current plaintext*, so the id is deterministic and moves iff
    /// content/visibility/message move, yet no object is written and the graph
    /// is untouched. It deliberately does **not** equal the sealed version id a
    /// later snapshot persists (sealing mints fresh keys per write, #98) — it is
    /// a "content right now" fingerprint, and the only holdable handle for the
    /// working change is its durable change id.
    ///
    /// Emptiness is judged against `tip`'s *openable* recorded manifest: the
    /// working change is empty when every live entry matches a tip path by
    /// plaintext + visibility and nothing openable was added or removed. Sealed
    /// tip paths this identity cannot read carry forward untouched and are not
    /// this caller's pending delta, so they are ignored. With no `tip`, empty
    /// means no files at all. The tip's own manifest — the pre-#288 `tree_at`
    /// ancestry overlay resurrected paths an ancestor held but the tip
    /// deleted, and would have read a clean tree as dirty forever after a
    /// deletion landed (#289).
    pub fn working_preview(
        &self,
        tip: Option<&Oid>,
        entries: &[(PathBuf, Vec<u8>, Visibility)],
        message: &str,
        now: u64,
    ) -> (Oid, bool) {
        let plain = |bytes: &[u8]| Oid(*blake3::hash(bytes).as_bytes());
        let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();
        for (path, bytes, vis) in entries {
            tree.insert(path.clone(), (plain(bytes), vis.clone()));
        }
        let parents = match tip {
            Some(t) => vec![t.clone()],
            None => self.graph.heads(),
        };
        let change = Change {
            id: Oid([0; 32]),
            parents,
            message: message.to_string(),
            tree: tree.clone(),
        };
        // The preview fingerprint ignores predecessors: it hashes "content right
        // now", and the durable handle — not this id — is the working change's
        // name (ADR 0030). A reopened change's preview moving on edit is enough.
        let version = compute_change_id(self.author.as_ref(), &change, &[]);

        let empty = match tip {
            Some(t) => {
                let tip_tree =
                    self.graph.get(t).map(|n| n.tree.clone()).unwrap_or_default();
                let mut openable: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();
                for (path, (oid, vis)) in &tip_tree {
                    if let Ok(bytes) = self.get(oid, &self.identity, now) {
                        openable.insert(path.clone(), (plain(&bytes), vis.clone()));
                    }
                }
                openable == tree
            }
            None => entries.is_empty(),
        };
        (version, empty)
    }

    /// All ancestors of `id` (including `id` itself), by walking parent edges.
    /// Used to compute head reachability for multi-head `log` display.
    fn ancestors_of(&self, id: &Oid) -> BTreeSet<Oid> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![id.clone()];
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(node) = self.graph.get(&cur) {
                for p in &node.parents {
                    stack.push(p.clone());
                }
            }
        }
        seen
    }

    /// Structured history for multi-head `log` (issue #18). Reports the current
    /// heads (ascending) and, per change, which heads can reach it — enough for
    /// a caller to show branch structure when peers have diverged. Changes are
    /// returned children-first (reverse topo), so a head precedes its ancestors.
    ///
    /// This is independent of head count; the CLI keeps its flat rendering when
    /// there is a single head and only switches to a branch view for two or more.
    pub fn log_graph(&self) -> LogGraph {
        let mut heads = self.graph.heads();
        heads.sort();

        // For each head, mark every ancestor as reachable from that head index.
        let mut reach: BTreeMap<Oid, Vec<usize>> = BTreeMap::new();
        for (hi, head) in heads.iter().enumerate() {
            for anc in self.ancestors_of(head) {
                reach.entry(anc).or_default().push(hi);
            }
        }

        // Children-first: reverse the parents-first topo order.
        let changes = self
            .graph
            .in_order()
            .into_iter()
            .rev()
            .map(|c| LogNode {
                id: c.id.clone(),
                message: c.message.clone(),
                reachable_from: reach.get(&c.id).cloned().unwrap_or_default(),
            })
            .collect();

        LogGraph { heads, changes }
    }

    /// Like `surface`, but also returns the list of materialized paths and their
    /// visibility, plus a count of skipped (sealed) paths. Lets the CLI report
    /// what was written without a second pass.
    pub fn surface_with_report(
        &self,
        change: &Oid,
        reader: &str,
        now: u64,
    ) -> Result<(Vec<(PathBuf, Visibility)>, usize), RepoError> {
        let node = self
            .graph
            .get(change)
            .ok_or_else(|| RepoError::NotFound(change.clone()))?;

        let mut written: Vec<(PathBuf, Visibility)> = Vec::new();
        let mut skipped = 0usize;

        for (path, (oid, vis)) in &node.tree {
            // Grant expiry gate (#20) — see the trait `surface`'s twin check.
            if self.grant_expired_for(oid, reader, now) {
                skipped += 1;
                continue;
            }
            let bytes = match self.get(oid, reader, now) {
                Ok(b) => b,
                Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => {
                    skipped += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };
            let dest = self.root.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
            }
            std::fs::write(&dest, &bytes).map_err(|e| RepoError::Backend(e.to_string()))?;
            written.push((path.clone(), vis.clone()));
        }

        Ok((written, skipped))
    }

    /// Paths at `tip` whose content `reader` can open now — the change's own tree
    /// (exactly what [`surface`] would write) minus anything sealed or embargoed
    /// against this reader. This is the set a dock switch may prune from disk, so
    /// it must match what `surface` put there (ADR 0022). Unknown tip => empty.
    ///
    /// [`surface`]: DagRepo::surface_with_report
    pub fn visible_paths_at(&self, tip: &Oid, reader: &str, now: u64) -> Vec<PathBuf> {
        let Some(node) = self.graph.get(tip) else {
            return Vec::new();
        };
        node.tree
            .iter()
            .filter(|(_, (oid, _))| {
                // Grant expiry gate (#20) — must match `surface`'s twin check,
                // or a dock switch could leave an expired-grant path materialized.
                !self.grant_expired_for(oid, reader, now) && self.get(oid, reader, now).is_ok()
            })
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Reconcile the working tree from one dock tip to another (dock switch, ADR
    /// 0022): write `to`'s visible content, then remove files that were visible
    /// under `from` but are gone in `to`. Content the reader cannot see is never
    /// touched — sealed data lives in `.loot/` as ciphertext, not as a plaintext
    /// file — so pruning is scoped to loot-managed, visible paths only. Callers
    /// must auto-snapshot the outgoing dock first, which makes every pruned file
    /// recoverable by switching back.
    pub fn materialize(
        &self,
        from: Option<&Oid>,
        to: &Oid,
        reader: &str,
        now: u64,
    ) -> Result<(Vec<(PathBuf, Visibility)>, usize), RepoError> {
        let (written, skipped) = self.surface_with_report(to, reader, now)?;
        let keep: std::collections::BTreeSet<&PathBuf> = written.iter().map(|(p, _)| p).collect();
        if let Some(from) = from {
            for path in self.visible_paths_at(from, reader, now) {
                if keep.contains(&path) {
                    continue;
                }
                let dest = self.root.join(&path);
                let _ = std::fs::remove_file(&dest);
                // Best-effort: drop parent dirs that this removal left empty, up to
                // (never including) the repo root. `remove_dir` only deletes empty
                // dirs, so a still-populated dir is a harmless error we ignore.
                let mut dir = dest.parent().map(Path::to_path_buf);
                while let Some(d) = dir {
                    if d == self.root || std::fs::remove_dir(&d).is_err() {
                        break;
                    }
                    dir = d.parent().map(Path::to_path_buf);
                }
            }
        }
        Ok((written, skipped))
    }

    /// Load a repo previously written by [`save`] from `dir`. `root` is the
    /// working directory `surface` will materialize into (kept separate from
    /// `dir` so the store can live in `.loot/` while files land in the repo).
    pub fn load(dir: &std::path::Path, root: PathBuf) -> Result<Self, RepoError> {
        Self::load_from(&RepoStore::new(dir), root)
    }

    /// Dock-aware load (CA1.5, ADR 0022). Reads the shared node store and this
    /// dock's per-dock lineage state, then materializes only the subgraph
    /// reachable from *this dock's heads* — so `current_tree`/`surface`/
    /// `snapshot` see the dock's lineage and nothing else, with no change to
    /// their logic. A repo predating per-dock heads has no `heads` file; we then
    /// treat the whole shared graph as the default dock's lineage (back-compat).
    pub fn load_from(store: &RepoStore, root: PathBuf) -> Result<Self, RepoError> {
        let io = |e: std::io::Error| RepoError::Backend(e.to_string());
        let identity = String::from_utf8(read_replaced(&store.identity()).map_err(io)?)
            .map_err(|e| RepoError::Backend(e.to_string()))?;
        let objects = persist_codec::load_objects_loose(&store.objects_dir())?;

        // Build the candidate node pool: shared finalized nodes plus this dock's
        // own working change (which lives outside the shared graph).
        let mut pool: BTreeMap<Oid, ChangeNode> = BTreeMap::new();
        for node in persist_codec::decode_nodes(&read_replaced(&store.graph()).map_err(io)?)? {
            pool.insert(node.id.clone(), node);
        }
        if let Some(blob) = store.read_working_change() {
            for node in persist_codec::decode_nodes(&blob)? {
                pool.insert(node.id.clone(), node);
            }
        }
        // Heads are authoritative when present; otherwise (legacy repo) the whole
        // pool is the default dock's lineage.
        let heads = store
            .read_heads()
            .unwrap_or_else(|| ChangeGraph::derive_all_heads(&pool));
        let graph = ChangeGraph::reachable_from(&pool, &heads);

        let keyring = persist_codec::decode_keyring(&read_replaced(&store.keyring()).map_err(io)?)?;
        // Escrow file may not exist in repos created before ADR 0007 — default empty.
        let escrow = match read_replaced(&store.escrow()) {
            Ok(b) => persist_codec::decode_escrow(&b)?,
            Err(_) => Escrow::new(),
        };
        let manifest = match read_replaced(&store.manifest()) {
            Ok(b) => decode_manifest(&b)?,
            Err(_) => Manifest::new(),
        };
        let purges = match read_replaced(&store.purges()) {
            Ok(b) => decode_purges(&b)?,
            Err(_) => Vec::new(),
        };
        let conflicts = match read_replaced(&store.conflicts()) {
            Ok(b) => decode_conflicts(&b)?,
            Err(_) => BTreeMap::new(),
        };
        // Attestations file may not exist in repos created before S4 — default empty.
        let attestations = match read_replaced(&store.attestations()) {
            Ok(b) => decode_attestations(&b)?,
            Err(_) => AttestationLog::new(),
        };
        Ok(DagRepo {
            root,
            identity,
            author: None,
            custody: Custody { keyring, escrow, manifest, purges },
            objects,
            graph,
            conflicts,
            attestations,
        })
    }
}

impl Repo for DagRepo {
    fn init(path: PathBuf, identity: &str) -> Result<Self, RepoError> {
        Ok(DagRepo {
            root: path,
            identity: identity.to_string(),
            author: None,
            custody: Custody::new(),
            objects: ObjectStore::new(),
            graph: ChangeGraph::new(),
            conflicts: BTreeMap::new(),
            attestations: AttestationLog::new(),
        })
    }

    fn put(&mut self, bytes: &[u8], vis: Visibility) -> Result<Oid, RepoError> {
        let (addr, obj, key) = sealed::seal(bytes, &vis)?;
        // We minted the key, so we file it (entitlement is enforced in `store`).
        Ok(self.store(addr, obj, Some(key)))
    }

    fn get(&self, oid: &Oid, reader: &str, now: u64) -> Result<Vec<u8>, RepoError> {
        let obj = self.object(oid)?;
        sealed::open(obj, oid, reader, &self.custody.keyring, now)
    }

    /// Record a change over the current set of put() objects, beginning a fresh
    /// change: it mints a new durable `change_id` when this repo is authored
    /// (ADR 0029). A re-snapshot that must *carry* an existing change id calls
    /// the inherent `record_carrying` instead.
    fn record(&mut self, change: Change) -> Result<Oid, RepoError> {
        self.record_carrying(change, None)
    }

    /// Materialize the tree of `change` to the working area, skipping
    /// content `reader` cannot see (ADR 0006).
    fn surface(&self, change: &Oid, reader: &str, now: u64) -> Result<(), RepoError> {
        let node = self
            .graph
            .get(change)
            .ok_or_else(|| RepoError::NotFound(change.clone()))?;

        for (path, (oid, _vis)) in &node.tree {
            // Grant expiry gate (#20), checked before the key/visibility gate:
            // skip a path whose grant to this reader has expired, even though
            // the key may still sit in the keyring (defense-in-depth, parallel
            // to embargo).
            if self.grant_expired_for(oid, reader, now) {
                continue;
            }
            // Materialize only the visible slice: skip content this reader
            // cannot see rather than erroring on it.
            let bytes = match self.get(oid, reader, now) {
                Ok(b) => b,
                Err(RepoError::Unauthorized(_)) | Err(RepoError::Embargoed(_)) => continue,
                Err(e) => return Err(e),
            };
            let dest = self.root.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RepoError::Backend(e.to_string()))?;
            }
            std::fs::write(&dest, &bytes).map_err(|e| RepoError::Backend(e.to_string()))?;
        }
        Ok(())
    }

    fn bundle(&self, have: &[Oid]) -> Result<SyncBundle, RepoError> {
        // Full bundle: ship every object referenced by the sent changes.
        self.bundle_impl(have, None)
    }

    fn apply(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        // The bake-off trait keeps its frozen shape; a keyholder CLI applies
        // through [`DagRepo::apply_with`] so the local abandoned set reaches
        // ingest classification (#216). No-abandonment callers (bench, tests,
        // relay-adjacent flows) are exactly the empty-set case.
        self.apply_with(bundle, now, &std::collections::BTreeSet::new())
    }

    fn heads(&self) -> Vec<Oid> {
        self.graph.heads()
    }

    fn flush_embargo(&mut self, now: u64) {
        self.flush_escrow(now);
    }
}

/// **Sync-negotiation face** (R3, #179): the wire conversation — what we'd
/// offer, what we lack, and the batched bundles for a want set (S5/S6,
/// ADR 0021/0024). The 9-method `Repo` trait above is the narrow generic face
/// loot-net and the bench consume; this is its object-level negotiation twin.
impl DagRepo {
    /// [`Repo::apply`] with the caller's local abandoned set (#216): ingest
    /// classification consults the [`Liveness`](crate::Liveness) view, so an
    /// incoming co-version of a locally-abandoned version is not
    /// divergence-forming and classifies normally. This is the keyholder
    /// CLI's apply — the Workspace passes `.loot/abandoned` through; the
    /// bake-off trait's `apply` delegates here with the empty set.
    pub fn apply_with(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
        abandoned: &std::collections::BTreeSet<Oid>,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        // One decode, then dispatch on the typed frame. A relay would call `stow`
        // instead and skip the merge. Sealed-key grants (tag 3) need the caller's
        // unseal closure, so they go through `apply_sealed_grant`, not here.
        match Frame::decode(&bundle.0)? {
            Frame::Sync { purges, body } => self.apply_sync(purges, body, now, abandoned),
            Frame::Grant { grantee, body } => {
                let BundleBody { objs, keys, .. } = body;
                // Install objects and, if the grant is addressed to us, its keys.
                for (addr, obj) in objs {
                    let key = keys.get(&addr).copied();
                    // Store the object (may dedup). For grant bundles targeted to us,
                    // file the key directly into the keyring — dedup does not block key
                    // custody since the key is the grant payload, not derived from storage.
                    self.store(addr.clone(), obj, None);
                    if grantee == self.identity {
                        if let Some(k) = key {
                            if !self.custody.keyring.holds(&addr) {
                                self.custody.keyring.insert(addr, k);
                            }
                        }
                    }
                }
                Ok(BTreeMap::new())
            }
            Frame::SealedGrant { .. } => Err(RepoError::Backend(
                "sealed-key grant bundle (tag 3) must be applied via apply_sealed_grant".into(),
            )),
        }
    }

    /// Returns `true` if the repo has any authored-but-unsigned change (a working
    /// change the author has not yet signed). Such changes are excluded from
    /// bundles (ADR 0018), so a push while one exists silently transfers nothing.
    pub fn has_unsigned_tip(&self) -> bool {
        self.graph
            .in_order()
            .into_iter()
            .any(is_working_change)
    }

    /// Object addresses in the closure of the changes this repo would send for
    /// `have` — the objects a recipient may be missing (S5). Only addresses of
    /// objects we actually hold are offered. Zero-knowledge: addresses only,
    /// never keys or plaintext (the relay already sees content addresses).
    pub fn offered_objects(&self, have: &[Oid]) -> Vec<Oid> {
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let mut addrs: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        for c in self.graph.in_order() {
            if have_set.contains(&c.id) || is_working_change(c) {
                continue;
            }
            for (oid, _vis) in c.tree.values() {
                if self.object(oid).is_ok() {
                    addrs.insert(oid.clone());
                }
            }
        }
        addrs.into_iter().collect()
    }

    /// The heads a pull should NEGOTIATE with (#217): heads whose own full
    /// tree's objects are all present locally. An interrupted batched pull
    /// (S6, ADR 0024) ingests change nodes before all their object bytes
    /// arrive; claiming such a head as `have` makes the relay skip the very
    /// changes whose objects we still lack — the pull could then never
    /// complete (offer returns nothing). Excluding incomplete heads makes the
    /// relay re-offer their closure, so re-pulling fetches exactly the
    /// remainder (change re-insertion is idempotent).
    pub fn negotiation_have(&self) -> Vec<Oid> {
        self.graph
            .heads()
            .into_iter()
            .filter(|h| self.closure_complete(h))
            .collect()
    }

    /// Whether this repo holds every object in `id`'s whole reachable CLOSURE,
    /// not just its own tree: batch order is address order, so a historical
    /// object of an ancestor can be the one still missing while the tip's tree
    /// happens to be whole. `false` means a transfer is still mid-flight (an
    /// interrupted pull ingested the change node before all its object bytes,
    /// S6/ADR 0024) — the working tree is not yet a materialization of `id`.
    pub fn closure_complete(&self, id: &Oid) -> bool {
        self.ancestors_of(id).iter().all(|a| {
            self.graph
                .tree_at(a)
                .values()
                .all(|(oid, _vis)| self.object(oid).is_ok())
        })
    }

    /// The subset of `offered` addresses this repo does NOT already hold — the
    /// "wants" a receiver replies with (S5).
    pub fn missing_objects(&self, offered: &[Oid]) -> Vec<Oid> {
        offered
            .iter()
            .filter(|oid| self.object(oid).is_err())
            .cloned()
            .collect()
    }

    /// A sync bundle for `have` whose object *bytes* are limited to `wants` (S5).
    /// Changes, keys, escrow, and attestations ride as in a normal bundle (they
    /// are tiny); only the negotiated object ciphertext is filtered, so a peer
    /// never re-downloads objects it already holds.
    pub fn bundle_wanted(&self, have: &[Oid], wants: &[Oid]) -> Result<SyncBundle, RepoError> {
        let wants_set: std::collections::BTreeSet<Oid> = wants.iter().cloned().collect();
        self.bundle_impl(have, Some(&wants_set))
    }

    /// Split `wants` into batches and produce one `SyncBundle` per batch (S6).
    ///
    /// The change delta, keys, escrow, and attestations are computed once via
    /// `bundle_impl`; only the object subset differs per batch. When `wants` is
    /// empty one bundle is returned (carrying the change delta and attestations
    /// with no object bytes) so the caller always makes at least one round-trip
    /// to propagate metadata.
    ///
    /// A batch closes at `batch_size` objects (resume granularity, ADR 0024) or
    /// when its object ciphertext would exceed `batch_bytes` (#309: a relay
    /// buffers the whole request body, so a batch must stay under its body
    /// limit). Byte accounting is ciphertext-only — the per-bundle change
    /// delta and framing ride on top, so callers pick `batch_bytes` with
    /// headroom below the transport limit. An object larger than the whole
    /// budget still ships, alone in its own bundle: the cap bounds packing,
    /// it never wedges a transfer.
    pub fn bundle_wanted_batched(
        &self,
        have: &[Oid],
        wants: &[Oid],
        batch_size: usize,
        batch_bytes: usize,
    ) -> Result<Vec<SyncBundle>, RepoError> {
        if wants.is_empty() {
            // One metadata-only bundle: change delta + attestations, no objects.
            return Ok(vec![self.bundle_impl(have, Some(&Default::default()))?]);
        }
        // Pre-partition objects across all batches in one pass over the wants list,
        // then build each bundle independently. This avoids iterating all_objects
        // once per batch (which would be O(total_objects × num_batches)).
        let mut batches: Vec<std::collections::BTreeSet<Oid>> = Vec::new();
        let mut cur: std::collections::BTreeSet<Oid> = Default::default();
        let mut cur_bytes = 0usize;
        for oid in wants {
            // An address we do not hold contributes no bytes; bundle_impl skips
            // it anyway, so it costs nothing to carry in a batch set.
            let size = self.object(oid).map(|o| o.ciphertext.len()).unwrap_or(0);
            if !cur.is_empty() && (cur.len() >= batch_size || cur_bytes + size > batch_bytes) {
                batches.push(std::mem::take(&mut cur));
                cur_bytes = 0;
            }
            cur.insert(oid.clone());
            cur_bytes += size;
        }
        if !cur.is_empty() {
            batches.push(cur);
        }
        batches
            .iter()
            .map(|batch_set| self.bundle_impl(have, Some(batch_set)))
            .collect()
    }

    /// Shared bundle builder. `wants = None` ships every referenced object;
    /// `wants = Some(set)` ships only those object *bytes* (S5 negotiation).
    fn bundle_impl(
        &self,
        have: &[Oid],
        wants: Option<&std::collections::BTreeSet<Oid>>,
    ) -> Result<SyncBundle, RepoError> {
        // Changes reachable here but not already known to the recipient. For
        // now, "reachable-not-have" = every change id not in `have`.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            // Skip changes the recipient has, and any authored-but-unsigned
            // working change: only finalized, signed history travels (ADR 0018).
            // Legacy unauthored changes still travel, so keyless repos are unaffected.
            .filter(|c| !have_set.contains(&c.id) && !is_working_change(c))
            .collect();

        // Ship SealedObjects (ciphertext, no keys) plus:
        //   - Public content keys -> plain keyring section (ANYONE-granted, not embargoed)
        //   - Embargoed content keys NEVER ride in a bundle (ADR 0027, v5): they
        //     reach peers only as relay-withheld timed SealedGrants after
        //     reveal_at. Ciphertext still syncs; the key lane is the relay.
        //   - Restricted keys NEVER travel (ADR 0003)
        let mut needed: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        for c in &send {
            for (oid, vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    // Object bytes: when negotiating (S5), ship only wanted addrs;
                    // keys below always ride (tiny, and a peer may hold the
                    // ciphertext but not the key).
                    if wants.map_or(true, |w| w.contains(oid)) {
                        needed.entry(oid.clone()).or_insert_with(|| obj.clone());
                    }
                    if obj.grant_ids.iter().any(|g| g == ANYONE)
                        && !matches!(vis, Visibility::Embargoed { .. })
                    {
                        if let Some(k) = self.custody.keyring.key_for(oid) {
                            public_keys.insert(oid.clone(), k);
                        }
                    }
                }
            }
        }

        // Only ship attestations for changes actually in this bundle's send set
        // (#42/#48). An attestation for a change the recipient is not receiving
        // would leak that change's existence and its reviewers, so attestations
        // ride strictly with their change.
        let sent_ids: std::collections::BTreeSet<&Oid> = send.iter().map(|c| &c.id).collect();
        let attestations: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| sent_ids.contains(&a.change_id))
            .cloned()
            .collect();

        let body = BundleBody {
            changes: send.into_iter().cloned().collect(),
            objs: needed,
            keys: public_keys,
            attestations,
        };
        Ok(SyncBundle(Frame::Sync { purges: self.custody.purges.clone(), body }.encode()))
    }
}

/// The engine answers the convergence classifier's content questions (ADR 0001).
/// `open` returns plaintext iff our own identity may read it now; `None` is the
/// relay role. The classifier owns the merge rule; we own crypto + storage.
impl converge::KeyOracle for DagRepo {
    fn open(&self, oid: &Oid, now: u64) -> Option<Vec<u8>> {
        self.get(oid, &self.identity, now).ok()
    }
}

// --- local persistence helpers for manifest, purges, conflicts ---
// These use the same hand-rolled length-prefixed format as the other codecs.

/// Reject an authored change whose signature is missing or does not verify over
/// its id (S3, ADR 0018). Legacy/unauthored changes (`author == None`) predate
/// signing and are accepted. Called inside `apply`/`stow` so validity is
/// enforced structurally — never a toggle a caller can skip. loot-core is
/// verify-only here; signing and key custody live in loot-identity.
/// True if sealing at `new` would make a path readable to a wider audience
/// than `old` sealed it for (#62). Restricted-set membership changes are
/// deliberately not compared — `grant`/`maroon` own that audit trail.
fn demotes(old: &Visibility, new: &Visibility) -> bool {
    matches!(
        (old, new),
        (Visibility::Restricted(_), Visibility::Public)
            | (Visibility::Embargoed { .. }, Visibility::Public)
            | (Visibility::Embargoed { .. }, Visibility::Restricted(_))
    )
}

/// A node is a *working change* iff it is authored but not yet signed — the
/// in-progress tip a keyholder is still editing (ADR 0018). It is finalized (and
/// publishable to the shared graph) exactly when `loot new` attaches its
/// signature. Legacy/unauthored nodes (`author == None`) are never working
/// changes: they predate signing and are already finalized. This is the single
/// discriminator CA1.5 uses to keep a dock's uncommitted work out of the shared
/// node store (ADR 0022).
fn is_working_change(node: &ChangeNode) -> bool {
    node.author.is_some() && node.signature.is_none()
}

/// Every finalized node in the shared graph file — the whole-store view the
/// lineage-filtered load deliberately narrows (ADR 0022). gc's root walk and
/// [`DagRepo::ingest_shared_lineage`] both read it (#265). Absent-is-empty (a
/// store may predate its first save); any other read error propagates —
/// callers decide what is *safe to prune* or *known to exist* from this, so a
/// torn read must fail loudly, never read as empty.
fn read_shared_graph(store: &RepoStore) -> Result<Vec<ChangeNode>, RepoError> {
    match read_replaced(&store.graph()) {
        Ok(bytes) => persist_codec::decode_nodes(&bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(RepoError::Backend(format!("read shared graph: {e}"))),
    }
}

/// Every content address rooted *on disk* in the shared store: the shared
/// graph file's nodes (every position's finalized changes, #263/#265) plus
/// every registered lane's working-change blob (an unsigned change's objects
/// are already sealed into the shared store). gc unions this with the loaded
/// repo's own [`DagRepo::referenced_oids`]; verify (#19) adds the primary's
/// working-change blob and treats the union as the referenced set.
fn disk_rooted_oids(store: &RepoStore) -> Result<BTreeSet<Oid>, RepoError> {
    Ok(disk_rooted_nodes(store)?
        .iter()
        .flat_map(|n| n.tree.values())
        .map(|(oid, _vis)| oid.clone())
        .collect())
}

/// The nodes behind [`disk_rooted_oids`], whole: verify (#335) needs the
/// referencing change and path for each missing address, not just the oid set.
fn disk_rooted_nodes(store: &RepoStore) -> Result<Vec<ChangeNode>, RepoError> {
    let mut nodes = read_shared_graph(store)?;
    for entry in store.list_lane_entries() {
        // Strict read, absent-is-empty: a lane with no WIP roots nothing, but
        // an unreadable or torn blob must FAIL the walk — treating it as empty
        // silently shrinks the root set, and gc then over-prunes: the exact
        // loss class this walk exists to prevent.
        let blob = match read_replaced(&store.lane_view(&entry).working_change()) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(RepoError::Backend(format!(
                    "read lane '{}' working change: {e}",
                    entry.id
                )))
            }
        };
        nodes.extend(persist_codec::decode_nodes(&blob)?);
    }
    Ok(nodes)
}

fn verify_authored_change(node: &ChangeNode) -> Result<(), RepoError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Some(author) = node.author else {
        return Ok(());
    };
    let Some(sig) = node.signature else {
        return Err(RepoError::BadChangeSignature(node.id.clone()));
    };
    let vk = VerifyingKey::from_bytes(&author)
        .map_err(|_| RepoError::BadChangeSignature(node.id.clone()))?;
    // The signature covers `version_id ‖ change_id ‖ predecessors` (ADR
    // 0029/0032), so a relay or peer cannot relabel signed content under a
    // different change id, nor strip or forge a supersession claim. A legacy
    // change (`change_id = None`, no predecessors) signs over the version id
    // alone, so its pre-v6 signature still verifies through the same call.
    let message = change_signing_message(&node.id, &node.change_id, &node.predecessors);
    vk.verify(&message, &Signature::from_bytes(&sig))
        .map_err(|_| RepoError::BadChangeSignature(node.id.clone()))
}

fn encode_attestations(log: &AttestationLog) -> Vec<u8> {
    use crate::bundle_codec::{put_attestation, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    put_u32(&mut out, log.len());
    for a in log.iter() {
        put_attestation(&mut out, a);
    }
    out
}

fn decode_attestations(b: &[u8]) -> Result<AttestationLog, RepoError> {
    use crate::bundle_codec::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let mut log = AttestationLog::new();
    let n = c.u32()?;
    for _ in 0..n {
        let att = c.attestation()?;
        // Re-verify on load: the on-disk log is untrusted (it can be edited or
        // corrupted between runs), so we hold it to the same verify-and-drop bar
        // as bundle ingest — an invalid attestation is silently discarded rather
        // than trusted just because it was on disk (S4, ADR 0018).
        if att.verify() {
            log.insert(att);
        }
    }
    Ok(log)
}

// encode_manifest/decode_manifest/encode_purges/decode_purges moved to
// `custody.rs` (#323) — they codec the two fields [`custody::Custody`] owns
// alongside the keyring/escrow.

fn encode_conflicts(conflicts: &BTreeMap<PathBuf, (Oid, Oid)>) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    put_u32(&mut out, conflicts.len());
    for (path, (ours, theirs)) in conflicts {
        put_bytes(&mut out, path.to_string_lossy().as_bytes());
        out.extend_from_slice(&ours.0);
        out.extend_from_slice(&theirs.0);
    }
    out
}

fn decode_conflicts(b: &[u8]) -> Result<BTreeMap<PathBuf, (Oid, Oid)>, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut conflicts = BTreeMap::new();
    for _ in 0..n {
        let path = PathBuf::from(c.string()?);
        let ours = Oid(c.arr32()?);
        let theirs = Oid(c.arr32()?);
        conflicts.insert(path, (ours, theirs));
    }
    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    //! White-box guards that need engine internals (`keyring`, `bundle_codec::decode`).
    //! The black-box bake-off scenarios live in the `spike-dag` shim crate,
    //! driving the engine through the public `Repo` interface (ADR 0002).
    use super::*;
    // White-box tests reach into the low-level body codec directly.
    use crate::bundle_codec;

    fn tmp() -> PathBuf {
        std::env::temp_dir()
    }

    /// ADR 0003 leak guard: a Restricted content key must NEVER appear in a sync
    /// bundle. Mint a restricted blob, capture its real content key from the
    /// keyring, and assert the raw key bytes are absent from the wire. Public
    /// keys may ride along; restricted ones may not.
    #[test]
    fn bundle_never_carries_restricted_keys() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let secret_oid = alice
            .put(b"TOKEN=supersecret\n", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let pub_oid = alice.put(b"readme\n", Visibility::Public).unwrap();

        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (secret_oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        tree.insert(PathBuf::from("README"), (pub_oid.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();

        let restricted_key = alice.custody.keyring.key_for(&secret_oid).expect("alice holds her key");
        let public_key = alice.custody.keyring.key_for(&pub_oid).expect("alice holds public key");

        let bundle = alice.bundle(&[]).unwrap();
        let payload = extract_sync_payload(&bundle.0);

        assert!(
            !contains_window(&payload, &restricted_key),
            "restricted content key leaked into the sync bundle"
        );
        assert!(
            contains_window(&payload, &public_key),
            "public content key should ride along for ANYONE-granted content"
        );
    }

    /// ADR 0004 leak guard: the sync wire must carry no plaintext-equality
    /// oracle. Commit the SAME restricted plaintext into two repos; neither
    /// bundle may contain blake3(plaintext), and the ciphertexts must differ.
    #[test]
    fn bundle_carries_no_plaintext_equality_oracle() {
        let secret = b"DUPLICATED SECRET VALUE";
        let plaintext_hash = *blake3::hash(secret).as_bytes();

        let bundle_for = |identity: &str| {
            let mut repo = DagRepo::init(tmp(), identity).unwrap();
            let oid = repo
                .put(secret, Visibility::Restricted(vec![identity.into()]))
                .unwrap();
            let mut tree = BTreeMap::new();
            tree.insert(PathBuf::from(".env"), (oid, Visibility::Restricted(vec![identity.into()])));
            repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
                .unwrap();
            repo.bundle(&[]).unwrap().0
        };

        let a = bundle_for("alice");
        let b = bundle_for("bob");

        assert!(!contains_window(&a, &plaintext_hash));
        assert!(!contains_window(&b, &plaintext_hash));

        let ct_a = single_ciphertext(&a);
        let ct_b = single_ciphertext(&b);
        assert_ne!(ct_a, ct_b, "same plaintext must not produce equal ciphertext on the wire");
    }

    fn single_ciphertext(bundle: &[u8]) -> Vec<u8> {
        let payload = extract_sync_payload(bundle);
        let (_changes, objs, _keys, _attestations) =
            bundle_codec::decode(&payload, crate::format::FORMAT_MAJOR).unwrap();
        assert_eq!(objs.len(), 1, "test fixture commits exactly one object");
        objs.into_iter().next().unwrap().1.ciphertext
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Decode a sync bundle through `Frame::decode` and re-encode just the body
    /// payload for ADR 0003/0004 leak-guard inspection. This approach is immune
    /// to future Frame header changes (S2 compression flags, etc.) — the frame
    /// decoder handles whatever is in front of the body.
    fn extract_sync_payload(bundle: &[u8]) -> Vec<u8> {
        let frame = bundle_codec::Frame::decode(bundle).expect("valid sync bundle");
        let bundle_codec::Frame::Sync { body, .. } = frame else {
            panic!("expected sync bundle (tag 0)");
        };
        let changes: Vec<&ChangeNode> = body.changes.iter().collect();
        bundle_codec::encode(&changes, &body.objs, &body.keys, &body.attestations)
    }

    /// S1/S2 compatibility: a v1-format sync bundle (marker `[1,0]`, no
    /// `compressed` flag in inline objects) applies cleanly through the full
    /// engine stack. Exercises `Frame::decode -> decode_body(major=1)` on `apply`.
    ///
    /// We hand-serialize the v1 wire layout using the public body-codec helpers
    /// so the test is coupled to the same field encoding as the real codec, not
    /// to internal byte offsets.
    #[test]
    fn v1_bundle_applies_through_engine() {
        use crate::bundle_codec::{put_bytes, put_u32, put_vis};

        // Produce a real bundle so we have live object/key/change data to work with.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"public\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();

        let v2_bundle = alice.bundle(&[]).unwrap();
        let frame = bundle_codec::Frame::decode(&v2_bundle.0).expect("valid v2 bundle");
        let bundle_codec::Frame::Sync { body, .. } = frame else { panic!("expected sync frame") };

        // Hand-serialize the v1 wire layout:
        //   [major=1][minor=0][tag=0][purge_count=0 u32le]
        //   [obj_count u32le]
        //     per object: [addr 32][nonce 12][ciphertext len+bytes][vis][grant_ids]
        //     note: v1 has NO `compressed` flag byte between nonce and ciphertext
        //   [key_count u32le][addr 32][key 32] ...
        //   [escrow_count u32le] ...
        //   [change_count u32le][change ...] ...
        let mut wire = Vec::new();
        wire.push(1u8); // major = 1
        wire.push(0u8); // minor = 0
        wire.push(0u8); // tag = Sync
        put_u32(&mut wire, 0); // no purges

        put_u32(&mut wire, body.objs.len());
        for (addr, obj) in &body.objs {
            wire.extend_from_slice(&addr.0);
            wire.extend_from_slice(&obj.nonce);
            // v1: no compressed flag byte here
            put_bytes(&mut wire, &obj.ciphertext);
            put_vis(&mut wire, &obj.vis);
            put_u32(&mut wire, obj.grant_ids.len());
            for id in &obj.grant_ids {
                put_bytes(&mut wire, id.as_bytes());
            }
        }
        put_u32(&mut wire, body.keys.len());
        for (addr, key) in &body.keys {
            wire.extend_from_slice(&addr.0);
            wire.extend_from_slice(key);
        }
        put_u32(&mut wire, 0); // v1 escrow section: empty (v5 bodies have none to copy)
        put_u32(&mut wire, body.changes.len());
        for c in &body.changes {
            wire.extend_from_slice(&c.id.0);
            put_u32(&mut wire, c.parents.len());
            for p in &c.parents {
                wire.extend_from_slice(&p.0);
            }
            put_bytes(&mut wire, c.message.as_bytes());
            put_u32(&mut wire, c.tree.len());
            for (path, (o, vis)) in &c.tree {
                put_bytes(&mut wire, path.to_string_lossy().as_bytes());
                wire.extend_from_slice(&o.0);
                put_vis(&mut wire, vis);
            }
        }

        // apply() must succeed: the v1 major is accepted, the body parses without
        // the compressed flag, and the change is integrated.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&SyncBundle(wire), 0).expect("v1 bundle must apply through engine");
        assert!(bob.heads().contains(&change_id), "change must be tracked after v1 apply");
    }

    /// S2 (ADR 0020): a public file compresses on seal and round-trips
    /// byte-identical through bundle -> apply -> read on a peer that receives the
    /// public key. Exercises compress-then-encrypt over the full sync path.
    #[test]
    fn public_content_round_trips_compressed_through_bundle_apply() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let doc = b"fn main() { println!(\"hi\"); }\n".repeat(64);
        let oid = alice.put(&doc, Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("main.rs"), (oid.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "add main".into(), tree })
            .unwrap();
        // Reads back verbatim locally (decompress-on-open).
        assert_eq!(alice.get(&oid, "alice", 0).unwrap(), doc);
        // A peer receives the bundle (public key rides along) and reads identical bytes.
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        assert_eq!(
            bob.get(&oid, "bob", 0).unwrap(),
            doc,
            "public content must round-trip byte-identical through bundle/apply"
        );
    }

    /// ADR 0005: a repo survives save -> load with identity, content, history,
    /// and key custody intact — so a process-per-command CLI works.
    #[test]
    fn save_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("loot-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let secret_oid;
        let change_id;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            secret_oid = repo
                .put(b"TOKEN=abc\n", Visibility::Restricted(vec!["alice".into()]))
                .unwrap();
            let pub_oid = repo.put(b"hi\n", Visibility::Public).unwrap();
            let mut tree = BTreeMap::new();
            tree.insert(PathBuf::from(".env"), (secret_oid.clone(), Visibility::Restricted(vec!["alice".into()])));
            tree.insert(PathBuf::from("README"), (pub_oid, Visibility::Public));
            change_id = repo
                .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
                .unwrap();
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        // Identity preserved -> alice can still decrypt her restricted content.
        assert_eq!(loaded.get(&secret_oid, "alice", 0).unwrap(), b"TOKEN=abc\n");
        // A peer that never received the key cannot read — confirmed by checking
        // that a fresh repo without the key returns NotFound for the oid.
        // (Under ADR 0008 semantics, holding the key IS authorization; an identity
        // that was never granted the key simply won't have it in their keyring.)
        let mallory_repo = DagRepo::init(dir.join("mallory"), "mallory").unwrap();
        assert!(matches!(
            mallory_repo.get(&secret_oid, "mallory", 0),
            Err(RepoError::NotFound(_))
        ));
        // History preserved.
        assert!(loaded.heads().contains(&change_id));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_writes_objects_as_loose_immutable_files() {
        // ADR 0012: each object is its own content-addressed file, written once.
        // A second save after adding one object writes only the new file and
        // leaves existing object files byte-identical (immutable, incremental).
        let dir = std::env::temp_dir().join(format!("loot-loose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let a = repo.put(b"first\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        let path_a = obj_dir.join(crate::hex::encode(&a.0));
        assert!(path_a.exists(), "object A should be a loose file named by its address");
        let a_bytes_first = std::fs::read(&path_a).unwrap();

        // Add a second object and save again.
        let b = repo.put(b"second\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        // A's file is untouched (immutable); B's file now exists.
        assert_eq!(std::fs::read(&path_a).unwrap(), a_bytes_first, "existing object file must not be rewritten");
        assert!(obj_dir.join(crate::hex::encode(&b.0)).exists(), "new object B should have its own file");

        // No leftover temp files from the atomic write.
        let leftover_tmp = std::fs::read_dir(&obj_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover_tmp, "atomic write should leave no .tmp files");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- atomic custody-metadata writes (#252) ---

    #[test]
    fn atomic_write_leaves_complete_new_contents_and_no_temp() {
        let dir = std::env::temp_dir().join(format!(
            "loot-atomic-write-{}-{}",
            std::process::id(),
            METADATA_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keyring");

        atomic_write(&path, b"old-and-shorter").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"old-and-shorter");

        // Overwriting with different-length content leaves exactly the new
        // bytes — never a truncated mix of old and new.
        atomic_write(&path, b"new-longer-contents").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-longer-contents");

        // No staging file survives the rename.
        let leftover = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!leftover, "atomic_write must leave no .tmp staging file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_atomic_writes_never_truncate() {
        use std::sync::Arc;
        // Many threads race to rewrite the same file with distinct, differently
        // sized payloads. Every observed state must be one *complete* payload —
        // never a torn/truncated blend (#252). Bare fs::write (truncate-in-
        // place) cannot guarantee this; temp+rename can.
        let dir = std::env::temp_dir().join(format!(
            "loot-atomic-race-{}-{}",
            std::process::id(),
            METADATA_TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = Arc::new(dir.join("manifest"));

        let payloads: Vec<Vec<u8>> =
            (0..8u8).map(|i| vec![b'A' + i; 100 + i as usize * 37]).collect();
        let payloads = Arc::new(payloads);

        let handles: Vec<_> = (0..payloads.len())
            .map(|i| {
                let path = Arc::clone(&path);
                let payloads = Arc::clone(&payloads);
                std::thread::spawn(move || {
                    for _ in 0..50 {
                        atomic_write(&path, &payloads[i]).unwrap();
                        let seen = std::fs::read(&*path).unwrap();
                        assert!(
                            payloads.iter().any(|p| *p == seen),
                            "reader saw a torn file of len {} — not any whole payload",
                            seen.len()
                        );
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- multi-head log display (ADR 0001, issue #18) ---

    fn empty_change(parents: Vec<Oid>, message: &str) -> Change {
        Change { id: Oid([0; 32]), parents, message: message.into(), tree: BTreeMap::new() }
    }

    #[test]
    fn divergent_change_detected_and_abandon_collapses_it() {
        use std::collections::BTreeSet;
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();

        // Two writers rewrite ONE change id onto two independent versions (S3):
        // same carried change id, different content -> different version ids, both
        // heads. This is exactly what a cross-repo amend of a shared change yields.
        let cid = [7u8; 16];
        let va = repo
            .record_carrying(empty_change(vec![root.clone()], "reworded A"), Some(cid))
            .unwrap();
        let vb = repo
            .record_carrying(empty_change(vec![root.clone()], "reworded B"), Some(cid))
            .unwrap();
        assert_ne!(va, vb, "different content -> different version ids");
        assert_eq!(repo.change_change_id(&va), Some(cid));
        assert_eq!(repo.change_change_id(&vb), Some(cid));

        let none: BTreeSet<Oid> = BTreeSet::new();
        assert_eq!(
            repo.liveness(&none, &[]).divergent().clone(),
            BTreeSet::from([cid]),
            "one change id with two live versions is divergent"
        );
        assert_eq!(repo.liveness(&none, &[]).live_of(&cid).len(), 2);

        // Abandoning one version collapses the divergence — over the abandoned
        // filter it is no longer counted, and it drops out of the live heads.
        let abandoned = BTreeSet::from([vb.clone()]);
        assert!(
            repo.liveness(&abandoned, &[]).divergent().clone().is_empty(),
            "abandoned version no longer makes the change divergent"
        );
        assert_eq!(repo.liveness(&abandoned, &[]).live_of(&cid), vec![va.clone()]);
        assert!(repo.abandon_head(&vb), "vb was a live head");
        assert!(!repo.heads().contains(&vb), "abandon drops it from the live heads");
        assert!(repo.heads().contains(&va), "the surviving version stays a head");
        // Legacy/unauthored root has no change id, so it is never divergent.
        assert!(repo.change_change_id(&root).is_none());
    }

    #[test]
    fn log_graph_single_head_is_linear() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let tip = repo.record(empty_change(vec![root.clone()], "tip")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads, vec![tip.clone()], "one head: the tip");
        // Every change is reachable from the single head (index 0).
        for node in &g.changes {
            assert_eq!(node.reachable_from, vec![0]);
        }
        // Children-first ordering: the tip precedes its ancestor.
        let ids: Vec<&Oid> = g.changes.iter().map(|n| &n.id).collect();
        assert_eq!(ids, vec![&tip, &root]);
    }

    #[test]
    fn log_graph_shows_two_diverged_heads() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let a = repo.record(empty_change(vec![root.clone()], "head A")).unwrap();
        let b = repo.record(empty_change(vec![root.clone()], "head B")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads.len(), 2);
        assert!(g.heads.contains(&a) && g.heads.contains(&b));

        let find = |id: &Oid| g.changes.iter().find(|n| &n.id == id).unwrap();
        // Root is shared by both heads; each tip is unique to one head.
        assert_eq!(find(&root).reachable_from.len(), 2, "root shared across the divergence");
        assert_eq!(find(&a).reachable_from.len(), 1);
        assert_eq!(find(&b).reachable_from.len(), 1);
        assert_ne!(
            find(&a).reachable_from,
            find(&b).reachable_from,
            "the two tips belong to different heads"
        );
    }

    #[test]
    fn log_graph_shows_three_diverged_heads() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let root = repo.record(empty_change(vec![], "root")).unwrap();
        let a = repo.record(empty_change(vec![root.clone()], "head A")).unwrap();
        let b = repo.record(empty_change(vec![root.clone()], "head B")).unwrap();
        let c = repo.record(empty_change(vec![root.clone()], "head C")).unwrap();

        let g = repo.log_graph();
        assert_eq!(g.heads.len(), 3);
        for h in [&a, &b, &c] {
            assert!(g.heads.contains(h), "each tip is a head");
        }
        let find = |id: &Oid| g.changes.iter().find(|n| &n.id == id).unwrap();
        assert_eq!(find(&root).reachable_from.len(), 3, "root shared by all three heads");
        assert_eq!(find(&a).reachable_from.len(), 1);
        assert_eq!(find(&b).reachable_from.len(), 1);
        assert_eq!(find(&c).reachable_from.len(), 1);
    }

    // --- gc: prune orphaned loose objects (ADR 0012, #17, restored in #66) ---

    /// A dry run reports the orphan count and total size but deletes nothing —
    /// neither the on-disk file nor the in-memory store entry.
    #[test]
    fn gc_dry_run_reports_orphans_without_deleting() {
        let dir = std::env::temp_dir().join(format!("loot-gc-dry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        // Referenced object: named by a change, so it is part of the live set.
        let kept = repo.put(b"keep me\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("keep.txt"), (kept.clone(), Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();
        // Orphan: stored but never referenced by any change.
        let orphan = repo.put(b"unreferenced orphan bytes\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        let kept_path = obj_dir.join(crate::hex::encode(&kept.0));
        let orphan_path = obj_dir.join(crate::hex::encode(&orphan.0));
        assert!(kept_path.exists() && orphan_path.exists());

        let report = repo.gc(&dir, true).unwrap();
        assert_eq!(report.pruned, 1, "exactly one orphan would be pruned");
        assert!(report.bytes > 0, "dry run reports the orphan's on-disk size");
        // Dry run mutates nothing.
        assert!(orphan_path.exists(), "dry run must not delete files");
        assert!(kept_path.exists());
        assert!(repo.object(&orphan).is_ok(), "in-memory store untouched by dry run");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A real run deletes the orphan file, compacts the in-memory store, and
    /// leaves referenced content intact and readable — including across reload.
    /// A second pass is a no-op.
    #[test]
    fn gc_deletes_orphaned_objects_and_keeps_referenced() {
        let dir = std::env::temp_dir().join(format!("loot-gc-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let kept = repo.put(b"referenced\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (kept.clone(), Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();
        let orphan = repo.put(b"unreferenced\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        let kept_path = obj_dir.join(crate::hex::encode(&kept.0));
        let orphan_path = obj_dir.join(crate::hex::encode(&orphan.0));

        let report = repo.gc(&dir, false).unwrap();
        assert_eq!(report.pruned, 1);
        assert!(!orphan_path.exists(), "orphan file deleted");
        assert!(kept_path.exists(), "referenced file retained");
        // In-memory store compacted: orphan gone, referenced object still readable.
        assert!(matches!(repo.object(&orphan), Err(RepoError::NotFound(_))));
        assert_eq!(repo.get(&kept, "alice", 0).unwrap(), b"referenced\n");

        // Idempotent: nothing left to prune.
        let report2 = repo.gc(&dir, false).unwrap();
        assert_eq!(report2.pruned, 0);

        // Reload from disk: referenced content survives; orphan is gone.
        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert_eq!(loaded.get(&kept, "alice", 0).unwrap(), b"referenced\n");
        assert!(matches!(loaded.get(&orphan, "alice", 0), Err(RepoError::NotFound(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Objects referenced by a NON-HEAD change (older history) must be retained —
    /// gc walks the whole graph, not just the tips.
    #[test]
    fn gc_retains_objects_referenced_by_non_head_changes() {
        let dir = std::env::temp_dir().join(format!("loot-gc-nonhead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        // Parent change references old_oid.
        let old_oid = repo.put(b"v1\n", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a.txt"), (old_oid.clone(), Visibility::Public));
        let parent = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "v1".into(), tree: t1 })
            .unwrap();
        // Child change references new_oid on top of the parent.
        let new_oid = repo.put(b"v2\n", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("a.txt"), (new_oid.clone(), Visibility::Public));
        repo.record(Change {
            id: Oid([0; 32]),
            parents: vec![parent.clone()],
            message: "v2".into(),
            tree: t2,
        })
        .unwrap();
        assert!(!repo.heads().contains(&parent), "parent is no longer a head");
        // Orphan object.
        let orphan = repo.put(b"orphan\n", Visibility::Public).unwrap();
        repo.save(&dir).unwrap();

        let report = repo.gc(&dir, false).unwrap();
        assert_eq!(report.pruned, 1, "only the orphan is pruned");

        let obj_dir = RepoStore::new(&dir).objects_dir();
        assert!(
            obj_dir.join(crate::hex::encode(&old_oid.0)).exists(),
            "object referenced only by a non-HEAD change must be retained"
        );
        assert!(obj_dir.join(crate::hex::encode(&new_oid.0)).exists(), "head object retained");
        assert!(!obj_dir.join(crate::hex::encode(&orphan.0)).exists(), "orphan deleted");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #6: `change_has_path` is the primitive `loot log --path` filters on —
    /// a straight lookup against a change's own recorded (full, not delta)
    /// tree, the same one `log_detailed` sizes. An unknown id has no path,
    /// same as an absent one.
    #[test]
    fn change_has_path_checks_the_recorded_tree() {
        let dir = std::env::temp_dir().join(format!("loot-6-change-has-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let a_oid = repo.put(b"a\n", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a.txt"), (a_oid.clone(), Visibility::Public));
        let c1 = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "adds a".into(), tree: t1 })
            .unwrap();

        let b_oid = repo.put(b"b\n", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("a.txt"), (a_oid, Visibility::Public));
        t2.insert(PathBuf::from("b.txt"), (b_oid, Visibility::Public));
        let c2 = repo
            .record(Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "adds b".into(), tree: t2 })
            .unwrap();

        assert!(repo.change_has_path(&c1, Path::new("a.txt")));
        assert!(!repo.change_has_path(&c1, Path::new("b.txt")), "c1's tree never held b.txt");
        assert!(repo.change_has_path(&c2, Path::new("a.txt")));
        assert!(repo.change_has_path(&c2, Path::new("b.txt")));
        assert!(!repo.change_has_path(&Oid([0xff; 32]), Path::new("a.txt")), "unknown id has no path");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #263/#265 prevention: a change finalized by another lane lives in the
    /// shared graph file but not in this dock's lineage-filtered loaded graph
    /// (ADR 0022). gc must root its objects anyway — landed work is never
    /// garbage, even before the primary adopts it.
    #[test]
    fn gc_keeps_objects_of_changes_outside_the_dock_lineage() {
        let dir = std::env::temp_dir().join(format!("loot-gc-lineage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Primary: one change c1, persisted (its heads file names c1).
        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let kept = repo.put(b"primary\n", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a.txt"), (kept, Visibility::Public));
        let c1 = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        repo.save(&dir).unwrap();

        // A lane over the same shared store finalizes c2 (a child of c1) with
        // a new object — the landed-from-lane shape: the shared graph file
        // gains c2 while the primary's heads still name only c1.
        let lane_work = dir.join("lane");
        std::fs::create_dir_all(lane_work.join(".loot")).unwrap();
        let lane_store = RepoStore::for_lane(&dir, lane_work.join(".loot"));
        let mut lane = DagRepo::load_from(&lane_store, lane_work.clone()).unwrap();
        let landed = lane.put(b"landed\n", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("b.txt"), (landed.clone(), Visibility::Public));
        lane.record(Change {
            id: Oid([0; 32]),
            parents: vec![c1.clone()],
            message: "c2".into(),
            tree: t2,
        })
        .unwrap();
        lane.save_to(&lane_store).unwrap();

        // The primary reloads: its lineage is c1 only — c2 is out of view.
        let mut primary = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert_eq!(primary.heads(), vec![c1], "the landed change is outside the loaded lineage");

        let report = primary.gc(&dir, false).unwrap();
        assert_eq!(report.pruned, 0, "a landed-but-unadopted change is rooted, not garbage");
        let obj = RepoStore::new(&dir).objects_dir().join(crate::hex::encode(&landed.0));
        assert!(obj.exists(), "the landed change's object survives the prune");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A registered lane's *unsigned* working change roots its objects too:
    /// they are sealed into the shared store at snapshot, before any finalize,
    /// and the primary is the only pruner (ADR 0034) — so gc consults every
    /// lane's working-change blob, not just its own loaded graph.
    #[test]
    fn gc_keeps_a_registered_lanes_working_change_objects() {
        let dir = std::env::temp_dir().join(format!("loot-gc-lanewip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let base = repo.put(b"base\n", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a.txt"), (base, Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        repo.save(&dir).unwrap();

        // A registered lane with in-progress (authored, unsigned) work.
        let (_, pk) = test_signer(9);
        let lane_work = dir.join("lane");
        std::fs::create_dir_all(lane_work.join(".loot")).unwrap();
        let lane_store = RepoStore::for_lane(&dir, lane_work.join(".loot"));
        let mut lane = DagRepo::load_from(&lane_store, lane_work.clone()).unwrap();
        lane.set_author(pk);
        let wip = lane
            .snapshot(None, None, &[entry("wip.txt", b"lane wip", Visibility::Public)], "wip", 0)
            .unwrap();
        let wip_oid = lane.change_tree(&wip).unwrap()[&PathBuf::from("wip.txt")].0.clone();
        lane.save_to(&lane_store).unwrap();
        RepoStore::new(&dir).create_lane_entry("l1", &lane_work, None, 0).unwrap();

        let mut primary = DagRepo::load(&dir, dir.join("work")).unwrap();
        let report = primary.gc(&dir, false).unwrap();
        assert_eq!(report.pruned, 0, "a live lane's WIP objects are rooted");
        let obj = RepoStore::new(&dir).objects_dir().join(crate::hex::encode(&wip_oid.0));
        assert!(obj.exists(), "the lane's uncommitted object survives the prune");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- verify: loose-object integrity check (#19) ---

    /// A healthy store verifies clean: every object file re-hashes to its
    /// address and every referenced address has a file. A leftover `*.tmp`
    /// stage is not an object and never counts against integrity.
    #[test]
    fn verify_reports_clean_on_a_healthy_store() {
        let dir = std::env::temp_dir().join(format!("loot-verify-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let kept = repo.put(b"healthy\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (kept, Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();
        repo.save(&dir).unwrap();
        // An interrupted write's leftover stage must be ignored, as in load/gc.
        std::fs::write(RepoStore::new(&dir).objects_dir().join("deadbeef.1.2.tmp"), b"junk")
            .unwrap();

        let report = DagRepo::verify(&dir).unwrap();
        assert!(report.is_clean(), "healthy store must verify clean: {report:?}");
        assert!(report.ok >= 1, "the referenced object counts as verified");
        assert!(report.corrupt.is_empty() && report.missing.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Corruption is exact, not heuristic: a file whose bytes no longer decode,
    /// and a decodable file sitting at the wrong address (its content re-hashes
    /// elsewhere), are both reported corrupt by address. The wrongly-named
    /// file's true address is then missing — present-at-the-wrong-address is
    /// not present.
    #[test]
    fn verify_reports_corrupt_objects_by_address() {
        let dir = std::env::temp_dir().join(format!("loot-verify-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let smashed = repo.put(b"will be overwritten with garbage\n", Visibility::Public).unwrap();
        let moved = repo.put(b"will be renamed to a wrong address\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (smashed.clone(), Visibility::Public));
        tree.insert(PathBuf::from("b.txt"), (moved.clone(), Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        // Bit rot / truncation: the file exists but no longer decodes.
        std::fs::write(obj_dir.join(crate::hex::encode(&smashed.0)), b"garbage").unwrap();
        // Wrong address: valid object bytes filed under an address their
        // content does not hash to.
        let bogus = Oid([0xEE; 32]);
        std::fs::rename(
            obj_dir.join(crate::hex::encode(&moved.0)),
            obj_dir.join(crate::hex::encode(&bogus.0)),
        )
        .unwrap();

        // The corrupt store is exactly the one that fails to LOAD — verify
        // must diagnose it anyway, which is why it never loads the repo.
        assert!(
            DagRepo::load(&dir, dir.join("work")).is_err(),
            "a store with an undecodable object cannot load"
        );
        let report = DagRepo::verify(&dir).unwrap();
        assert!(!report.is_clean());
        assert!(report.corrupt.contains(&smashed), "undecodable file is corrupt");
        assert!(report.corrupt.contains(&bogus), "hash-mismatched file is corrupt");
        assert!(
            report.missing.iter().any(|m| m.addr == moved),
            "the renamed-away address is missing"
        );
        assert!(
            !report.missing.iter().any(|m| m.addr == smashed),
            "corrupt is present, never also missing"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An address the change graph references but no file backs is missing —
    /// the after-a-disk-incident case the command exists for.
    #[test]
    fn verify_reports_missing_referenced_objects() {
        let dir = std::env::temp_dir().join(format!("loot-verify-miss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let lost = repo.put(b"referenced then deleted\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (lost.clone(), Visibility::Public));
        let c1 = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        std::fs::remove_file(obj_dir.join(crate::hex::encode(&lost.0))).unwrap();

        let report = DagRepo::verify(&dir).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.missing.len(), 1, "exactly the deleted referenced object is missing");
        let m = &report.missing[0];
        assert_eq!(m.addr, lost);
        // Provenance (#335): the report names the referencing change, path,
        // and message — the address alone doesn't say what was lost.
        assert_eq!(
            m.referenced_by,
            vec![MissingRef {
                change: c1.clone(),
                path: PathBuf::from("a.txt"),
                message: "c".into(),
            }]
        );
        assert!(report.corrupt.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The acknowledged-loss flow (#335): `accept_loss` records the missing
    /// set in the ledger, after which verify is clean and reports the
    /// addresses as `lost`; NEW damage still fails; and a ledgered object
    /// whose bytes come back is simply verified normally again.
    #[test]
    fn accept_loss_acknowledges_missing_and_still_catches_new_damage() {
        let dir = std::env::temp_dir().join(format!("loot-verify-loss-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let gone = repo.put(b"lost forever\n", Visibility::Public).unwrap();
        let later = repo.put(b"damaged later\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (gone.clone(), Visibility::Public));
        tree.insert(PathBuf::from("b.txt"), (later.clone(), Visibility::Public));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();
        repo.save(&dir).unwrap();

        let obj_dir = RepoStore::new(&dir).objects_dir();
        let gone_path = obj_dir.join(crate::hex::encode(&gone.0));
        let gone_bytes = std::fs::read(&gone_path).unwrap();
        std::fs::remove_file(&gone_path).unwrap();

        // Accept the loss: the report shows what was acknowledged (provenance
        // included), and the next verify is clean with the address in `lost`.
        let accepted = DagRepo::accept_loss(&dir).unwrap();
        assert_eq!(accepted.missing.len(), 1);
        assert_eq!(accepted.missing[0].addr, gone);
        let report = DagRepo::verify(&dir).unwrap();
        assert!(report.is_clean(), "acknowledged loss no longer fails: {report:?}");
        assert!(report.missing.is_empty());
        assert_eq!(report.lost, vec![gone.clone()], "the loss stays on the record");

        // New damage after the acknowledgment still fails — the ledger must
        // never become a blanket pardon.
        std::fs::remove_file(obj_dir.join(crate::hex::encode(&later.0))).unwrap();
        let report = DagRepo::verify(&dir).unwrap();
        assert!(!report.is_clean());
        assert_eq!(report.missing.len(), 1, "only the NEW loss fails");
        assert_eq!(report.missing[0].addr, later);
        assert_eq!(report.lost, vec![gone.clone()]);

        // A ledgered object whose bytes come back is verified normally; its
        // inert ledger entry stops mattering.
        std::fs::write(&gone_path, &gone_bytes).unwrap();
        let report = DagRepo::verify(&dir).unwrap();
        assert!(!report.lost.contains(&gone), "a present object is not lost");
        assert!(report.missing.iter().all(|m| m.addr != gone));

        // Idempotent: accepting again only adds the still-missing address.
        DagRepo::accept_loss(&dir).unwrap();
        let report = DagRepo::verify(&dir).unwrap();
        assert!(report.is_clean());
        assert_eq!(report.lost, vec![later], "both losses acknowledged, one inert");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The catch-up primitive (#265): a landed change recorded in the shared
    /// graph file but dropped by the lineage-filtered load becomes walkable
    /// (ancestry, merge) after `ingest_shared_lineage` — no disk state moves.
    #[test]
    fn ingest_shared_lineage_makes_a_landed_change_visible() {
        let dir = std::env::temp_dir().join(format!("loot-ingest-lineage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
        let c1 = repo.record(empty_change(vec![], "c1")).unwrap();
        repo.save(&dir).unwrap();

        let lane_work = dir.join("lane");
        std::fs::create_dir_all(lane_work.join(".loot")).unwrap();
        let lane_store = RepoStore::for_lane(&dir, lane_work.join(".loot"));
        let mut lane = DagRepo::load_from(&lane_store, lane_work).unwrap();
        let c2 = lane.record(empty_change(vec![c1.clone()], "landed c2")).unwrap();
        lane.save_to(&lane_store).unwrap();

        let mut primary = DagRepo::load(&dir, dir.join("work")).unwrap();
        let store = RepoStore::new(&dir);
        assert_eq!(primary.heads(), vec![c1.clone()], "c2 starts outside the loaded lineage");

        assert!(
            primary.ingest_shared_lineage(&store, &c2).unwrap(),
            "the landed tip is in the shared graph"
        );
        assert_eq!(primary.parents_of(&c2), vec![c1], "the lineage is walkable");
        assert_eq!(primary.heads(), vec![c2.clone()], "the landed tip is now the frontier");
        // Idempotent; an unknown tip reports false and touches nothing.
        assert!(primary.ingest_shared_lineage(&store, &c2).unwrap());
        assert!(!primary.ingest_shared_lineage(&store, &Oid([9; 32])).unwrap());
        assert_eq!(primary.heads(), vec![c2]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- snapshot / reconcile (ADR 0006) ---

    fn entry(path: &str, body: &[u8], vis: Visibility) -> (PathBuf, Vec<u8>, Visibility) {
        (PathBuf::from(path), body.to_vec(), vis)
    }

    #[test]
    fn snapshot_rewrites_working_change_in_place() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(None, None, &[entry("a.txt", b"one", Visibility::Public)], "wip", 0)
            .unwrap();
        // Re-snapshot with new content -> same working slot, not a second change.
        let w2 = repo
            .snapshot(None, Some(&w1), &[entry("a.txt", b"two", Visibility::Public)], "wip", 0)
            .unwrap();
        assert_eq!(repo.log().len(), 1, "working change rewritten, not appended");
        assert!(repo.heads().contains(&w2));
        // Latest content wins.
        let tree = repo.graph.current_tree();
        let oid = &tree[&PathBuf::from("a.txt")].0;
        assert_eq!(repo.get(oid, "alice", 0).unwrap(), b"two");
    }

    #[test]
    fn change_id_is_stable_across_resnapshots_while_version_id_changes() {
        // ADR 0029 keystone: a working change keeps ONE durable change_id across
        // every re-snapshot, even as its content-derived version id rewrites — the
        // durable-name-while-you-edit property the rest of the trio builds on.
        let (_, pk) = test_signer(3);
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        repo.set_author(pk);
        let w1 = repo
            .snapshot(None, None, &[entry("a.txt", b"one", Visibility::Public)], "wip", 0)
            .unwrap();
        let cid1 = repo.change_change_id(&w1).expect("an authored change mints a change id");
        let w2 = repo
            .snapshot(None, Some(&w1), &[entry("a.txt", b"two", Visibility::Public)], "wip", 0)
            .unwrap();
        assert_ne!(w1, w2, "the version id rewrites when content changes");
        assert_eq!(
            repo.change_change_id(&w2),
            Some(cid1),
            "the durable change id is carried across the re-snapshot"
        );
    }

    #[test]
    fn keyless_repo_mints_no_change_id() {
        // A keyless (unauthored) repo gets no durable handle: an unsigned change
        // matches legacy `None` (ADR 0029).
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w = repo
            .snapshot(None, None, &[entry("a.txt", b"x", Visibility::Public)], "wip", 0)
            .unwrap();
        assert!(repo.change_change_id(&w).is_none());
    }

    #[test]
    fn snapshot_reuses_sealed_object_for_unchanged_paths() {
        // #98: a one-file edit must not re-address the whole repo. The
        // unchanged path keeps its oid across the rewrite, so the push
        // wants-negotiation (S5) ships only the delta.
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(
                None,
                None,
                &[
                    entry("edited.txt", b"one", Visibility::Public),
                    entry("stable.txt", b"same", Visibility::Public),
                ],
                "wip",
                0,
            )
            .unwrap();
        let t1 = repo.graph.tree_at(&w1);
        let w2 = repo
            .snapshot(
                None,
                Some(&w1),
                &[
                    entry("edited.txt", b"two", Visibility::Public),
                    entry("stable.txt", b"same", Visibility::Public),
                ],
                "wip",
                0,
            )
            .unwrap();
        let t2 = repo.graph.tree_at(&w2);
        assert_eq!(
            t1[&PathBuf::from("stable.txt")].0,
            t2[&PathBuf::from("stable.txt")].0,
            "unchanged path must keep its sealed object"
        );
        assert_ne!(
            t1[&PathBuf::from("edited.txt")].0,
            t2[&PathBuf::from("edited.txt")].0,
            "edited path must get a fresh object"
        );
        // The reused object still opens.
        let oid = &t2[&PathBuf::from("stable.txt")].0;
        assert_eq!(repo.get(oid, "alice", 0).unwrap(), b"same");
    }

    #[test]
    fn snapshot_is_idempotent_at_the_engine_level() {
        // With oid reuse (#98) the doc's idempotency claim holds in the engine
        // itself, not just behind the workspace's tree-hash short-circuit:
        // unchanged entries + same message => the same change id.
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let entries = [entry("a.txt", b"body", Visibility::Public)];
        let w1 = repo.snapshot(None, None, &entries, "wip", 0).unwrap();
        let w2 = repo.snapshot(None, Some(&w1), &entries, "wip", 0).unwrap();
        assert_eq!(w1, w2, "unchanged tree must rewrite to the same change id");
    }

    #[test]
    fn snapshot_reseals_on_visibility_change_even_with_same_bytes() {
        // Visibility lives on the sealed object (grant_ids, compression),
        // so a promotion must mint a fresh seal — reuse would leave the old
        // policy on the object.
        let restricted = Visibility::Restricted(vec!["alice".into()]);
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(None, None, &[entry("a.txt", b"s", Visibility::Public)], "wip", 0)
            .unwrap();
        let t1 = repo.graph.tree_at(&w1);
        let w2 = repo
            .snapshot(None, Some(&w1), &[entry("a.txt", b"s", restricted.clone())], "wip", 0)
            .unwrap();
        let t2 = repo.graph.tree_at(&w2);
        assert_ne!(
            t1[&PathBuf::from("a.txt")].0,
            t2[&PathBuf::from("a.txt")].0,
            "visibility change must re-seal"
        );
        assert_eq!(t2[&PathBuf::from("a.txt")].1, restricted);
    }

    #[test]
    fn snapshot_of_still_embargoed_path_reseals_rather_than_leaking_a_read() {
        // Before reveal_at even the author cannot open the object
        // (sealed::open checks embargo first), so reuse cannot compare
        // plaintexts. The path re-seals fresh — same behavior as before #98,
        // and the demotion guard still applies on top.
        let embargoed = Visibility::Embargoed { reveal_at: 100 };
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(None, None, &[entry("fix.rs", b"cve", embargoed.clone())], "wip", 0)
            .unwrap();
        let t1 = repo.graph.tree_at(&w1);
        let w2 = repo
            .snapshot(None, Some(&w1), &[entry("fix.rs", b"cve", embargoed.clone())], "wip", 0)
            .unwrap();
        let t2 = repo.graph.tree_at(&w2);
        assert_ne!(
            t1[&PathBuf::from("fix.rs")].0,
            t2[&PathBuf::from("fix.rs")].0,
            "still-embargoed content re-seals (no plaintext comparison possible)"
        );
    }

    #[test]
    fn snapshot_refuses_implicit_visibility_demotion() {
        // #62: a path already sealed Restricted must not re-seal Public just
        // because the attributes resolution changed — that is the fail-open
        // that leaked in the dogfood pilot.
        let restricted = Visibility::Restricted(vec!["alice".into()]);
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w1 = repo
            .snapshot(None, None, &[entry(".env", b"s", restricted.clone())], "wip", 0)
            .unwrap();
        let err = repo
            .snapshot(None, Some(&w1), &[entry(".env", b"s", Visibility::Public)], "wip", 0)
            .unwrap_err();
        assert!(err.to_string().contains("demote"), "unexpected error: {err}");
        // The refusal happened before any mutation: the working head survives.
        assert!(repo.heads().contains(&w1));

        // The same demotion goes through when explicitly allowed.
        let w2 = repo
            .snapshot_allowing(
                None,
                Some(&w1),
                &[entry(".env", b"s", Visibility::Public)],
                "wip",
                0,
                &[PathBuf::from(".env")],
            )
            .unwrap();
        let tree = repo.graph.tree_at(&w2);
        assert!(matches!(tree[&PathBuf::from(".env")].1, Visibility::Public));
    }

    #[test]
    fn snapshot_demotion_guard_covers_embargo_and_frees_promotion() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let embargoed = Visibility::Embargoed { reveal_at: 100 };
        let restricted = Visibility::Restricted(vec!["alice".into()]);

        // Embargoed -> Restricted reveals to named ids before reveal_at: demotion.
        let w = repo
            .snapshot(None, None, &[entry("fix.rs", b"cve", embargoed.clone())], "wip", 0)
            .unwrap();
        assert!(repo
            .snapshot(None, Some(&w), &[entry("fix.rs", b"cve", restricted.clone())], "wip", 0)
            .is_err());
        // Embargoed -> Public: demotion.
        assert!(repo
            .snapshot(None, Some(&w), &[entry("fix.rs", b"cve", Visibility::Public)], "wip", 0)
            .is_err());

        // Promotion (Public -> Restricted) needs no ceremony.
        let w2 = repo
            .snapshot(None, Some(&w), &[entry("fix.rs", b"cve", embargoed), entry("a.md", b"x", Visibility::Public)], "wip", 0)
            .unwrap();
        assert!(repo
            .snapshot(None, Some(&w2), &[entry("fix.rs", b"cve", Visibility::Embargoed { reveal_at: 100 }), entry("a.md", b"x", restricted)], "wip", 0)
            .is_ok());
    }

    #[test]
    fn pull_of_stale_chain_does_not_conflict_on_paths_it_never_touched() {
        // Pilot finding 6 (#65): bob clones connor's push; his snapshot
        // re-seals every path under fresh addresses; connor edits ctx.md
        // locally (a line MODIFICATION, so the line-set heuristic can't save
        // it); connor pulls. Bob never touched ctx.md since the base — the
        // pull must not report a conflict on it.
        let base_bytes: &[u8] = b"# context\nalpha\nbeta\n";
        let vis = Visibility::Public;

        let mut connor = DagRepo::init(std::env::temp_dir(), "connor").unwrap();
        let c_ctx = connor.put(base_bytes, vis.clone()).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("ctx.md"), (c_ctx, vis.clone()));
        let base_id = connor
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: t })
            .unwrap();
        let base_bundle = connor.bundle(&[]).unwrap();

        // bob clones the base, then his clone-day snapshot re-seals ctx.md
        // (same bytes, fresh key/address) and adds his own file.
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&base_bundle, 0).unwrap();
        let b_ctx = bob.put(base_bytes, vis.clone()).unwrap();
        let b_new = bob.put(b"bob's file\n", vis.clone()).unwrap();
        let mut bt = BTreeMap::new();
        bt.insert(PathBuf::from("ctx.md"), (b_ctx, vis.clone()));
        bt.insert(PathBuf::from("bob.txt"), (b_new, vis.clone()));
        bob.record(Change {
            id: Oid([0; 32]),
            parents: vec![base_id.clone()],
            message: "bob work".into(),
            tree: bt,
        })
        .unwrap();

        // connor meanwhile modifies a line of ctx.md on his own head.
        let c_ctx2 = connor.put(b"# context\nalpha\nbeta EDITED\n", vis.clone()).unwrap();
        let mut ct = BTreeMap::new();
        ct.insert(PathBuf::from("ctx.md"), (c_ctx2.clone(), vis.clone()));
        let connor_head = connor
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![base_id],
                message: "connor edit".into(),
                tree: ct,
            })
            .unwrap();

        // connor pulls bob's chain (full bundle: re-delivery must also be safe).
        let outcomes = connor.apply(&bob.bundle(&[]).unwrap(), 0).unwrap();
        let ctx = outcomes.get(&PathBuf::from("ctx.md")).cloned();
        assert!(
            matches!(ctx, Some(MergeOutcome::Converged) | Some(MergeOutcome::Merged)),
            "path untouched by the incoming chain must not conflict, got {ctx:?}"
        );
        assert_eq!(outcomes[&PathBuf::from("bob.txt")], MergeOutcome::Converged);
        // Connor's own line still carries his edit.
        let tree = connor.graph.tree_at(&connor_head);
        assert_eq!(
            connor.get(&tree[&PathBuf::from("ctx.md")].0, "connor", 0).unwrap(),
            b"# context\nalpha\nbeta EDITED\n"
        );
    }

    #[test]
    fn dock_merge_of_stale_side_does_not_conflict_on_untouched_paths() {
        // Same root cause through merge_tips (#65): tip B re-sealed ctx.md
        // without touching it while tip A modified a line.
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let base_oid = repo.put(b"alpha\nbeta\n", vis.clone()).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("ctx.md"), (base_oid, vis.clone()));
        let base = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: t })
            .unwrap();

        let a_oid = repo.put(b"alpha\nbeta EDITED\n", vis.clone()).unwrap();
        let mut at = BTreeMap::new();
        at.insert(PathBuf::from("ctx.md"), (a_oid.clone(), vis.clone()));
        let tip_a = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![base.clone()],
                message: "a".into(),
                tree: at,
            })
            .unwrap();

        let b_oid = repo.put(b"alpha\nbeta\n", vis.clone()).unwrap(); // untouched re-seal
        let b_new = repo.put(b"b's file\n", vis.clone()).unwrap();
        let mut bt = BTreeMap::new();
        bt.insert(PathBuf::from("ctx.md"), (b_oid, vis.clone()));
        bt.insert(PathBuf::from("b.txt"), (b_new, vis.clone()));
        let tip_b = repo
            .record(Change { id: Oid([0; 32]), parents: vec![base], message: "b".into(), tree: bt })
            .unwrap();

        let (merge_id, outcomes) = repo.merge_tips(&tip_a, &tip_b, "merge", 0).unwrap();
        assert_eq!(outcomes[&PathBuf::from("ctx.md")], MergeOutcome::Merged);
        let tree = repo.graph.tree_at(&merge_id);
        assert_eq!(tree[&PathBuf::from("ctx.md")].0, a_oid, "the edited side wins");
        assert_eq!(outcomes[&PathBuf::from("b.txt")], MergeOutcome::Converged);
    }

    #[test]
    fn merge_tips_does_not_resurrect_a_path_deleted_before_the_fork() {
        // #288: a path deleted on the spine long before either merge side
        // forked must NOT reappear in the merge change's tree. The old
        // ancestry-union `tree_at` re-raised every deleted path into both
        // merge inputs, and the classifier — seeing the same stale address on
        // both sides — kept it.
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let keep = repo.put(b"keep\n", vis.clone()).unwrap();
        let gone = repo.put(b"doomed\n", vis.clone()).unwrap();
        let mut t0 = BTreeMap::new();
        t0.insert(PathBuf::from("keep.txt"), (keep.clone(), vis.clone()));
        t0.insert(PathBuf::from("gone.txt"), (gone, vis.clone()));
        let root = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "root".into(), tree: t0 })
            .unwrap();

        // The deletion: a full manifest without gone.txt.
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("keep.txt"), (keep.clone(), vis.clone()));
        let spine = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![root],
                message: "delete gone.txt".into(),
                tree: t1.clone(),
            })
            .unwrap();

        // Two lines fork AFTER the deletion; neither manifest holds gone.txt.
        let x = repo.put(b"x\n", vis.clone()).unwrap();
        let mut ta = t1.clone();
        ta.insert(PathBuf::from("x.txt"), (x, vis.clone()));
        let tip_a = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![spine.clone()],
                message: "a".into(),
                tree: ta,
            })
            .unwrap();
        let y = repo.put(b"y\n", vis.clone()).unwrap();
        let mut tb = t1.clone();
        tb.insert(PathBuf::from("y.txt"), (y, vis.clone()));
        let tip_b = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![spine],
                message: "b".into(),
                tree: tb,
            })
            .unwrap();

        let (merge_id, _) = repo.merge_tips(&tip_a, &tip_b, "merge", 0).unwrap();
        let tree = repo.graph.get(&merge_id).unwrap().tree.clone();
        assert!(
            !tree.contains_key(&PathBuf::from("gone.txt")),
            "merge resurrected a path both lines deleted long ago (#288): {:?}",
            tree.keys().collect::<Vec<_>>()
        );
        assert!(tree.contains_key(&PathBuf::from("keep.txt")));
        assert!(tree.contains_key(&PathBuf::from("x.txt")));
        assert!(tree.contains_key(&PathBuf::from("y.txt")));
    }

    #[test]
    fn merge_tips_honors_a_one_side_deletion_since_the_fork() {
        // #295: doomed.txt exists at the fork point. One line deletes it since
        // the fork; the other never touches it. The reconcile merge must keep
        // it DELETED — not re-adopt it from the untouched side. This is the gap
        // the #288 fix (full manifests) left open in the converge classifier.
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let keep = repo.put(b"keep\n", vis.clone()).unwrap();
        let doomed = repo.put(b"doomed\n", vis.clone()).unwrap();
        // Fork point holds both files.
        let mut t0 = BTreeMap::new();
        t0.insert(PathBuf::from("keep.txt"), (keep.clone(), vis.clone()));
        t0.insert(PathBuf::from("doomed.txt"), (doomed.clone(), vis.clone()));
        let fork = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "fork".into(), tree: t0 })
            .unwrap();

        // Line A deletes doomed.txt (full manifest omits it), adds a.txt.
        let a = repo.put(b"a\n", vis.clone()).unwrap();
        let mut ta = BTreeMap::new();
        ta.insert(PathBuf::from("keep.txt"), (keep.clone(), vis.clone()));
        ta.insert(PathBuf::from("a.txt"), (a, vis.clone()));
        let tip_a = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![fork.clone()],
                message: "delete doomed.txt".into(),
                tree: ta,
            })
            .unwrap();

        // Line B leaves doomed.txt untouched (same address), adds b.txt.
        let b = repo.put(b"b\n", vis.clone()).unwrap();
        let mut tb = BTreeMap::new();
        tb.insert(PathBuf::from("keep.txt"), (keep.clone(), vis.clone()));
        tb.insert(PathBuf::from("doomed.txt"), (doomed.clone(), vis.clone()));
        tb.insert(PathBuf::from("b.txt"), (b, vis.clone()));
        let tip_b = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![fork],
                message: "unrelated edit".into(),
                tree: tb,
            })
            .unwrap();

        // Deletion must win regardless of merge order.
        let (merge_ab, _) = repo.merge_tips(&tip_a, &tip_b, "merge a<-b", 0).unwrap();
        let tree_ab = repo.graph.get(&merge_ab).unwrap().tree.clone();
        assert!(
            !tree_ab.contains_key(&PathBuf::from("doomed.txt")),
            "one-side deletion silently undone (ours=A): {:?}",
            tree_ab.keys().collect::<Vec<_>>()
        );
        assert!(tree_ab.contains_key(&PathBuf::from("a.txt")));
        assert!(tree_ab.contains_key(&PathBuf::from("b.txt")));
        assert!(repo.conflicts.is_empty(), "an untouched-vs-deleted merge is clean");

        let (merge_ba, _) = repo.merge_tips(&tip_b, &tip_a, "merge b<-a", 0).unwrap();
        let tree_ba = repo.graph.get(&merge_ba).unwrap().tree.clone();
        assert!(
            !tree_ba.contains_key(&PathBuf::from("doomed.txt")),
            "one-side deletion silently undone (ours=B): {:?}",
            tree_ba.keys().collect::<Vec<_>>()
        );
        assert!(repo.conflicts.is_empty());
    }

    #[test]
    fn merge_tips_surfaces_a_delete_vs_edit_conflict() {
        // #295: one line deletes a path since the fork, the other edits it. That
        // is a genuine conflict — it must surface (bounce), never silently pick
        // a winner.
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let orig = repo.put(b"orig\n", vis.clone()).unwrap();
        let mut t0 = BTreeMap::new();
        t0.insert(PathBuf::from("contested.txt"), (orig.clone(), vis.clone()));
        let fork = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "fork".into(), tree: t0 })
            .unwrap();

        // Line A deletes contested.txt.
        let tip_a = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![fork.clone()],
                message: "delete".into(),
                tree: BTreeMap::new(),
            })
            .unwrap();

        // Line B edits contested.txt since the fork.
        let edited = repo.put(b"edited\n", vis.clone()).unwrap();
        let mut tb = BTreeMap::new();
        tb.insert(PathBuf::from("contested.txt"), (edited.clone(), vis.clone()));
        let tip_b = repo
            .record(Change { id: Oid([0; 32]), parents: vec![fork], message: "edit".into(), tree: tb })
            .unwrap();

        let (_merge, _) = repo.merge_tips(&tip_a, &tip_b, "merge", 0).unwrap();
        assert!(
            repo.conflicts.contains_key(&PathBuf::from("contested.txt")),
            "a delete/edit collision must surface as a conflict, not silently resolve"
        );
    }

    #[test]
    fn snapshot_with_base_forks_isolated_lines_over_one_store() {
        // The dock primitive (ADR 0022, CA1): two snapshots forked from a common
        // base tip produce independent heads that do NOT see each other's writes,
        // while sharing the object store for the base content.
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let base = repo
            .snapshot(None, None, &[entry("shared.txt", b"base", Visibility::Public)], "base", 0)
            .unwrap();

        // Fork A adds a.txt on top of base; fork B adds b.txt on top of base.
        // `entries` is the WHOLE visible tree (an absent visible path is a
        // deletion — #288), so each fork's snapshot carries the base file too;
        // unchanged content keeps its sealed address (#98).
        let a = repo
            .snapshot(
                Some(&base),
                None,
                &[
                    entry("shared.txt", b"base", Visibility::Public),
                    entry("a.txt", b"A", Visibility::Public),
                ],
                "fork a",
                0,
            )
            .unwrap();
        let b = repo
            .snapshot(
                Some(&base),
                None,
                &[
                    entry("shared.txt", b"base", Visibility::Public),
                    entry("b.txt", b"B", Visibility::Public),
                ],
                "fork b",
                0,
            )
            .unwrap();

        // Both are live heads — a local fork of the DAG, same shape as a remote push.
        assert!(repo.heads().contains(&a) && repo.heads().contains(&b), "two independent tips");

        let ta = repo.graph.tree_at(&a);
        let tb = repo.graph.tree_at(&b);
        assert!(ta.contains_key(&PathBuf::from("a.txt")) && !ta.contains_key(&PathBuf::from("b.txt")));
        assert!(tb.contains_key(&PathBuf::from("b.txt")) && !tb.contains_key(&PathBuf::from("a.txt")));

        // Shared base content is one object in the store, referenced by both.
        assert_eq!(
            ta[&PathBuf::from("shared.txt")].0, tb[&PathBuf::from("shared.txt")].0,
            "base content is shared, not duplicated"
        );
    }

    #[test]
    fn materialize_writes_target_and_prunes_stale_visible_files() {
        // Dock switch (ADR 0022): moving from fork A to fork B writes B's tree and
        // removes A-only files, without touching shared content.
        let root = tmp().join(format!("loot-materialize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut repo = DagRepo::init(root.clone(), "alice").unwrap();

        let base = repo
            .snapshot(None, None, &[entry("shared.txt", b"s", Visibility::Public)], "base", 0)
            .unwrap();
        // Real snapshots carry the full working tree, so shared.txt rides along.
        let a = repo
            .snapshot(
                Some(&base),
                None,
                &[entry("shared.txt", b"s", Visibility::Public), entry("a.txt", b"A", Visibility::Public)],
                "a",
                0,
            )
            .unwrap();
        let b = repo
            .snapshot(
                Some(&base),
                None,
                &[entry("shared.txt", b"s", Visibility::Public), entry("b.txt", b"B", Visibility::Public)],
                "b",
                0,
            )
            .unwrap();

        // Materialize A first (fresh working tree), then switch to B.
        repo.materialize(None, &a, "alice", 0).unwrap();
        assert!(root.join("a.txt").exists() && root.join("shared.txt").exists());

        repo.materialize(Some(&a), &b, "alice", 0).unwrap();
        assert!(root.join("b.txt").exists(), "target file written");
        assert!(root.join("shared.txt").exists(), "content in both trees is kept");
        assert!(!root.join("a.txt").exists(), "A-only file pruned on switch to B");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn snapshot_deletes_a_visible_path_absent_from_the_tree() {
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let w = repo
            .snapshot(
                None,
                None,
                &[
                    entry("keep.txt", b"k", Visibility::Public),
                    entry("gone.txt", b"g", Visibility::Public),
                ],
                "wip",
                0,
            )
            .unwrap();
        // Re-snapshot with gone.txt removed from the tree -> it's deleted.
        let w2 = repo
            .snapshot(None, Some(&w), &[entry("keep.txt", b"k", Visibility::Public)], "wip", 0)
            .unwrap();
        let tree = repo.graph.current_tree();
        assert!(tree.contains_key(&PathBuf::from("keep.txt")));
        assert!(!tree.contains_key(&PathBuf::from("gone.txt")), "visible+absent => deleted");
        let _ = w2;
    }

    #[test]
    fn same_tree_content_sees_a_deletion_only_child_as_different() {
        // #289: judged by the recorded manifests, a change whose only content is
        // deleting a path differs from its parent. The ancestry overlay
        // (`tree_at`) unions the parent's entry back in, so it can never see a
        // missing path — that blindness silently dropped a described
        // deletion-only change at finalize as a "tip-duplicate".
        let mut repo = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let base = repo
            .snapshot(
                None,
                None,
                &[
                    entry("keep.txt", b"k", Visibility::Public),
                    entry("gone.txt", b"g", Visibility::Public),
                ],
                "base",
                0,
            )
            .unwrap();
        // A deletion-only child: identical content minus gone.txt.
        let del = repo
            .snapshot(Some(&base), None, &[entry("keep.txt", b"k", Visibility::Public)], "del", 0)
            .unwrap();
        assert!(!repo.same_tree_content(&base, &del, 0), "a deletion-only change ≠ its parent");
        assert!(!repo.same_tree_content(&del, &base, 0), "and the judgment is symmetric");

        // Regression: a child re-recording the identical manifest still compares
        // equal — the truly-redundant drop (bare `new`, co-located checkout after
        // a `git pull`) must keep working.
        let dup = repo
            .snapshot(Some(&del), None, &[entry("keep.txt", b"k", Visibility::Public)], "dup", 0)
            .unwrap();
        assert!(repo.same_tree_content(&del, &dup, 0), "identical manifests still compare equal");
    }

    #[test]
    fn non_keyholder_snapshot_preserves_sealed_content() {
        // The core safety property (ADR 0006): a non-keyholder snapshotting their
        // partial tree must NOT delete the sealed file they cannot see.
        // Build a repo where alice committed a restricted .env + public README.
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let _ = alice
            .snapshot(
                None,
                None,
                &[
                    entry(".env", b"SECRET", Visibility::Restricted(vec!["alice".into()])),
                    entry("README", b"hi", Visibility::Public),
                ],
                "init",
                0,
            )
            .unwrap();
        // Sync the full history to bob (non-keyholder) via a bundle.
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        // Bob's visible tree is README only (he can't open .env). He has no
        // working change yet (just applied finalized history), so working=None:
        // his snapshot appends on alice's change, carrying .env forward.
        let sealed_env_oid = bob.graph.current_tree()[&PathBuf::from(".env")].0.clone();
        bob.snapshot(
            None,
            None,
            &[entry("README", b"hi edited by bob", Visibility::Public)],
            "bob edits readme",
            0,
        )
        .unwrap();

        // .env must still be present in bob's tree, carried forward as ciphertext.
        let tree = bob.graph.current_tree();
        assert!(tree.contains_key(&PathBuf::from(".env")), ".env must survive bob's snapshot");
        assert_eq!(tree[&PathBuf::from(".env")].0, sealed_env_oid, ".env carried forward unchanged");
        // And bob still cannot read it.
        assert!(matches!(
            bob.get(&sealed_env_oid, "bob", 0),
            Err(RepoError::Unauthorized(_))
        ));
    }

    #[test]
    fn snapshot_refuses_write_onto_sealed_invisible_path() {
        // Bob (non-keyholder) tries to write his own .env where alice's sealed
        // .env already lives -> refused, no silent clobber.
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let _ = alice
            .snapshot(
                None,
                None,
                &[entry(".env", b"ALICE", Visibility::Restricted(vec!["alice".into()]))],
                "init",
                0,
            )
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        let result = bob.snapshot(
            None,
            None,
            &[entry(".env", b"BOB", Visibility::Restricted(vec!["bob".into()]))],
            "bob writes own env",
            0,
        );
        assert!(matches!(result, Err(RepoError::Backend(_))), "must refuse the collision");
    }

    // --- embargo/escrow, grant/manifest, maroon, migrate (ADR 0007/0008/0009/
    // 0010) tests moved to `engine::custody`'s own test module (#323) — they
    // exercise the custody verbs and fields directly. `stow`'s purge-forwarding
    // tests below stay here: they exercise the Reconcile face's relay ingest.

    // --- path history (`loot embargo-status`, #15) ---

    /// `path_history_entry` is a thin public wrapper over
    /// `ChangeGraph::path_in_history` (unit-tested directly there); this pins
    /// the wiring through the real `DagRepo::record` path with a genuine
    /// embargoed object, both for a path still in the current tree and for
    /// one deleted off it (the "not in the working tree" AC).
    #[test]
    fn path_history_entry_finds_a_live_embargoed_path_and_survives_its_deletion() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let vis = Visibility::Embargoed { reveal_at: 500 };
        let oid = repo.put(b"cve fix\n", vis.clone()).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("plans.md"), (oid.clone(), vis.clone()));
        repo.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();

        let (found_oid, found_vis) = repo
            .path_history_entry(Path::new("plans.md"))
            .expect("path is live");
        assert_eq!(found_oid, oid);
        assert_eq!(found_vis, vis);

        // Delete the path on a child change; the live tree no longer carries
        // it, but the object's full history still explains it.
        let empty_tree = BTreeMap::new();
        repo.record(Change {
            id: Oid([1; 32]),
            parents: repo.graph.heads(),
            message: "delete".into(),
            tree: empty_tree,
        })
        .unwrap();
        assert!(
            repo.current_tree_oid(Path::new("plans.md")).is_err(),
            "precondition: gone from the live tree"
        );
        let (_, vis_after_delete) = repo
            .path_history_entry(Path::new("plans.md"))
            .expect("still explainable via history");
        assert_eq!(vis_after_delete, vis);
    }

    #[test]
    fn path_history_entry_is_none_for_a_path_never_recorded() {
        let repo = DagRepo::init(tmp(), "alice").unwrap();
        assert!(repo.path_history_entry(Path::new("never.md")).is_none());
    }

    // --- conflicts (ADR 0001) ---

    #[test]
    fn conflicts_recorded_on_apply() {
        // Two peers both edit the same public file (both are keyholders) with
        // divergent content, so the classifier produces Conflict.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        // Shared base.
        let oid_base = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Divergent edits.
        let oid_alice = alice.put(b"alice edit\n", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "alice".into(), tree: alice_tree }).unwrap();

        let oid_bob = bob.put(b"bob edit\n", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob.clone(), Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "bob".into(), tree: bob_tree }).unwrap();

        // Bob applies alice's bundle.
        let alice_bundle = alice.bundle(&bob.heads()).unwrap();
        let outcomes = bob.apply(&alice_bundle, 0).unwrap();

        let f_outcome = outcomes.get(Path::new("f.txt"));
        assert!(
            matches!(f_outcome, Some(MergeOutcome::Conflict { .. })),
            "divergent edits must produce Conflict"
        );
        assert!(bob.conflicts.contains_key(Path::new("f.txt")), "conflict must be recorded");
    }

    #[test]
    fn no_conflict_recorded_when_apply_forms_a_divergence() {
        // #198/#203: an incoming co-version of a change id we already hold
        // live is ONE two-writer event, carried by the `!` marker — apply must
        // not additionally classify its tree against ours into a per-path
        // conflict. Both peers amend the same handle from a shared base; bob
        // pulls alice's amend.
        let cid = [7u8; 16];
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        // Shared base carrying the handle.
        let oid_base = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        let x = alice
            .record_carrying(
                Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree },
                Some(cid),
            )
            .unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Concurrent amends of the SAME handle, same path: each supersedes the
        // base, neither the other.
        let oid_alice = alice.put(b"alice's take\n", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice
            .record_superseding(
                Change { id: Oid([0; 32]), parents: vec![x.clone()], message: "amend".into(), tree: alice_tree },
                Some(cid),
                vec![x.clone()],
            )
            .unwrap();

        let oid_bob = bob.put(b"bob's take\n", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob, Visibility::Public));
        bob.record_superseding(
            Change { id: Oid([0; 32]), parents: vec![x.clone()], message: "amend".into(), tree: bob_tree },
            Some(cid),
            vec![x.clone()],
        )
        .unwrap();

        let alice_bundle = alice.bundle(&bob.heads()).unwrap();
        let outcomes = bob.apply(&alice_bundle, 0).unwrap();

        assert!(
            !matches!(outcomes.get(Path::new("f.txt")), Some(MergeOutcome::Conflict { .. })),
            "a divergent co-version is not classified into a per-path conflict"
        );
        assert!(
            !bob.conflicts.contains_key(Path::new("f.txt")),
            "no conflict recorded — the ! marker carries the two-writer event"
        );
        assert_eq!(
            bob.liveness(&Default::default(), &[]).divergent().clone().len(),
            1,
            "the handle IS divergent — the event is represented exactly once"
        );
    }

    #[test]
    fn apply_with_abandoned_coversion_is_not_divergence_forming() {
        // #216 (locked in the map #215 grilling): the local abandoned set now
        // reaches ingest classification. Bob held two live co-versions of one
        // handle and ABANDONED his own side — so when alice's amend of the
        // survivor arrives, there is no second live version: it is a clean
        // replacement, classified normally, not a skipped divergence.
        let cid = [7u8; 16];
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        let oid_base = alice.put(b"base
", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        let x = alice
            .record_carrying(
                Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree },
                Some(cid),
            )
            .unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Bob's own co-version (no supersession claim), then abandoned.
        let oid_bob = bob.put(b"bob's take
", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob, Visibility::Public));
        let y = bob
            .record_carrying(
                Change { id: Oid([0; 32]), parents: vec![x.clone()], message: "take".into(), tree: bob_tree },
                Some(cid),
            )
            .unwrap();
        // Mirror `loot abandon` faithfully: the version joins the abandoned
        // set AND leaves the live heads (workspace.rs does both).
        bob.abandon_head(&y);
        let abandoned = std::collections::BTreeSet::from([y.clone()]);

        // Alice amends X (supersedes it) and ships the amend.
        let oid_alice = alice.put(b"alice's take
", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice
            .record_superseding(
                Change { id: Oid([0; 32]), parents: vec![x.clone()], message: "amend".into(), tree: alice_tree },
                Some(cid),
                vec![x.clone()],
            )
            .unwrap();
        let bundle = alice.bundle(&bob.heads()).unwrap();

        // WITH the abandoned set: y is not live, X is exempt (named in the
        // amend's predecessors) — classification runs, outcomes flow.
        let outcomes = bob.apply_with(&bundle, 0, &abandoned).unwrap();
        assert!(
            outcomes.contains_key(Path::new("f.txt")),
            "a co-version of an abandoned version classifies normally"
        );
        assert!(
            !matches!(outcomes.get(Path::new("f.txt")), Some(MergeOutcome::Conflict { .. })),
            "and it is a clean replacement, not a conflict"
        );
        assert!(
            bob.liveness(&abandoned, &[]).divergent().is_empty(),
            "no divergence: the abandoned side is not a live version"
        );
    }

    // --- relay stow (ADR 0011) ---

    #[test]
    fn stow_stores_restricted_ciphertext_without_its_key_and_never_merges() {
        // A relay stows alice's bundle carrying RESTRICTED content. It gains the
        // ciphertext and the change as a tip, but receives no restricted key
        // (those never travel — ADR 0003), so it cannot read it. It also records
        // no conflict and surfaces no working tree: storage + forwarding only.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let restricted = Visibility::Restricted(vec!["alice".into()]);
        let oid = alice.put(b"secret\n", restricted.clone()).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (oid.clone(), restricted));
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree })
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();

        // Object stored as ciphertext; the change is now a tip.
        assert!(relay.object(&oid).is_ok(), "relay must store the ciphertext");
        assert!(relay.heads().contains(&change_id), "relay must hold the change");
        // The relay holds no key for restricted content and cannot read it.
        assert!(!relay.custody.keyring.holds(&oid), "a relay must never hold a restricted key");
        assert!(relay.get(&oid, "relay", 0).is_err(), "relay must not read restricted content");
        // Nothing classified, nothing conflicted.
        assert!(relay.conflicts.is_empty(), "stow must never record a conflict");
    }

    #[test]
    fn stow_forwards_public_keys_so_downstream_peers_can_read() {
        // Public content is ANYONE-granted, so its key travels in every sync
        // bundle (ADR 0003). A relay must retain that key and forward it, or a
        // downstream peer would receive unreadable public ciphertext.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"readme\n", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("README"), (oid.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // A fresh peer pulls from the relay and can read the public content.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&relay.bundle(&[]).unwrap(), 0).unwrap();
        assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"readme\n", "public content must survive the relay hop");
    }

    #[test]
    fn stow_accumulates_concurrent_forks_without_conflict() {
        // Two peers fork from a shared base. A relay stows both. The relay's
        // graph holds both tips (a fork) and records no conflict — convergence
        // is the keyholders' job on pull, not the relay's.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let base_oid = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (base_oid, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // Bob clones the base off the relay's state by applying the same seed.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[]).unwrap(), 0).unwrap();

        // Divergent edits on the same path.
        let a_oid = alice.put(b"alice\n", Visibility::Public).unwrap();
        let mut a_tree = BTreeMap::new();
        a_tree.insert(PathBuf::from("f.txt"), (a_oid, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "a".into(), tree: a_tree }).unwrap();

        let b_oid = bob.put(b"bob\n", Visibility::Public).unwrap();
        let mut b_tree = BTreeMap::new();
        b_tree.insert(PathBuf::from("f.txt"), (b_oid, Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "b".into(), tree: b_tree }).unwrap();

        // Relay stows both pushes. No merge, no conflict — just two tips.
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();
        relay.stow(&bob.bundle(&[]).unwrap()).unwrap();

        assert!(relay.conflicts.is_empty(), "relay must never manufacture a conflict");
        assert!(relay.heads().len() >= 2, "relay must hold the forked tips, uncollapsed");
    }

    #[test]
    fn stow_rejects_grant_bundles() {
        // A grant bundle (tag 1) is a targeted key handoff — meaningless to a
        // keyless relay. Stow rejects it rather than silently dropping it.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"secret\n", Visibility::Restricted(vec!["alice".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from(".env"), (oid.clone(), Visibility::Restricted(vec!["alice".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();
        let grant = alice.grant(&oid, "bob", 0, None).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        assert!(matches!(relay.stow(&grant), Err(RepoError::Backend(_))), "relay must reject grant bundles");
    }

    #[test]
    fn stow_forwards_purges_downstream() {
        // A hard-maroon purge event rides a sync bundle. A relay stows it,
        // holds no keyring entry to remove, but re-emits the purge in its own
        // bundle so a downstream marooned peer still receives it.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"code\n", Visibility::Restricted(vec!["alice".into(), "bob".into()])).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("src.rs"), (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "init".into(), tree }).unwrap();
        // Grant bob so the manifest knows him, then hard-maroon him.
        alice.grant(&oid, "bob", 0, None).unwrap();
        alice.maroon_hard(Path::new("src.rs"), "bob", 1).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&alice.bundle(&[]).unwrap()).unwrap();

        // The relay re-emits the purge in its own outgoing bundle.
        let relay_out = relay.bundle(&[]).unwrap();
        let purges = match bundle_codec::Frame::decode(&relay_out.0).unwrap() {
            bundle_codec::Frame::Sync { purges, .. } => purges,
            _ => panic!("relay bundle must be a sync frame"),
        };
        assert!(
            purges.iter().any(|(o, who)| *o == oid && who == "bob"),
            "relay must forward the purge event downstream"
        );
    }

    #[test]
    fn resolve_clears_conflict_and_updates_tree() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();

        // Shared base.
        let oid_base = alice.put(b"base\n", Visibility::Public).unwrap();
        let mut base_tree = BTreeMap::new();
        base_tree.insert(PathBuf::from("f.txt"), (oid_base.clone(), Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree }).unwrap();
        let seed = alice.bundle(&[]).unwrap();
        bob.apply(&seed, 0).unwrap();

        // Divergent edits.
        let oid_alice = alice.put(b"alice\n", Visibility::Public).unwrap();
        let mut alice_tree = BTreeMap::new();
        alice_tree.insert(PathBuf::from("f.txt"), (oid_alice, Visibility::Public));
        alice.record(Change { id: Oid([0; 32]), parents: alice.graph.heads(), message: "alice".into(), tree: alice_tree }).unwrap();

        let oid_bob_edit = bob.put(b"bob\n", Visibility::Public).unwrap();
        let mut bob_tree = BTreeMap::new();
        bob_tree.insert(PathBuf::from("f.txt"), (oid_bob_edit.clone(), Visibility::Public));
        bob.record(Change { id: Oid([0; 32]), parents: bob.graph.heads(), message: "bob".into(), tree: bob_tree }).unwrap();

        let alice_bundle = alice.bundle(&bob.heads()).unwrap();
        bob.apply(&alice_bundle, 0).unwrap();

        // Ensure conflict is recorded.
        assert!(bob.conflicts.contains_key(Path::new("f.txt")));

        // Resolve.
        let resolution = b"resolved content\n";
        let (_change, new_oid) = bob.resolve(None, Path::new("f.txt"), resolution, Visibility::Public, 0).unwrap();

        // Conflict cleared.
        assert!(!bob.conflicts.contains_key(Path::new("f.txt")), "conflict must be cleared after resolve");

        // Tree updated.
        let tree = bob.graph.current_tree();
        assert_eq!(tree[Path::new("f.txt")].0, new_oid, "tree must point to resolution oid");
    }

    #[test]
    fn resolve_unknown_path_errors() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.resolve(None, Path::new("no-conflict.txt"), b"resolution", Visibility::Public, 0);
        assert!(matches!(result, Err(RepoError::Backend(_))), "unknown path must error");
    }

    // --- #337: a resolution inherits the ours-line subject ------------------
    // A bounced land is reconciled with `loot resolve`, which used to mint
    // every resolution change as "resolve conflict at <path>" — so git main
    // read as a wall of placeholders with the real subjects buried. The
    // resolution now inherits the nearest describable subject on the ours
    // line (first-parent walk from `base`, skipping merges and placeholder
    // subjects); the placeholder survives only as the fallback.

    /// A conflicted reconcile in miniature: base → ours edit (message
    /// `subject`) and theirs edit of the same `paths`, merged as the ferry
    /// does. Returns the repo and the conflicted merge id.
    fn bounced_merge(subject: &str, paths: &[&str]) -> (DagRepo, Oid) {
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let mut base_tree = BTreeMap::new();
        let base_oid = repo.put(b"base\n", vis.clone()).unwrap();
        for p in paths {
            base_tree.insert(PathBuf::from(p), (base_oid.clone(), vis.clone()));
        }
        let base = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "base".into(), tree: base_tree })
            .unwrap();

        let ours_oid = repo.put(b"ours\n", vis.clone()).unwrap();
        let mut ours_tree = BTreeMap::new();
        for p in paths {
            ours_tree.insert(PathBuf::from(p), (ours_oid.clone(), vis.clone()));
        }
        let ours = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![base.clone()],
                message: subject.into(),
                tree: ours_tree,
            })
            .unwrap();

        let theirs_oid = repo.put(b"theirs\n", vis.clone()).unwrap();
        let mut their_tree = BTreeMap::new();
        for p in paths {
            their_tree.insert(PathBuf::from(p), (theirs_oid.clone(), vis.clone()));
        }
        let theirs = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![base],
                message: "landed on main meanwhile".into(),
                tree: their_tree,
            })
            .unwrap();

        let (merge, _) = repo.merge_tips(&ours, &theirs, "ferry: reconcile git main", 0).unwrap();
        for p in paths {
            assert!(repo.conflicts.contains_key(Path::new(p)), "precondition: {p} conflicted");
        }
        (repo, merge)
    }

    #[test]
    fn resolve_inherits_the_ours_line_subject_over_a_bounced_merge() {
        let subject = "loot grant-status <path>: list current grantees (#5)";
        let (mut repo, merge) = bounced_merge(subject, &["contested.txt"]);
        let (res, _) = repo
            .resolve(Some(&merge), Path::new("contested.txt"), b"resolved\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&res).unwrap().message,
            format!("{subject} (conflict resolution: contested.txt)"),
            "the resolution carries the landed change's subject, not the placeholder"
        );
    }

    #[test]
    fn sequential_resolutions_inherit_without_stacking_suffixes() {
        // A multi-path bounce resolves one path at a time, each resolution
        // building on the previous one — inheriting through a sibling
        // resolution must re-derive the bare subject, not stack suffixes.
        let subject = "wave subject (#23)";
        let (mut repo, merge) = bounced_merge(subject, &["a.txt", "d.txt"]);
        let (r1, _) = repo
            .resolve(Some(&merge), Path::new("a.txt"), b"resolved a\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&r1).unwrap().message,
            format!("{subject} (conflict resolution: a.txt)")
        );
        let (r2, _) = repo
            .resolve(Some(&r1), Path::new("d.txt"), b"resolved d\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&r2).unwrap().message,
            format!("{subject} (conflict resolution: d.txt)"),
            "no suffix stacking through the sibling resolution"
        );
    }

    #[test]
    fn resolve_walks_past_a_legacy_placeholder_subject() {
        // An ours line whose tip is an old-style placeholder resolution still
        // yields the real subject beneath it.
        let subject = "the real subject (#42)";
        let (mut repo, merge) = bounced_merge(subject, &["contested.txt"]);
        // Splice a legacy placeholder change between the merge and resolve:
        // resolve builds on it, exactly like a pre-#337 partial reconcile.
        let oid = repo.put(b"legacy\n", Visibility::Public).unwrap();
        let mut tree = repo.graph.tree_at(&merge);
        tree.insert(PathBuf::from("other.txt"), (oid, Visibility::Public));
        let legacy = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![merge],
                message: "resolve conflict at other.txt".into(),
                tree,
            })
            .unwrap();
        let (res, _) = repo
            .resolve(Some(&legacy), Path::new("contested.txt"), b"resolved\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&res).unwrap().message,
            format!("{subject} (conflict resolution: contested.txt)"),
            "the walk skips placeholder subjects on its way to the real one"
        );
    }

    #[test]
    fn resolve_without_a_base_keeps_the_placeholder() {
        // The pre-dock home flow (base = None) has no single ours line to
        // inherit from — the placeholder stays, and loot-first's land gate
        // (#316) keeps refusing it.
        let (mut repo, _merge) = bounced_merge("some subject", &["contested.txt"]);
        let (res, _) = repo
            .resolve(None, Path::new("contested.txt"), b"resolved\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&res).unwrap().message,
            "resolve conflict at contested.txt"
        );
    }

    #[test]
    fn resolve_walks_past_an_undescribed_working_change_subject() {
        // "(working change)" is loot-cli's un-described placeholder
        // (`UNDESCRIBED_MESSAGE`); a finalized bare one has reached git main
        // before (fd926e4). Inheriting it would mint an undescribed subject
        // that additionally evades the #316 land gate — skip it like the
        // resolve placeholder.
        let subject = "the real subject (#42)";
        let (mut repo, merge) = bounced_merge(subject, &["contested.txt"]);
        let oid = repo.put(b"wip\n", Visibility::Public).unwrap();
        let mut tree = repo.graph.tree_at(&merge);
        tree.insert(PathBuf::from("other.txt"), (oid, Visibility::Public));
        let undescribed = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![merge],
                message: "(working change)".into(),
                tree,
            })
            .unwrap();
        let (res, _) = repo
            .resolve(Some(&undescribed), Path::new("contested.txt"), b"resolved\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&res).unwrap().message,
            format!("{subject} (conflict resolution: contested.txt)"),
            "an undescribed placeholder subject is never inherited"
        );
    }

    #[test]
    fn resolve_falls_back_when_the_walk_finds_no_subject() {
        // An ours line made only of placeholder subjects derives nothing —
        // fall back rather than inherit a placeholder.
        let vis = Visibility::Public;
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let base_oid = repo.put(b"base\n", vis.clone()).unwrap();
        let mut t0 = BTreeMap::new();
        t0.insert(PathBuf::from("contested.txt"), (base_oid, vis.clone()));
        let root = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "resolve conflict at ancient.txt".into(),
                tree: t0,
            })
            .unwrap();
        let ours_oid = repo.put(b"ours\n", vis.clone()).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("contested.txt"), (ours_oid, vis.clone()));
        let ours = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![root.clone()],
                message: "resolve conflict at old.txt".into(),
                tree: t1,
            })
            .unwrap();
        let theirs_oid = repo.put(b"theirs\n", vis.clone()).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("contested.txt"), (theirs_oid, vis.clone()));
        let theirs = repo
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![root],
                message: "resolve conflict at other-old.txt".into(),
                tree: t2,
            })
            .unwrap();
        let (merge, _) = repo.merge_tips(&ours, &theirs, "ferry: reconcile git main", 0).unwrap();
        let (res, _) = repo
            .resolve(Some(&merge), Path::new("contested.txt"), b"resolved\n", Visibility::Public, 0)
            .unwrap();
        assert_eq!(
            repo.graph.get(&res).unwrap().message,
            "resolve conflict at contested.txt"
        );
    }

    // --- golden-byte fixtures + major-rejection for conflicts (ADR 0019) ---
    // The manifest/purges goldens moved to `engine::custody`'s test module
    // (#323) alongside `encode_manifest`/`decode_manifest`/`encode_purges`/
    // `decode_purges`, which they lock the layout of.

    // conflicts: one entry — path="f.txt", ours=[7;32], theirs=[8;32].
    // Layout: [major=1][minor=0][count=1 u32le][put_bytes("f.txt")=9][ours 32][theirs 32]
    const GOLDEN_CONFLICTS_V1: [u8; 79] = [
        1, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116, // put_bytes("f.txt")
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // ours=[7;32]
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, // theirs=[8;32]
    ];

    // v2 golden (current format, FORMAT_MAJOR = 2, ADR 0020). Layout is
    // unchanged from v1; only the marker byte differs.
    const GOLDEN_CONFLICTS_V2: [u8; 79] = [
        2, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];

    // v3 golden (current format, FORMAT_MAJOR = 3, ADR 0018). This artifact
    // contains no changes, so its layout is unchanged from v2 — only the
    // marker byte differs.
    const GOLDEN_CONFLICTS_V3: [u8; 79] = [
        3, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];

    // v4 golden (FORMAT_MAJOR = 4). conflicts layout unchanged in S4 — only
    // the marker. The attestation log is new in v4.
    const GOLDEN_CONFLICTS_V4: [u8; 79] = [
        4, 0, 1, 0, 0, 0,
        5, 0, 0, 0, 102, 46, 116, 120, 116,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    ];
    // attestation log: 1 entry — change_id=[1;32], attester=[7;32], role="reviewed", sig=[9;64].
    const GOLDEN_ATTEST_V4: [u8; 146] = [
        4, 0, 1, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        8, 0, 0, 0, 114, 101, 118, 105, 101, 119, 101, 100,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
        9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
    ];

    #[test]
    fn v1_conflicts_still_decodes() {
        let back = decode_conflicts(&GOLDEN_CONFLICTS_V1).unwrap();
        let (ours, theirs) = &back[Path::new("f.txt")];
        assert_eq!(*ours, Oid([7; 32]));
        assert_eq!(*theirs, Oid([8; 32]));
    }

    #[test]
    fn v2_conflicts_still_decodes() {
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V2).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn v3_conflicts_still_decodes() {
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V3).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn golden_v4_conflicts_matches_and_round_trips() {
        let mut conflicts = BTreeMap::new();
        conflicts.insert(PathBuf::from("f.txt"), (Oid([7; 32]), Oid([8; 32])));
        let mut golden_v5 = GOLDEN_CONFLICTS_V4.to_vec();
        golden_v5[0] = crate::format::FORMAT_MAJOR;
        assert_eq!(encode_conflicts(&conflicts), golden_v5, "v5 conflicts layout must not drift");
        assert!(decode_conflicts(&GOLDEN_CONFLICTS_V4).unwrap().contains_key(Path::new("f.txt")));
    }

    #[test]
    fn golden_v4_attestations_layout_matches() {
        // Encode-direction golden: fixed bytes (with a placeholder signature)
        // lock the durable *layout* so it cannot drift. Decode is not exercised
        // here — `decode_attestations` now re-verifies and would drop this
        // placeholder signature; disk decode is covered by the round-trip tests.
        let mut log = AttestationLog::new();
        log.insert(Attestation {
            change_id: Oid([1; 32]),
            attester: [7; 32],
            role: "reviewed".into(),
            signature: [9; 64],
        });
        let mut golden_v5 = GOLDEN_ATTEST_V4.to_vec();
        golden_v5[0] = crate::format::FORMAT_MAJOR;
        assert_eq!(encode_attestations(&log), golden_v5, "v5 attestation layout must not drift");
    }

    #[test]
    fn valid_attestations_survive_disk_round_trip() {
        let (sk, pk) = test_signer(9);
        let mut log = AttestationLog::new();
        log.insert(make_attestation(&sk, pk, Oid([1; 32]), "reviewed"));
        let back = decode_attestations(&encode_attestations(&log)).unwrap();
        assert_eq!(back.for_change(&Oid([1; 32])).len(), 1, "valid attestation survives disk load");
    }

    #[test]
    fn invalid_attestation_dropped_on_disk_load() {
        // A tampered on-disk log must not be trusted just because it was on disk.
        let (sk, pk) = test_signer(9);
        let mut att = make_attestation(&sk, pk, Oid([1; 32]), "reviewed");
        att.signature[0] ^= 0xff; // corrupt after signing
        let mut log = AttestationLog::new();
        log.insert(att);
        let back = decode_attestations(&encode_attestations(&log)).unwrap();
        assert!(back.is_empty(), "invalid on-disk attestation is dropped on load");
    }

    // ---- S3: authored, signed history (ADR 0018) ----

    /// A deterministic ed25519 test keypair (seeded, no RNG needed).
    fn test_signer(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn authored_change(id: Oid, author: [u8; 32], signature: Option<[u8; 64]>) -> ChangeNode {
        ChangeNode {
            id,
            parents: vec![],
            message: "m".into(),
            tree: BTreeMap::new(),
            author: Some(author),
            signature,
            change_id: None,
            predecessors: Vec::new(),
        }
    }

    fn bundle_of(node: ChangeNode) -> SyncBundle {
        let body = BundleBody {
            changes: vec![node],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![],
        };
        SyncBundle(Frame::Sync { purges: vec![], body }.encode())
    }

    #[test]
    fn author_is_part_of_change_id() {
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f"), (Oid([9; 32]), Visibility::Public));
        let change = Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree };
        let (_s1, pk1) = test_signer(1);
        let (_s2, pk2) = test_signer(2);
        let id_legacy = compute_change_id(None, &change, &[]);
        let id1 = compute_change_id(Some(&pk1), &change, &[]);
        let id2 = compute_change_id(Some(&pk2), &change, &[]);
        assert_ne!(id1, id2, "same edit by two authors must yield different ids");
        assert_ne!(id1, id_legacy, "authored id must differ from the legacy (unauthored) id");
    }

    #[test]
    fn signed_change_verifies_through_apply() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let node = authored_change(id.clone(), pk, Some(sk.sign(&id.0).to_bytes()));
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        assert!(bob.apply(&bundle_of(node), 0).is_ok(), "a validly signed change must apply");
    }

    #[test]
    fn v6_change_signed_over_both_ids_verifies_through_apply() {
        // ADR 0029: a v6 change signs over `version_id ‖ change_id`. A signature
        // built over that wider message must verify on apply.
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let cid = Some([0xAB; 16]);
        let mut node = authored_change(id.clone(), pk, None);
        node.change_id = cid;
        node.signature = Some(sk.sign(&change_signing_message(&id, &cid, &[])).to_bytes());
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        assert!(bob.apply(&bundle_of(node), 0).is_ok(), "a change signed over both ids must apply");
    }

    #[test]
    fn apply_rejects_change_id_relabelled_after_signing() {
        // The signature binds the change id (ADR 0029): a peer that keeps the
        // signed bytes but swaps the change_id (relabelling signed content under a
        // different handle) must be rejected.
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let signed_cid = Some([0xAB; 16]);
        let mut node = authored_change(id.clone(), pk, None);
        // Signed over change_id 0xAB…, but the node now carries a different one.
        node.signature = Some(sk.sign(&change_signing_message(&id, &signed_cid, &[])).to_bytes());
        node.change_id = Some([0xCD; 16]);
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(node), 0),
            Err(RepoError::BadChangeSignature(_))
        ));
    }

    #[test]
    fn apply_rejects_predecessors_stripped_or_forged_after_signing() {
        // The signature covers the predecessors (ADR 0032): a peer that keeps
        // the signed bytes but strips the supersession claim (resurrecting the
        // superseded version at every downstream peer) — or forges one onto a
        // change that never made it — must be rejected.
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let cid = Some([0xAB; 16]);
        let preds = vec![Oid([3; 32])];

        // Signed WITH the claim, shipped without it.
        let mut stripped = authored_change(id.clone(), pk, None);
        stripped.change_id = cid;
        stripped.signature = Some(sk.sign(&change_signing_message(&id, &cid, &preds)).to_bytes());
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(stripped), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // Signed WITHOUT a claim, shipped with one forged on.
        let mut forged = authored_change(id.clone(), pk, None);
        forged.change_id = cid;
        forged.signature = Some(sk.sign(&change_signing_message(&id, &cid, &[])).to_bytes());
        forged.predecessors = preds.clone();
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(forged), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // The honest node — signed over what it ships — applies.
        let mut honest = authored_change(id.clone(), pk, None);
        honest.change_id = cid;
        honest.predecessors = preds.clone();
        honest.signature = Some(sk.sign(&change_signing_message(&id, &cid, &preds)).to_bytes());
        assert!(DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(honest), 0).is_ok());
    }

    #[test]
    fn predecessors_fold_into_the_version_id_canonically() {
        // ADR 0032: a no-op amend (same author/message/parents/tree) must still
        // mint a DISTINCT version — otherwise "X′ supersedes X" collapses into X
        // superseding itself — and two writers naming the same set in different
        // orders must agree on the id.
        let change = Change {
            id: Oid([0; 32]),
            parents: vec![],
            message: "m".into(),
            tree: BTreeMap::new(),
        };
        let (_s, pk) = test_signer(1);
        let plain = compute_change_id(Some(&pk), &change, &[]);
        let a = Oid([1; 32]);
        let b = Oid([2; 32]);
        let ab = compute_change_id(Some(&pk), &change, &[a.clone(), b.clone()]);
        let ba = compute_change_id(Some(&pk), &change, &[b, a.clone()]);
        let just_a = compute_change_id(Some(&pk), &change, &[a]);
        assert_ne!(plain, just_a, "a superseding version differs from its no-op twin");
        assert_ne!(just_a, ab, "the claimed set is part of the id");
        assert_eq!(ab, ba, "predecessors hash canonically (order-independent)");
    }

    #[test]
    fn a_superseded_version_leaves_the_live_view_but_stays_addressable() {
        // ADR 0032 liveness: live = in-graph ∧ ¬abandoned ∧ ¬superseded. A solo
        // amend (one live successor naming its predecessor) is NOT divergence;
        // abandoning the successor kills the change rather than resurrecting the
        // predecessor (abandon means kill, never revert).
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let cid = [7u8; 16];
        let x = repo
            .record_carrying(
                Change { id: Oid([0; 32]), parents: vec![], message: "X".into(), tree: Default::default() },
                Some(cid),
            )
            .unwrap();
        let x2 = repo
            .record_superseding(
                Change { id: Oid([0; 32]), parents: vec![], message: "X".into(), tree: Default::default() },
                Some(cid),
                vec![x.clone()],
            )
            .unwrap();
        assert_ne!(x, x2, "the amend minted a distinct sibling version");
        let none = std::collections::BTreeSet::new();
        assert!(repo.liveness(&none, &[]).superseded().contains(&x));
        assert!(repo.liveness(&none, &[]).divergent().clone().is_empty(), "a solo amend is not divergence");
        assert_eq!(repo.liveness(&none, &[]).live_of(&cid), vec![x2.clone()], "one live version");

        // Abandoning the amend leaves ZERO live versions — X stays superseded.
        let mut abandoned = std::collections::BTreeSet::new();
        abandoned.insert(x2);
        assert!(
            repo.liveness(&abandoned, &[]).live_of(&cid).is_empty(),
            "abandon kills the change; it never resurrects the superseded version"
        );

        // Two live successors naming the same predecessor — the concurrent
        // amend — IS divergence, and exactly between the two amends.
        let x3 = repo
            .record_superseding(
                Change { id: Oid([0; 32]), parents: vec![], message: "X other".into(), tree: Default::default() },
                Some(cid),
                vec![x.clone()],
            )
            .unwrap();
        assert!(repo.liveness(&none, &[]).divergent().clone().contains(&cid));
        let live = repo.liveness(&none, &[]).live_of(&cid);
        assert!(!live.contains(&x) && live.len() == 2 && live.contains(&x3));
    }

    #[test]
    fn apply_rejects_missing_forged_and_tampered_signatures() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);

        // Names an author but carries no signature — a stripped signature.
        let missing = authored_change(id.clone(), pk, None);
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(missing), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // Signature is valid ed25519 but over a different message (forged/tampered).
        let forged = authored_change(id.clone(), pk, Some(sk.sign(b"not the id").to_bytes()));
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(forged), 0),
            Err(RepoError::BadChangeSignature(_))
        ));

        // Signature by the wrong key (author claims pk but a different key signed).
        let (other, _) = test_signer(8);
        let wrong_key = authored_change(id.clone(), pk, Some(other.sign(&id.0).to_bytes()));
        assert!(matches!(
            DagRepo::init(tmp(), "bob").unwrap().apply(&bundle_of(wrong_key), 0),
            Err(RepoError::BadChangeSignature(_))
        ));
    }

    #[test]
    fn relay_stow_preserves_author_and_signature() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);
        let node = authored_change(id.clone(), pk, Some(sk.sign(&id.0).to_bytes()));

        // A keyless relay verifies then stows, and re-bundles downstream with the
        // author + signature intact — authorship survives the relay hop (ADR 0018).
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle_of(node)).unwrap();
        let out = relay.bundle(&[]).unwrap();
        match Frame::decode(&out.0).unwrap() {
            Frame::Sync { body, .. } => {
                let c = body.changes.iter().find(|c| c.id == id).expect("change survived the relay");
                assert_eq!(c.author, Some(pk), "author must survive the relay hop");
                assert!(c.signature.is_some(), "signature must survive the relay hop");
            }
            _ => panic!("expected Sync"),
        }
    }

    // ---- S4: attestation lane (ADR 0018) ----

    fn make_attestation(sk: &ed25519_dalek::SigningKey, pk: [u8; 32], change: Oid, role: &str) -> Attestation {
        use ed25519_dalek::Signer;
        let signature = sk.sign(&crate::attestation::signing_bytes(&change, &pk, role)).to_bytes();
        Attestation { change_id: change, attester: pk, role: role.into(), signature }
    }

    fn attestation_bundle(atts: Vec<Attestation>) -> SyncBundle {
        let body = BundleBody {
            changes: vec![],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: atts,
        };
        SyncBundle(Frame::Sync { purges: vec![], body }.encode())
    }

    #[test]
    fn attestation_round_trips_through_apply() {
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&attestation_bundle(vec![att]), 0).unwrap();
        let got = bob.attestations_for(&Oid([5; 32]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].role, "reviewed");
        assert_eq!(got[0].attester, pk);
    }

    #[test]
    fn invalid_attestation_is_dropped_not_fatal() {
        let (sk, pk) = test_signer(9);
        let good = make_attestation(&sk, pk, Oid([6; 32]), "kept");
        let mut bad = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        bad.signature[0] ^= 0xff; // corrupt the signature

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        // apply must NOT fail on a bad attestation (advisory, unlike change sigs).
        bob.apply(&attestation_bundle(vec![bad, good]), 0).unwrap();
        assert!(bob.attestations_for(&Oid([5; 32])).is_empty(), "invalid attestation dropped");
        assert_eq!(bob.attestations_for(&Oid([6; 32])).len(), 1, "valid attestation kept");
    }

    #[test]
    fn attestation_does_not_change_change_id() {
        let (sk, pk) = test_signer(9);
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        repo.set_author(pk);
        let oid = repo.put(b"x", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f"), (oid, Visibility::Public));
        let id = repo
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "m".into(), tree })
            .unwrap();
        let heads_before = repo.heads();
        assert!(repo.add_attestation(make_attestation(&sk, pk, id.clone(), "reviewed")));
        assert_eq!(repo.heads(), heads_before, "attesting must not touch the graph or ids");
        assert_eq!(repo.attestations_for(&id).len(), 1);
    }

    #[test]
    fn mint_next_change_id_only_when_authored() {
        // The eager-handle mint mirrors `record`'s rule: an unsigned change gets
        // no durable handle (ADR 0029), so a keyless repo mints `None`.
        let mut repo = DagRepo::init(tmp(), "connor").unwrap();
        assert_eq!(repo.mint_next_change_id(), None, "keyless repo mints no handle");
        let (_sk, pk) = test_signer(3);
        repo.set_author(pk);
        assert!(repo.mint_next_change_id().is_some(), "authored repo mints a handle");
    }

    #[test]
    fn snapshot_assigns_eager_handle_then_carries_it_over_a_new_assign() {
        // ADR 0029/0030: the handle `new` minted eagerly lands on the fresh
        // change's first version; a re-snapshot carries the node's handle and
        // ignores any new assign (a change keeps one handle while edited).
        let (_sk, pk) = test_signer(7);
        let mut repo = DagRepo::init(tmp(), "connor").unwrap();
        repo.set_author(pk);
        let handle = [0x5A; 16];
        let entries = vec![(PathBuf::from("f"), b"one".to_vec(), Visibility::Public)];
        let v1 = repo
            .snapshot_assigning(None, None, &entries, "m", 0, &[], Some(handle))
            .unwrap();
        assert_eq!(repo.change_change_id(&v1), Some(handle), "assign lands on the fresh change");

        let entries2 = vec![(PathBuf::from("f"), b"two".to_vec(), Visibility::Public)];
        let v2 = repo
            .snapshot_assigning(None, Some(&v1), &entries2, "m", 0, &[], Some([0x11; 16]))
            .unwrap();
        assert_ne!(v1, v2, "a content change moves the version id");
        assert_eq!(
            repo.change_change_id(&v2),
            Some(handle),
            "the carried handle wins over a fresh assign"
        );
    }

    #[test]
    fn working_preview_is_pure_and_detects_empty() {
        // The read-only status/log figure (ADR 0030): deterministic, empty when
        // the tree matches the tip, and moving with content — all without
        // recording a node or advancing the graph.
        let (_sk, pk) = test_signer(4);
        let mut repo = DagRepo::init(tmp(), "connor").unwrap();
        repo.set_author(pk);
        let entries = vec![(PathBuf::from("f"), b"hello".to_vec(), Visibility::Public)];
        let tip = repo
            .snapshot_assigning(None, None, &entries, "m", 0, &[], Some([1; 16]))
            .unwrap();
        let heads_before = repo.heads();

        let (v_a, empty_a) = repo.working_preview(Some(&tip), &entries, "m", 0);
        let (v_b, empty_b) = repo.working_preview(Some(&tip), &entries, "m", 0);
        assert_eq!(v_a, v_b, "preview is a pure function of content");
        assert!(empty_a && empty_b, "no delta over the tip -> empty");

        let changed = vec![(PathBuf::from("f"), b"hello world".to_vec(), Visibility::Public)];
        let (v_c, empty_c) = repo.working_preview(Some(&tip), &changed, "m", 0);
        assert!(!empty_c, "a delta over the tip is not empty");
        assert_ne!(v_a, v_c, "the live version moves with content");
        assert_eq!(repo.heads(), heads_before, "preview never advances the graph");
    }

    /// A legacy (unauthored) change with an arbitrary id — travels through a
    /// relay, so an attestation over it can ride along.
    fn carried_change(id: Oid) -> ChangeNode {
        ChangeNode {
            id,
            parents: vec![],
            message: "m".into(),
            tree: BTreeMap::new(),
            author: None,
            signature: None,
            change_id: None,
            predecessors: Vec::new(),
        }
    }

    #[test]
    fn relay_preserves_attestations_for_changes_it_carries() {
        // Strict send-set filtering (#42/#48): an attestation rides only with its
        // change. A relay that carries the change also forwards its attestation.
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let body = BundleBody {
            changes: vec![carried_change(Oid([5; 32]))],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![att],
        };
        let bundle = SyncBundle(Frame::Sync { purges: vec![], body }.encode());
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();
        match Frame::decode(&relay.bundle(&[]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => {
                assert_eq!(body.attestations.len(), 1, "attestation rides with its carried change");
                assert_eq!(body.attestations[0].attester, pk);
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_omits_attestations_for_changes_not_sent() {
        // The change is NOT in the send set, so its attestation must not ship —
        // shipping it would leak the change's existence and reviewers (#42).
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&attestation_bundle(vec![att])).unwrap(); // attestation only, no change
        match Frame::decode(&relay.bundle(&[]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => {
                assert!(body.attestations.is_empty(), "orphan attestation must not be shipped");
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn bundle_omits_attestations_for_changes_the_recipient_already_holds() {
        // Delta filter (#48): the change IS carried in the graph, but the
        // recipient's `have` set already includes it, so it falls out of the
        // send set — and its attestation must not be re-sent. Incremental sync
        // grows with new changes, not with total attestation history.
        let (sk, pk) = test_signer(9);
        let att = make_attestation(&sk, pk, Oid([5; 32]), "reviewed");
        let body = BundleBody {
            changes: vec![carried_change(Oid([5; 32]))],
            objs: BTreeMap::new(),
            keys: BTreeMap::new(),
            attestations: vec![att],
        };
        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&SyncBundle(Frame::Sync { purges: vec![], body }.encode())).unwrap();

        // Sanity: a full bundle (have = []) still carries the attestation...
        match Frame::decode(&relay.bundle(&[]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => assert_eq!(body.attestations.len(), 1, "full bundle carries it"),
            _ => panic!("expected Sync"),
        }
        // ...but an incremental bundle whose recipient already holds change 5 omits it.
        match Frame::decode(&relay.bundle(&[Oid([5; 32])]).unwrap().0).unwrap() {
            Frame::Sync { body, .. } => {
                assert!(body.changes.is_empty(), "held change is not re-sent");
                assert!(
                    body.attestations.is_empty(),
                    "attestation for an already-held change must not be re-sent"
                );
            }
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn stow_rejects_authored_change_with_missing_or_bad_signature() {
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(7);
        let id = Oid([5; 32]);

        let missing_sig = authored_change(id.clone(), pk, None);
        assert!(
            matches!(
                DagRepo::init(tmp(), "relay").unwrap().stow(&bundle_of(missing_sig)),
                Err(RepoError::BadChangeSignature(_))
            ),
            "stow must reject authored change with no signature"
        );

        let forged = authored_change(id.clone(), pk, Some(sk.sign(b"wrong").to_bytes()));
        assert!(
            matches!(
                DagRepo::init(tmp(), "relay").unwrap().stow(&bundle_of(forged)),
                Err(RepoError::BadChangeSignature(_))
            ),
            "stow must reject authored change with a forged signature"
        );
    }

    // ---- S5: object-level "wants" negotiation ----

    fn objs_in(bundle: &SyncBundle) -> BTreeMap<Oid, SealedObject> {
        match Frame::decode(&bundle.0).unwrap() {
            Frame::Sync { body, .. } => body.objs,
            _ => panic!("expected Sync"),
        }
    }

    #[test]
    fn negotiation_transfers_only_missing_objects() {
        // Alice: two changes, each adding one public object (A then B).
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"aaaa", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a"), (a.clone(), Visibility::Public));
        let c1 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        let b = alice.put(b"bbbb", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("b"), (b.clone(), Visibility::Public));
        let c2 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![c1.clone()], message: "c2".into(), tree: t2 })
            .unwrap();

        // Bob receives only change1 (+ object A) via a partial bundle (have=[c2]).
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[c2]).unwrap(), 0).unwrap();
        assert!(bob.object(&a).is_ok(), "bob has A");
        assert!(bob.object(&b).is_err(), "bob lacks B");

        // Negotiate: alice offers the closure, bob replies with the subset it lacks.
        let have = bob.heads();
        let offered = alice.offered_objects(&have);
        let wants = bob.missing_objects(&offered);
        assert_eq!(wants, vec![b.clone()], "bob wants only the object it is missing");

        // Alice ships only the wanted object bytes; the already-held one is not re-sent.
        let bundle = alice.bundle_wanted(&have, &wants).unwrap();
        let objs = objs_in(&bundle);
        assert_eq!(objs.len(), 1);
        assert!(objs.contains_key(&b) && !objs.contains_key(&a));
        bob.apply(&bundle, 0).unwrap();
        assert!(bob.object(&b).is_ok(), "bob now holds B");
    }

    #[test]
    fn re_pull_with_nothing_new_transfers_zero_objects() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"data", Visibility::Public).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("f"), (a, Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree: t })
            .unwrap();

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&alice.bundle(&[]).unwrap(), 0).unwrap();

        // Re-pull: bob already holds everything, so wants is empty and no object
        // bytes move (AC: a re-pull with nothing new transfers ~0 object bytes).
        let have = bob.heads();
        let offered = alice.offered_objects(&have);
        let wants = bob.missing_objects(&offered);
        assert!(wants.is_empty(), "nothing new to want");
        assert!(objs_in(&alice.bundle_wanted(&have, &wants).unwrap()).is_empty());
    }

    // ---- S6: resumable transfer ----

    #[test]
    fn interrupted_push_resumes_transferring_only_remaining() {
        // Alice: two changes, objects A then B.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"aaaa", Visibility::Public).unwrap();
        let mut t1 = BTreeMap::new();
        t1.insert(PathBuf::from("a"), (a.clone(), Visibility::Public));
        let c1 = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c1".into(), tree: t1 })
            .unwrap();
        let b = alice.put(b"bbbb", Visibility::Public).unwrap();
        let mut t2 = BTreeMap::new();
        t2.insert(PathBuf::from("b"), (b.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![c1], message: "c2".into(), tree: t2 })
            .unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();

        // "Interrupted" push: only the first batch (object A) reaches the relay and
        // is stowed. `stow` is append-only + idempotent, so this partial progress
        // is durable.
        relay.stow(&alice.bundle_wanted(&[], &[a.clone()]).unwrap()).unwrap();
        assert!(relay.object(&a).is_ok(), "A delivered");
        assert!(relay.object(&b).is_err(), "B not yet delivered");

        // Resume: re-negotiate. The relay already holds A, so only B is wanted.
        let wants = relay.missing_objects(&alice.offered_objects(&[]));
        assert_eq!(wants, vec![b.clone()], "resume sends only the remaining object");
        relay.stow(&alice.bundle_wanted(&[], &wants).unwrap()).unwrap();
        assert!(relay.object(&b).is_ok(), "B delivered on resume");

        // Re-run a completed push: nothing left to want (idempotent no-op).
        assert!(relay.missing_objects(&alice.offered_objects(&[])).is_empty());
    }

    #[test]
    fn re_stowing_a_delivered_bundle_is_idempotent() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let a = alice.put(b"data", Visibility::Public).unwrap();
        let mut t = BTreeMap::new();
        t.insert(PathBuf::from("f"), (a.clone(), Visibility::Public));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree: t })
            .unwrap();
        let bundle = alice.bundle(&[]).unwrap();

        let mut relay = DagRepo::init(tmp(), "relay").unwrap();
        relay.stow(&bundle).unwrap();
        relay.stow(&bundle).unwrap(); // re-run of a completed transfer
        assert!(relay.object(&a).is_ok());
        assert_eq!(relay.offered_objects(&[]).len(), 1, "no duplication on re-stow");
    }

    #[test]
    fn batched_bundles_respect_the_byte_budget() {
        // #309: a batch of 32 large objects can exceed a relay's request-body
        // limit, so batching must cap bytes as well as object count. Restricted
        // content is never compressed (ADR 0020), so ciphertext size tracks
        // plaintext size and the packing decision is deterministic.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let vis = Visibility::Restricted(vec!["alice".into()]);
        let mut tree = BTreeMap::new();
        let mut oids = Vec::new();
        for i in 0..5u8 {
            let oid = alice.put(&vec![i; 40_000], vis.clone()).unwrap();
            tree.insert(PathBuf::from(format!("f{i}")), (oid.clone(), vis.clone()));
            oids.push(oid);
        }
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();

        // The budget fits two ~40 KB objects per bundle; the 32-object count cap
        // alone would pack all five into one bundle — the byte cap must split.
        let budget = 100_000;
        let bundles = alice.bundle_wanted_batched(&[], &oids, 32, budget).unwrap();
        assert!(
            bundles.len() >= 3,
            "five ~40 KB objects under a 100 KB budget need at least 3 bundles, got {}",
            bundles.len()
        );

        // Every want ships exactly once, and no bundle's object payload exceeds
        // the budget.
        let mut seen = std::collections::BTreeSet::new();
        for b in &bundles {
            let objs = objs_in(b);
            let bytes: usize = objs.values().map(|o| o.ciphertext.len()).sum();
            assert!(bytes <= budget, "bundle object payload {bytes} exceeds budget {budget}");
            for oid in objs.keys() {
                assert!(seen.insert(oid.clone()), "object shipped twice");
            }
        }
        assert_eq!(seen.len(), 5, "all wanted objects must ship");
    }

    #[test]
    fn an_object_larger_than_the_byte_budget_ships_alone() {
        // The byte cap must never wedge a push: an object bigger than the whole
        // budget still travels, alone in its own bundle (the relay's limit is
        // the only ceiling that can refuse it).
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let vis = Visibility::Restricted(vec!["alice".into()]);
        let big = alice.put(&vec![9u8; 50_000], vis.clone()).unwrap();
        let small = alice.put(b"tiny", vis.clone()).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("big"), (big.clone(), vis.clone()));
        tree.insert(PathBuf::from("small"), (small.clone(), vis.clone()));
        alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "c".into(), tree })
            .unwrap();

        let bundles = alice
            .bundle_wanted_batched(&[], &[big.clone(), small.clone()], 32, 1_000)
            .unwrap();
        assert_eq!(bundles.len(), 2, "oversized object ships alone; the small one follows");
        let first = objs_in(&bundles[0]);
        assert_eq!(first.len(), 1);
        assert!(first.contains_key(&big), "the oversized object still travels");
        assert!(objs_in(&bundles[1]).contains_key(&small));
    }

    // decode_manifest_rejects_incompatible_future_major and
    // decode_purges_rejects_incompatible_future_major moved to
    // `engine::custody`'s test module alongside the codecs they exercise (#323).

    #[test]
    fn decode_conflicts_rejects_incompatible_future_major() {
        let mut conflicts = BTreeMap::new();
        conflicts.insert(PathBuf::from("f.txt"), (Oid([7; 32]), Oid([8; 32])));
        let mut bytes = encode_conflicts(&conflicts);
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(decode_conflicts(&bytes), Err(RepoError::UnsupportedFormat { .. })));
    }

    #[test]
    fn conflicts_survive_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-conflicts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            // Manually insert a conflict to test persistence.
            repo.conflicts.insert(
                PathBuf::from("f.txt"),
                (Oid([1; 32]), Oid([2; 32])),
            );
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert!(loaded.conflicts.contains_key(Path::new("f.txt")), "conflict must survive save/load");
        let (ours, theirs) = &loaded.conflicts[Path::new("f.txt")];
        assert_eq!(*ours, Oid([1; 32]));
        assert_eq!(*theirs, Oid([2; 32]));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
