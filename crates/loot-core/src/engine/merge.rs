//! **Merge face** (extracted by the codebase-design review's candidate 3): the
//! change-level operations that combine divergent history into a new change,
//! layered over [`converge`](crate::converge)'s per-path classifier. Where
//! `converge` decides, per path, how two trees reconcile, this face produces the
//! resulting *change*: [`merge_tips`](DagRepo::merge_tips) a 2-parent merge node,
//! [`carry_line`](DagRepo::carry_line) the ADR 0039 superseding replay of a
//! diverged suffix, and [`change_delta_merge`](DagRepo::change_delta_merge) the
//! cherry-pick/revert parent-delta core (#392/#393). All three reuse the shared
//! ADR 0001 rule and add none.
//!
//! These are `DagRepo` methods living in a child module of `engine`, so they
//! reach the engine's private object store, change graph, and conflicts map
//! exactly as they did inline — a pure relocation, no interface or behaviour
//! change, the same shape as the Custody (#323) and Sync-negotiation extractions.
//! `super::*` brings the engine's types and helpers into scope. Their
//! integration tests stay in `engine.rs`: they drive `DagRepo` through
//! `record`/`merge` and share that test module's helpers — the same convention
//! [`negotiation`](super::negotiation)'s extraction followed.

use super::*;

/// One clean delta path's plaintext action, from
/// [`DagRepo::change_delta_merge`]: `Some(bytes)` writes/overwrites the content,
/// `None` deletes the path. The caller applies these to the working tree and
/// snapshots, so the delta is **re-sealed under the current `.lootattributes`**
/// — never the source change's policy (`loot cherry-pick`/`revert`, #392/#393).
pub type DeltaAction = Option<Vec<u8>>;

/// The result of computing a change's parent-delta and 3-way merging it onto a
/// working line — the shared core of `loot cherry-pick` and `loot revert`
/// ([`DagRepo::change_delta_merge`]).
#[derive(Clone, Debug, Default)]
pub struct DeltaMerge {
    /// Per touched-path verdict, for reporting (same labels as `apply`).
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
    /// Clean delta paths to apply as plaintext — empty when the delta conflicted
    /// (nothing is applied on a conflict, exactly like `apply`).
    pub actions: BTreeMap<PathBuf, DeltaAction>,
    /// Delta paths skipped because this identity cannot open the content the
    /// delta introduces (the key oracle returned `None`) — reported, not fatal.
    pub skipped: Vec<PathBuf>,
    /// Whether the delta conflicted with the working line. On `true` the
    /// conflicts are recorded in the repo's conflicts map and `actions` is empty.
    pub conflicted: bool,
}

/// What [`DagRepo::carry_line`] decided — the git bridge's diverged-line
/// reconcile (ADR 0039). Only `Carried` minted anything; a `Bounced` or
/// `Foreign` outcome leaves the graph exactly as it was.
#[derive(Debug)]
pub enum CarryOutcome {
    /// The suffix replayed clean: `minted` are the carried superseding
    /// versions (unsigned — the caller finalizes each), oldest first, the
    /// last being the new tip.
    Carried { minted: Vec<Oid>, outcomes: BTreeMap<PathBuf, MergeOutcome> },
    /// Genuine same-path divergence remains: the conflicts are recorded for
    /// `loot resolve`, nothing was minted, the caller must not advance.
    Bounced { outcomes: BTreeMap<PathBuf, MergeOutcome> },
    /// The suffix carries work this repo did not author (or the repo is
    /// keyless) — re-authoring it would forge provenance; the caller falls
    /// back to the merge shape.
    Foreign,
    /// Nothing to carry: every suffix node replayed empty over `onto`.
    Covered,
}

impl DagRepo {
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
        for (path, (b, o, t)) in &merged.conflicts {
            self.conflicts.insert(path.clone(), (b.clone(), o.clone(), t.clone()));
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

    /// Compute `target`'s **parent-delta** (its tree vs. its parent's tree) and
    /// 3-way merge it onto `working`'s tree — the shared core of `loot
    /// cherry-pick` (`invert = false`) and `loot revert` (`invert = true`, which
    /// swaps additions and deletions). The merge is the exact ADR 0001 rule
    /// [`merge_tips`](DagRepo::merge_tips)/`apply` use ([`converge::merge_trees`]),
    /// with `target`'s "before" side as the base — so a `working` line that never
    /// touched a delta path takes the delta cleanly, while a genuine same-path
    /// divergence is a `Conflict` recorded for `loot resolve`.
    ///
    /// Parent-delta corner cases (the report's question): a **root** change (no
    /// parents) diffs against the *empty* tree, so its whole tree is the delta
    /// (all additions); a **merge** change diffs against its **first** parent —
    /// the same first-parent convention [`carry_line`](DagRepo::carry_line) and
    /// blame walk with — so a cherry-pick of a merge replays the first-parent
    /// delta.
    ///
    /// Sealed-path gate: a delta path whose introduced content this identity
    /// cannot open (the key oracle returns `None`) is **skipped** and reported in
    /// [`DeltaMerge::skipped`], never fatal — you cannot re-seal plaintext you
    /// cannot read, and the source change's own visibility does not travel with a
    /// cherry-pick (the caller re-seals under the *current* policy).
    ///
    /// On conflict this records the conflicts in the repo's conflicts map (so
    /// `loot resolve` sees them, exactly as `apply` does) and returns
    /// [`DeltaMerge::actions`] empty; otherwise it mutates nothing and the caller
    /// applies the plaintext `actions`. The predecessor graph is **not** touched:
    /// a cherry-pick is a new change, not a superseding version of `target`.
    pub fn change_delta_merge(
        &mut self,
        working: &Oid,
        target: &Oid,
        invert: bool,
        now: u64,
    ) -> DeltaMerge {
        let working_tree = self.graph.tree_at(working);
        let target_tree = self.graph.tree_at(target);
        // The parent-delta's base tree: the target's first parent (root -> empty).
        let parent_tree = self
            .graph
            .get(target)
            .and_then(|n| n.parents.first().cloned())
            .map(|p| self.graph.tree_at(&p))
            .unwrap_or_default();

        // Forward applies `target`'s side over its parent; invert swaps them, so
        // an addition (parent lacks, target has) becomes a deletion and a
        // deletion becomes a re-addition.
        let (theirs_full, base_full): (&converge::Tree, &converge::Tree) =
            if invert { (&parent_tree, &target_tree) } else { (&target_tree, &parent_tree) };

        // The delta = every path the change actually touched (target vs. parent
        // differ). A change reuses a path's sealed object when content and
        // visibility are unchanged (#98), so entry inequality here is a real edit.
        let mut delta_paths: BTreeSet<PathBuf> = BTreeSet::new();
        for (path, entry) in &target_tree {
            if parent_tree.get(path) != Some(entry) {
                delta_paths.insert(path.clone());
            }
        }
        for (path, entry) in &parent_tree {
            if target_tree.get(path) != Some(entry) {
                delta_paths.insert(path.clone());
            }
        }

        // Restrict the 3-way to the delta's paths, dropping any whose introduced
        // content we cannot open (skipped, reported). `theirs`/`base` are the two
        // trees `merge_trees` walks: an add/modify rides in `theirs`, a deletion
        // rides in `base` only (the symmetric ours-vs-base pass sees it there).
        let mut theirs: converge::Tree = BTreeMap::new();
        let mut base: converge::Tree = BTreeMap::new();
        let mut skipped: Vec<PathBuf> = Vec::new();
        for path in &delta_paths {
            if let Some(entry) = theirs_full.get(path) {
                // The content the delta would introduce — we must read it to
                // re-seal it, so an unopenable side cannot be cherry-picked.
                if self.get(&entry.0, &self.identity, now).is_err() {
                    skipped.push(path.clone());
                    continue;
                }
                theirs.insert(path.clone(), entry.clone());
            }
            if let Some(entry) = base_full.get(path) {
                base.insert(path.clone(), entry.clone());
            }
        }

        let merged = converge::merge_trees(&working_tree, &theirs, Some(&base), self, now);

        if !merged.conflicts.is_empty() {
            // Record conflicts so `loot conflicts`/`loot resolve` see them —
            // `target`'s side stays reachable through `target` itself — and mint
            // nothing (the caller stops, leaving the working line untouched).
            for (path, pair) in &merged.conflicts {
                self.conflicts.insert(path.clone(), pair.clone());
            }
            return DeltaMerge {
                outcomes: merged.outcomes,
                actions: BTreeMap::new(),
                skipped,
                conflicted: true,
            };
        }

        // Clean: turn each delta path's chosen content in the merged tree into a
        // plaintext action the caller writes and re-seals. Present -> write the
        // (opened) bytes; absent -> a deletion won, remove the path.
        let mut actions: BTreeMap<PathBuf, DeltaAction> = BTreeMap::new();
        for path in &delta_paths {
            if skipped.contains(path) {
                continue;
            }
            match merged.tree.get(path) {
                Some((oid, _vis)) => match self.get(oid, &self.identity, now) {
                    Ok(bytes) => {
                        actions.insert(path.clone(), Some(bytes));
                    }
                    // A kept path should be openable; if not, skip rather than
                    // write blind.
                    Err(_) => skipped.push(path.clone()),
                },
                None => {
                    actions.insert(path.clone(), None);
                }
            }
        }
        DeltaMerge { outcomes: merged.outcomes, actions, skipped, conflicted: false }
    }

    /// Carry the first-parent suffix of `ours` that `onto` does not cover onto
    /// `onto`, as **superseding versions** (ADR 0032) — the reconcile shape the
    /// git bridge lands with (ADR 0039's hard criterion): a lane that fell
    /// behind `main` re-anchors its changes instead of minting a
    /// `ferry: reconcile git main` merge, so landed git history stays **one
    /// commit per change** with no merge or resolution-commit noise.
    ///
    /// Per suffix node, oldest first, the replay is the same three-way the
    /// merge shape used (`converge::merge_trees`; base = the node's first
    /// parent, so exactly the node's own delta replays). Each real node mints
    /// a version carrying the original's change id, message, and a
    /// `predecessors` entry naming it (so the old head reads superseded, never
    /// deleted — ADR 0031). Two node kinds never mint their own version:
    ///
    /// - a **resolution** change (the `loot resolve` shapes, #337/#316 —
    ///   recognized by [`RESOLUTION_SUFFIX_OPEN`]/[`RESOLVE_FALLBACK_PREFIX`])
    ///   folds into the version before it: its tree-effect lands there and its
    ///   own version joins that version's predecessors. This is what makes a
    ///   bounced-then-resolved land still re-land as one commit;
    /// - a node whose replay adds nothing over the carried line is dropped
    ///   redundant, its version likewise folded into the neighbouring mint.
    ///
    /// Returns without minting when the suffix still genuinely conflicts
    /// ([`CarryOutcome::Bounced`] — conflicts recorded for `loot resolve`),
    /// when the suffix carries work this repo did not author
    /// ([`CarryOutcome::Foreign`] — re-authoring a peer's or a git-native
    /// change would forge provenance; the caller merges instead), or when
    /// every node replayed empty ([`CarryOutcome::Covered`]).
    ///
    /// The minted versions are **unsigned** — the caller finalizes each, as
    /// with [`merge_tips`](DagRepo::merge_tips) (ADR 0018, verify-only core).
    pub fn carry_line(
        &mut self,
        ours: &Oid,
        onto: &Oid,
        now: u64,
    ) -> Result<CarryOutcome, RepoError> {
        // A keyless repo cannot author the carried versions it would mint.
        let Some(self_author) = self.author else {
            return Ok(CarryOutcome::Foreign);
        };

        // The ancestry of `onto` — everything already covered by the target.
        let mut covered: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        let mut stack = vec![onto.clone()];
        while let Some(id) = stack.pop() {
            if !covered.insert(id.clone()) {
                continue;
            }
            if let Some(node) = self.graph.get(&id) {
                stack.extend(node.parents.iter().cloned());
            }
        }

        // First-parent suffix of `ours` outside that ancestry, oldest first.
        let mut chain: Vec<Oid> = Vec::new();
        let mut cur = ours.clone();
        while !covered.contains(&cur) {
            let Some(node) = self.graph.get(&cur) else {
                return Err(RepoError::Backend(format!(
                    "carry: change {} is not loaded",
                    crate::hex::short(&cur.0, 8)
                )));
            };
            chain.push(cur.clone());
            match node.parents.first() {
                Some(p) => cur = p.clone(),
                None => break, // disjoint root: replay against the empty tree
            }
        }
        chain.reverse();
        if chain.is_empty() {
            return Ok(CarryOutcome::Covered);
        }
        // Re-authoring someone else's (or unauthored git-native) work as our
        // own version would forge provenance — those lines keep the merge.
        if chain
            .iter()
            .any(|id| self.graph.get(id).and_then(|n| n.author) != Some(self_author))
        {
            return Ok(CarryOutcome::Foreign);
        }

        /// One carried version waiting to mint (nothing minted until the whole
        /// suffix replays clean, so a bounce leaves the graph untouched).
        struct Pending {
            message: String,
            cid: Option<[u8; 16]>,
            preds: Vec<Oid>,
            tree: converge::Tree,
        }
        let mut pendings: Vec<Pending> = Vec::new();
        let mut carried_tree = self.graph.tree_at(onto);
        let mut outcomes: BTreeMap<PathBuf, MergeOutcome> = BTreeMap::new();
        let mut open_conflicts: BTreeMap<PathBuf, (Option<Oid>, Oid, Oid)> = BTreeMap::new();

        for id in &chain {
            let node = self.graph.get(id).expect("chain nodes are loaded").clone();
            let base_tree = node.parents.first().map(|p| self.graph.tree_at(p));
            let merged =
                converge::merge_trees(&node.tree, &carried_tree, base_tree.as_ref(), self, now);
            for (path, outcome) in merged.outcomes {
                match &outcome {
                    MergeOutcome::Conflict { .. } => {
                        outcomes.insert(path, outcome);
                    }
                    _ => {
                        // A later node that answers a path cleanly supersedes the
                        // earlier conflict there — the ours line already resolved
                        // it (the fold that keeps a re-land at one commit).
                        if open_conflicts.remove(&path).is_some() {
                            outcomes.insert(path, outcome);
                        } else {
                            let slot =
                                outcomes.entry(path).or_insert(MergeOutcome::Converged);
                            *slot = converge::worst(slot.clone(), outcome);
                        }
                    }
                }
            }
            for (path, pair) in merged.conflicts {
                open_conflicts.insert(path, pair);
            }

            let is_resolution = node.message.starts_with(RESOLVE_FALLBACK_PREFIX)
                || (node.message.ends_with(')')
                    && node.message.rfind(RESOLUTION_SUFFIX_OPEN).is_some());
            let redundant = merged.tree == carried_tree;
            carried_tree = merged.tree.clone();
            match pendings.last_mut() {
                // Resolutions and empty replays never mint their own version:
                // their effect (if any) is already in `carried_tree`, and their
                // version rides the neighbouring mint's predecessors so the old
                // head reads superseded.
                Some(last) if is_resolution || redundant => {
                    last.tree = merged.tree;
                    last.preds.push(id.clone());
                }
                _ if redundant => continue,
                _ => pendings.push(Pending {
                    message: node.message,
                    cid: node.change_id,
                    preds: vec![id.clone()],
                    tree: merged.tree,
                }),
            }
        }

        if !open_conflicts.is_empty() {
            for (path, pair) in open_conflicts {
                self.conflicts.insert(path, pair);
            }
            return Ok(CarryOutcome::Bounced { outcomes });
        }
        if pendings.is_empty() {
            return Ok(CarryOutcome::Covered);
        }
        let mut minted: Vec<Oid> = Vec::new();
        let mut parent = onto.clone();
        for pend in pendings {
            let change = Change {
                id: Oid([0; 32]),
                parents: vec![parent.clone()],
                message: pend.message,
                tree: pend.tree,
            };
            let id = self.record_superseding(change, pend.cid, pend.preds)?;
            parent = id.clone();
            minted.push(id);
        }
        // The carried line continues on `onto`; the superseded original tip
        // stops being a head (node untouched — ADR 0031). Without this, a
        // heads-derived anchor (the untracked pristine home) can keep
        // answering the stale tip.
        self.graph.retire_head(ours);
        Ok(CarryOutcome::Carried { minted, outcomes })
    }
}
