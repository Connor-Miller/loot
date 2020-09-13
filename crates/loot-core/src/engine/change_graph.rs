//! The change DAG for the backend (internal seam).
//!
//! Owns change nodes, head tracking, topological ordering, and the derived
//! "current tree" (latest content address per path). It knows nothing about
//! bytes, ciphertext, or keys — only change identity and parent/child shape.
//! Backend-private.

use crate::converge::Tree;
use crate::{Change, Oid, Visibility};
// Re-exported (not a private `use`) so `engine::ChangeNode` and other in-crate
// paths that referenced `change_graph::ChangeNode` keep resolving.
pub use crate::ChangeNode;
use std::collections::BTreeMap;
use std::path::Path;

// `ChangeNode` (the pure DAG-node shape the wire codec reads/writes) and the
// change-id fold now live in `loot-codec` so they can build to wasm; the graph
// algorithms below operate on them unchanged. Re-exported here at their original
// paths so in-crate callers (and `pub use engine::change_signing_message`) are
// unaffected.
pub use loot_codec::change_id::{canonical_predecessors, change_signing_message, mint_change_id};

/// Content-and-author-derived change id over a [`Change`] — a thin wrapper that
/// delegates to [`loot_codec::change_id::compute_change_id_raw`], so the engine
/// and the WASM author path fold byte-identically. See that function for the
/// full rationale (authorship intrinsic, predecessors domain-tagged, legacy ids
/// unchanged).
pub fn compute_change_id(author: Option<&[u8; 32]>, change: &Change, predecessors: &[Oid]) -> Oid {
    loot_codec::change_id::compute_change_id_raw(
        author,
        &change.message,
        &change.parents,
        &change.tree,
        predecessors,
    )
}

#[derive(Default)]
pub struct ChangeGraph {
    changes: BTreeMap<Oid, ChangeNode>,
    /// Change ids that are nobody's parent.
    heads: Vec<Oid>,
}

impl ChangeGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a node, maintaining heads. Idempotent on change id.
    pub fn insert(&mut self, node: ChangeNode) {
        let id = node.id.clone();
        if self.changes.contains_key(&id) {
            return;
        }
        self.heads.retain(|h| !node.parents.contains(h));
        self.changes.insert(id.clone(), node);
        if !self.heads.contains(&id) {
            self.heads.push(id);
        }
    }

    pub fn heads(&self) -> Vec<Oid> {
        self.heads.clone()
    }

    /// Remove a head node (one nobody is a child of) and restore any of its
    /// parents that become heads as a result. Used to rewrite the working change
    /// in place (ADR 0006): the working change is always a head, so this is safe.
    /// No-op if `id` is unknown or is not a head.
    pub fn remove_head(&mut self, id: &Oid) {
        if !self.heads.contains(id) {
            return;
        }
        let Some(node) = self.changes.remove(id) else {
            return;
        };
        self.heads.retain(|h| h != id);
        // A parent becomes a head iff no remaining change lists it as a parent.
        for parent in &node.parents {
            let still_referenced = self
                .changes
                .values()
                .any(|n| n.parents.contains(parent));
            if !still_referenced && self.changes.contains_key(parent) && !self.heads.contains(parent)
            {
                self.heads.push(parent.clone());
            }
        }
    }

    pub fn get(&self, id: &Oid) -> Option<&ChangeNode> {
        self.changes.get(id)
    }

    /// Retire `id` from the head set **without touching the node** — the
    /// carry's supersession bookkeeping (ADR 0039): a carried version
    /// continues the line on a new parent, so the superseded original stops
    /// being a tip while staying fully in history (ADR 0031 — a head entry is
    /// not the change). Unlike [`remove_head`](Self::remove_head), parents are
    /// not restored: the line's continuation is the carried version, not the
    /// original's parent. No-op when `id` is not a head.
    pub fn retire_head(&mut self, id: &Oid) {
        self.heads.retain(|h| h != id);
    }

    /// Build a graph containing only the subgraph reachable from `heads` over a
    /// `pool` of candidate nodes (CA1.5, ADR 0022). This is the per-dock load:
    /// the shared store holds every dock's finalized nodes, but a dock only wants
    /// *its own lineage*, so it materializes exactly the ancestry of its heads.
    ///
    /// Because only reachable nodes are inserted (parents before children), the
    /// derived heads come out equal to `heads` (every non-tip is some node's
    /// parent), so `current_tree`/`surface`/`snapshot` see the dock's lineage
    /// with no change to their logic. Heads absent from `pool` are skipped.
    pub fn reachable_from(pool: &BTreeMap<Oid, ChangeNode>, heads: &[Oid]) -> Self {
        // Collect the reachable id set by walking parent edges from each head.
        let mut reachable: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        let mut stack: Vec<Oid> = heads.to_vec();
        while let Some(id) = stack.pop() {
            if !reachable.insert(id.clone()) {
                continue;
            }
            if let Some(node) = pool.get(&id) {
                for p in &node.parents {
                    stack.push(p.clone());
                }
            }
        }
        // Topo-insert (parents first) so head tracking stays correct.
        fn visit(
            id: &Oid,
            pool: &BTreeMap<Oid, ChangeNode>,
            reachable: &std::collections::BTreeSet<Oid>,
            visited: &mut std::collections::BTreeSet<Oid>,
            out: &mut ChangeGraph,
        ) {
            if !reachable.contains(id) || !visited.insert(id.clone()) {
                return;
            }
            if let Some(node) = pool.get(id) {
                for p in &node.parents {
                    visit(p, pool, reachable, visited, out);
                }
                out.insert(node.clone());
            }
        }
        let mut graph = ChangeGraph::new();
        let mut visited = std::collections::BTreeSet::new();
        for h in heads {
            visit(h, pool, &reachable, &mut visited, &mut graph);
        }
        graph
    }

    /// The ids in `pool` that no node in `pool` names as a parent — the tips of
    /// the whole pool. Used for back-compat load of a repo that predates per-dock
    /// heads (no heads file): treat the entire graph as the (default) dock's
    /// lineage, exactly as before CA1.5.
    pub fn derive_all_heads(pool: &BTreeMap<Oid, ChangeNode>) -> Vec<Oid> {
        let mut parented: std::collections::BTreeSet<&Oid> = std::collections::BTreeSet::new();
        for node in pool.values() {
            for p in &node.parents {
                parented.insert(p);
            }
        }
        pool.keys().filter(|id| !parented.contains(id)).cloned().collect()
    }

    /// Attach a signature to a node's `signature` field (finalization, ADR 0018).
    /// Returns `None` if the change id is unknown.
    pub fn set_signature(&mut self, id: &Oid, signature: [u8; 64]) -> Option<()> {
        self.changes.get_mut(id)?.signature = Some(signature);
        Some(())
    }

    /// The current tree across every head: the union of the **head manifests**,
    /// in topo order so a later head's write wins a shared path. Every recorded
    /// change carries a *full* path→address manifest (snapshot, ingest and
    /// merge all record whole trees), so a head's own manifest is authoritative
    /// for its line; ancestors are history, not an overlay. Unioning the whole
    /// ancestry — the pre-#288 behavior — treated manifests as deltas and
    /// re-raised every path ever deleted anywhere in the graph, forever.
    pub fn current_tree(&self) -> Tree {
        let mut tree: Tree = BTreeMap::new();
        for node in self.in_order() {
            if !self.heads.contains(&node.id) {
                continue;
            }
            for (path, entry) in &node.tree {
                tree.insert(path.clone(), entry.clone());
            }
        }
        tree
    }

    /// The most recently recorded `(oid, visibility)` for `path`, searching
    /// the live tree first and then **every** change in history if `path`
    /// isn't there — so a path this graph's current heads no longer carry
    /// (deleted on that line) or don't carry *yet* (landed on a head this
    /// position hasn't surfaced) is still explainable rather than a bare
    /// "not found" (`loot embargo-status`, #15). Unlike `current_tree`, this
    /// walks the whole graph, not just the heads' own manifests; topo-newest
    /// match wins. `None` if `path` never appears in any recorded change.
    pub fn path_in_history(&self, path: &Path) -> Option<(Oid, Visibility)> {
        if let Some(entry) = self.current_tree().get(path) {
            return Some(entry.clone());
        }
        self.in_order().into_iter().rev().find_map(|n| n.tree.get(path).cloned())
    }

    /// The tree at one change: its recorded manifest, exactly. Unlike
    /// [`current_tree`], which merges every head, this scopes to one line — the
    /// basis for per-dock isolation, where each dock forks from its own tip
    /// (ADR 0022). A path present in an ancestor but absent here was **deleted**
    /// on the way and must stay gone: walking the ancestry child-wins (the
    /// pre-#288 behavior) resurrected every deleted path into merge inputs,
    /// which is how `merge_tips` re-raised files both lines had deleted months
    /// earlier and published them to git `main`. An unknown head yields an
    /// empty tree.
    ///
    /// [`current_tree`]: ChangeGraph::current_tree
    pub fn tree_at(&self, head: &Oid) -> Tree {
        self.changes.get(head).map(|n| n.tree.clone()).unwrap_or_default()
    }

    /// The full tree of the nearest common ancestor of `a` and `b` — the merge
    /// base the convergence classifier consults to tell "untouched since the
    /// fork" from "both sides edited" (#65). Walks breadth-first from `b`
    /// (inclusive: if one tip is an ancestor of the other, that tip IS the
    /// base) through parents until it hits `a`'s ancestry. `None` when the two
    /// lines share no history.
    pub fn common_ancestor_tree(&self, a: &Oid, b: &Oid) -> Option<Tree> {
        let mut a_ancestry: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        let mut stack = vec![a.clone()];
        while let Some(id) = stack.pop() {
            if !a_ancestry.insert(id.clone()) {
                continue;
            }
            if let Some(node) = self.changes.get(&id) {
                stack.extend(node.parents.iter().cloned());
            }
        }
        let mut queue: std::collections::VecDeque<Oid> = std::collections::VecDeque::new();
        let mut seen: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        queue.push_back(b.clone());
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            let Some(node) = self.changes.get(&id) else { continue };
            if a_ancestry.contains(&id) {
                return Some(node.tree.clone());
            }
            queue.extend(node.parents.iter().cloned());
        }
        None
    }

    /// Changes ordered so parents precede children (DFS topo sort).
    pub fn in_order(&self) -> Vec<&ChangeNode> {
        let mut ordered = Vec::with_capacity(self.changes.len());
        let mut visited: BTreeMap<Oid, bool> = BTreeMap::new();
        for id in self.changes.keys() {
            visit(id, &self.changes, &mut visited, &mut ordered);
        }
        ordered
    }

}

/// Shared DFS: emit `id` and its ancestors with parents before children.
fn visit<'a>(
    id: &Oid,
    changes: &'a BTreeMap<Oid, ChangeNode>,
    visited: &mut BTreeMap<Oid, bool>,
    out: &mut Vec<&'a ChangeNode>,
) {
    if visited.get(id).copied().unwrap_or(false) {
        return;
    }
    visited.insert(id.clone(), true);
    if let Some(node) = changes.get(id) {
        for p in &node.parents {
            visit(p, changes, visited, out);
        }
        out.push(node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn node(id: u8, parents: &[u8], path: &str, addr: u8) -> ChangeNode {
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from(path),
            (Oid([addr; 32]), Visibility::Internal),
        );
        ChangeNode {
            id: Oid([id; 32]),
            parents: parents.iter().map(|&p| Oid([p; 32])).collect(),
            message: format!("c{id}"),
            tree,
            author: None,
            signature: None,
            change_id: None,
            predecessors: Vec::new(),
        }
    }

    #[test]
    fn single_change_is_the_head() {
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        assert_eq!(g.heads(), vec![Oid([1; 32])]);
    }

    #[test]
    fn child_replaces_parent_as_head() {
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        g.insert(node(2, &[1], "a", 11));
        assert_eq!(g.heads(), vec![Oid([2; 32])]);
    }

    #[test]
    fn insert_is_idempotent() {
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        g.insert(node(1, &[], "a", 10));
        assert_eq!(g.heads(), vec![Oid([1; 32])]);
    }

    #[test]
    fn current_tree_takes_child_write_over_parent() {
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        g.insert(node(2, &[1], "a", 11));
        let tree = g.current_tree();
        assert_eq!(tree[&PathBuf::from("a")].0, Oid([11; 32]));
    }

    #[test]
    fn two_heads_when_disjoint() {
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        g.insert(node(2, &[], "b", 20));
        let mut heads = g.heads();
        heads.sort_by_key(|o| o.0[0]);
        assert_eq!(heads, vec![Oid([1; 32]), Oid([2; 32])]);
    }

    /// A node carrying a FULL manifest — the shape every production recorder
    /// (snapshot, ingest, merge) actually writes (#288).
    fn manifest_node(id: u8, parents: &[u8], entries: &[(&str, u8)]) -> ChangeNode {
        let tree = entries
            .iter()
            .map(|&(path, addr)| (PathBuf::from(path), (Oid([addr; 32]), Visibility::Internal)))
            .collect();
        ChangeNode {
            id: Oid([id; 32]),
            parents: parents.iter().map(|&p| Oid([p; 32])).collect(),
            message: format!("c{id}"),
            tree,
            author: None,
            signature: None,
            change_id: None,
            predecessors: Vec::new(),
        }
    }

    #[test]
    fn tree_at_scopes_to_one_line_unlike_current_tree() {
        // A common base (1), then two forks whose manifests carry the base
        // plus their own write. current_tree() merges the heads; tree_at()
        // sees one line only.
        let mut g = ChangeGraph::new();
        g.insert(manifest_node(1, &[], &[("a", 10)]));
        g.insert(manifest_node(2, &[1], &[("a", 10), ("b", 20)])); // fork A
        g.insert(manifest_node(3, &[1], &[("a", 10), ("c", 30)])); // fork B

        let merged = g.current_tree();
        assert!(merged.contains_key(&PathBuf::from("a")));
        assert!(merged.contains_key(&PathBuf::from("b")));
        assert!(merged.contains_key(&PathBuf::from("c")), "current_tree merges all heads");

        let fork_a = g.tree_at(&Oid([2; 32]));
        assert!(fork_a.contains_key(&PathBuf::from("a")), "sees the shared base");
        assert!(fork_a.contains_key(&PathBuf::from("b")), "sees its own write");
        assert!(!fork_a.contains_key(&PathBuf::from("c")), "must NOT see the sibling fork");

        let fork_b = g.tree_at(&Oid([3; 32]));
        assert!(fork_b.contains_key(&PathBuf::from("c")));
        assert!(!fork_b.contains_key(&PathBuf::from("b")), "isolation is symmetric");
    }

    #[test]
    fn tree_at_child_write_wins_and_unknown_head_is_empty() {
        let mut g = ChangeGraph::new();
        g.insert(manifest_node(1, &[], &[("a", 10)]));
        g.insert(manifest_node(2, &[1], &[("a", 11)])); // child overwrites a
        assert_eq!(g.tree_at(&Oid([2; 32]))[&PathBuf::from("a")].0, Oid([11; 32]));
        assert!(g.tree_at(&Oid([99; 32])).is_empty(), "unknown head => empty tree");
    }

    #[test]
    fn tree_at_honors_a_deletion_instead_of_unioning_the_ancestry() {
        // #288: a change's tree is its full manifest; a path present in an
        // ancestor but absent from the child's manifest was DELETED. The old
        // ancestry-union re-raised it forever, which is what resurrected
        // long-deleted files in every reconcile merge.
        let mut g = ChangeGraph::new();
        g.insert(manifest_node(1, &[], &[("a", 10), ("b", 20)]));
        g.insert(manifest_node(2, &[1], &[("a", 10)])); // deletes b
        let t = g.tree_at(&Oid([2; 32]));
        assert!(t.contains_key(&PathBuf::from("a")));
        assert!(
            !t.contains_key(&PathBuf::from("b")),
            "a deleted path must not resurrect via the ancestry"
        );
        // The single-head current tree agrees with the head's manifest.
        let ct = g.current_tree();
        assert!(!ct.contains_key(&PathBuf::from("b")));
    }

    /// Like `manifest_node`, but lets a caller pin a path's [`Visibility`]
    /// (the others stay `Public`) — needed to test `path_in_history` against
    /// an embargoed entry the current heads no longer carry (#15).
    fn manifest_node_vis(id: u8, parents: &[u8], entries: &[(&str, u8, Visibility)]) -> ChangeNode {
        let tree = entries
            .iter()
            .map(|(path, addr, vis)| (PathBuf::from(*path), (Oid([*addr; 32]), vis.clone())))
            .collect();
        ChangeNode {
            id: Oid([id; 32]),
            parents: parents.iter().map(|&p| Oid([p; 32])).collect(),
            message: format!("c{id}"),
            tree,
            author: None,
            signature: None,
            change_id: None,
            predecessors: Vec::new(),
        }
    }

    /// #15: a path still in the current tree resolves straight from it —
    /// `path_in_history` must not fall back to a stale historical entry when
    /// a live one exists.
    #[test]
    fn path_in_history_prefers_the_current_tree() {
        let mut g = ChangeGraph::new();
        g.insert(manifest_node(1, &[], &[("a", 10)]));
        g.insert(manifest_node(2, &[1], &[("a", 11)]));
        let (oid, vis) = g.path_in_history(&PathBuf::from("a")).expect("path is live");
        assert_eq!(oid, Oid([11; 32]));
        assert_eq!(vis, Visibility::Internal);
    }

    /// #15's core AC: a path deleted off the live line is still found by
    /// walking history — "works for paths not in the working tree".
    #[test]
    fn path_in_history_falls_back_to_a_deleted_path() {
        let mut g = ChangeGraph::new();
        g.insert(manifest_node_vis(
            1,
            &[],
            &[("secret.md", 10, Visibility::Embargoed { reveal_at: 500 })],
        ));
        g.insert(manifest_node(2, &[1], &[])); // deletes secret.md on the live line
        assert!(
            g.current_tree().get(&PathBuf::from("secret.md")).is_none(),
            "precondition: the path is gone from the live tree"
        );
        let (oid, vis) = g
            .path_in_history(&PathBuf::from("secret.md"))
            .expect("still explainable via history");
        assert_eq!(oid, Oid([10; 32]));
        assert_eq!(vis, Visibility::Embargoed { reveal_at: 500 });
    }

    #[test]
    fn path_in_history_is_none_for_a_path_that_never_existed() {
        let mut g = ChangeGraph::new();
        g.insert(manifest_node(1, &[], &[("a", 10)]));
        assert!(g.path_in_history(&PathBuf::from("never.md")).is_none());
    }
}
