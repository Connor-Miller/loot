//! The change DAG for the backend (internal seam).
//!
//! Owns change nodes, head tracking, topological ordering, and the derived
//! "current tree" (latest content address per path). It knows nothing about
//! bytes, ciphertext, or keys — only change identity and parent/child shape.
//! Backend-private.

use crate::converge::Tree;
use crate::{Change, Oid, Visibility};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A node in the change DAG.
#[derive(Clone)]
pub struct ChangeNode {
    pub id: Oid,
    pub parents: Vec<Oid>,
    pub message: String,
    pub tree: BTreeMap<PathBuf, (Oid, Visibility)>,
    /// The author's ed25519 public key (S3, ADR 0018). `Some` for authored
    /// changes — the pubkey is folded into `id`, so authorship is intrinsic.
    /// `None` for legacy/unauthored changes read under an older format version.
    pub author: Option<[u8; 32]>,
    /// The author's signature over `id`, attached at finalization (`loot new`).
    /// `None` for an in-progress working change, or a legacy/unauthored change.
    pub signature: Option<[u8; 64]>,
}

/// Content-and-author-derived change id: hash of the author pubkey (when
/// present), message, parents, and the path/address tree. Pure; identical
/// changes get identical ids (idempotent commit/apply).
///
/// Folding the author in first makes authorship intrinsic (ADR 0018): the same
/// edit by two identities yields distinct ids. `author = None` reproduces the
/// pre-authorship id exactly, so legacy/unauthored changes are unchanged and
/// "newer reads older" holds.
pub fn compute_change_id(author: Option<&[u8; 32]>, change: &Change) -> Oid {
    let mut h = blake3::Hasher::new();
    if let Some(a) = author {
        h.update(a);
    }
    h.update(change.message.as_bytes());
    for p in &change.parents {
        h.update(&p.0);
    }
    for (path, (oid, _vis)) in &change.tree {
        h.update(path.to_string_lossy().as_bytes());
        h.update(&[0]);
        h.update(&oid.0);
    }
    Oid(*h.finalize().as_bytes())
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

    /// Attach a signature to a node's `signature` field (finalization, ADR 0018).
    /// Returns `None` if the change id is unknown.
    pub fn set_signature(&mut self, id: &Oid, signature: [u8; 64]) -> Option<()> {
        self.changes.get_mut(id)?.signature = Some(signature);
        Some(())
    }

    /// Latest content address per path, applying changes in topo order so a
    /// child's write wins over its parent's.
    pub fn current_tree(&self) -> Tree {
        let mut tree: Tree = BTreeMap::new();
        for node in self.in_order() {
            for (path, entry) in &node.tree {
                tree.insert(path.clone(), entry.clone());
            }
        }
        tree
    }

    /// Latest content address per path along a *single* head's ancestry, applying
    /// changes in topo order so a child's write wins. Unlike [`current_tree`],
    /// which merges every head, this scopes the tree to one line — the basis for
    /// per-dock isolation, where each dock forks from its own tip (ADR 0022). An
    /// unknown head yields an empty tree.
    ///
    /// [`current_tree`]: ChangeGraph::current_tree
    pub fn tree_at(&self, head: &Oid) -> Tree {
        let mut tree: Tree = BTreeMap::new();
        for node in self.ancestry_in_order(head) {
            for (path, entry) in &node.tree {
                tree.insert(path.clone(), entry.clone());
            }
        }
        tree
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

    /// The ancestor-closure of `head` (head included) in parents-before-children
    /// order. Empty if `head` is unknown.
    fn ancestry_in_order(&self, head: &Oid) -> Vec<&ChangeNode> {
        let mut ordered = Vec::new();
        let mut visited: BTreeMap<Oid, bool> = BTreeMap::new();
        visit(head, &self.changes, &mut visited, &mut ordered);
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

    fn node(id: u8, parents: &[u8], path: &str, addr: u8) -> ChangeNode {
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from(path),
            (Oid([addr; 32]), Visibility::Public),
        );
        ChangeNode {
            id: Oid([id; 32]),
            parents: parents.iter().map(|&p| Oid([p; 32])).collect(),
            message: format!("c{id}"),
            tree,
            author: None,
            signature: None,
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

    #[test]
    fn tree_at_scopes_to_one_line_unlike_current_tree() {
        // A common base (1), then two forks: 2 writes b, 3 writes c. Both are
        // heads. current_tree() merges everything; tree_at() sees one line only.
        let mut g = ChangeGraph::new();
        g.insert(node(1, &[], "a", 10));
        g.insert(node(2, &[1], "b", 20)); // fork A
        g.insert(node(3, &[1], "c", 30)); // fork B

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
        g.insert(node(1, &[], "a", 10));
        g.insert(node(2, &[1], "a", 11)); // child overwrites a
        assert_eq!(g.tree_at(&Oid([2; 32]))[&PathBuf::from("a")].0, Oid([11; 32]));
        assert!(g.tree_at(&Oid([99; 32])).is_empty(), "unknown head => empty tree");
    }
}
