//! Evaluator: an [`Expr`] plus a [`DagRepo`] view -> an ordered, de-duplicated
//! set of change (version) ids.
//!
//! All reads go through `DagRepo`'s existing public accessors — the same ones
//! `log`/`blame`/the git bridge use — so a revset sees exactly the dock's loaded
//! lineage and nothing speculative:
//!
//! - enumeration + messages: [`DagRepo::log`]
//! - parent edges:           [`DagRepo::parents_of`]
//! - heads / tip:            [`loot_core::Repo::heads`]
//! - working change:         [`DagRepo::change_author`] + [`DagRepo::change_signature`]
//! - author pubkey:          [`DagRepo::change_author`]
//! - readability:            [`loot_core::converge::KeyOracle::open`] (the "current key oracle")
//! - tree of a change:       [`DagRepo::change_tree`]
//!
//! Results come back in the repo's own topological order (parents before
//! children), which makes them stable and deduplicated regardless of how the
//! expression combined its pieces.

use std::collections::{BTreeMap, BTreeSet};

use loot_core::converge::KeyOracle;
use loot_core::{DagRepo, Oid, Repo};

use crate::parser::Expr;

/// Evaluate a parsed [`Expr`] against `repo` as of clock `now`, returning the
/// selected change ids in topological order (parents first).
///
/// `now` (unix seconds) is only consulted by `visible()` — loot's read side is
/// clock-parameterized because embargoed content becomes readable at a
/// scheduled time (ADR 0007). Every other selector is time-independent.
pub fn eval(expr: &Expr, repo: &DagRepo, now: u64) -> Vec<Oid> {
    let ev = Evaluator::new(repo, now);
    let set = ev.eval(expr);
    ev.order(&set)
}

struct Evaluator<'a> {
    repo: &'a DagRepo,
    now: u64,
    /// Every change in the view, topological order (parents before children).
    order: Vec<Oid>,
    /// change id -> message, for `description`.
    messages: BTreeMap<Oid, String>,
    /// parent -> its children, for descendant walks (the reverse of `parents_of`).
    children: BTreeMap<Oid, Vec<Oid>>,
}

impl<'a> Evaluator<'a> {
    fn new(repo: &'a DagRepo, now: u64) -> Self {
        let log = repo.log();
        let mut order = Vec::with_capacity(log.len());
        let mut messages = BTreeMap::new();
        for (id, msg) in log {
            order.push(id.clone());
            messages.insert(id, msg);
        }
        let mut children: BTreeMap<Oid, Vec<Oid>> = BTreeMap::new();
        for id in &order {
            for parent in repo.parents_of(id) {
                children.entry(parent).or_default().push(id.clone());
            }
        }
        Self { repo, now, order, messages, children }
    }

    /// Project a set back into the view's topological order.
    fn order(&self, set: &BTreeSet<Oid>) -> Vec<Oid> {
        self.order.iter().filter(|id| set.contains(*id)).cloned().collect()
    }

    fn universe(&self) -> BTreeSet<Oid> {
        self.order.iter().cloned().collect()
    }

    fn eval(&self, expr: &Expr) -> BTreeSet<Oid> {
        match expr {
            Expr::All => self.universe(),
            Expr::Visible => self.visible(),
            Expr::At => self.working_changes(),
            Expr::Head => self.heads(),
            Expr::HeadAncestor(n) => self.head_ancestor(*n),
            Expr::IdPrefix(p) => self.id_prefix(p),
            Expr::Author(name) => self.by_author(name),
            Expr::Description(pat) => self.by_description(pat),
            Expr::Ancestors(x) => self.ancestors(&self.eval(x)),
            Expr::Descendants(x) => self.descendants(&self.eval(x)),
            Expr::Range(x, y) => {
                let from_y = self.ancestors(&self.eval(y));
                let from_x = self.ancestors(&self.eval(x));
                from_y.difference(&from_x).cloned().collect()
            }
            Expr::Union(a, b) => self.eval(a).union(&self.eval(b)).cloned().collect(),
            Expr::Intersect(a, b) => {
                self.eval(a).intersection(&self.eval(b)).cloned().collect()
            }
            Expr::Difference(a, b) => {
                self.eval(a).difference(&self.eval(b)).cloned().collect()
            }
            Expr::Complement(x) => {
                let inner = self.eval(x);
                self.universe().difference(&inner).cloned().collect()
            }
        }
    }

    /// Heads, filtered to changes actually present in the view.
    fn heads(&self) -> BTreeSet<Oid> {
        let universe = self.universe();
        self.repo.heads().into_iter().filter(|h| universe.contains(h)).collect()
    }

    /// The working change(s): authored but not yet signed (ADR 0018). Normally
    /// at most one — the dock's own in-progress tip.
    fn working_changes(&self) -> BTreeSet<Oid> {
        self.order
            .iter()
            .filter(|id| {
                self.repo.change_author(id).is_some()
                    && self.repo.change_signature(id).is_none()
            })
            .cloned()
            .collect()
    }

    /// The n-th first-parent ancestor of each head. A head whose first-parent
    /// chain is shorter than `n` contributes nothing (the walk falls off).
    fn head_ancestor(&self, n: u32) -> BTreeSet<Oid> {
        let mut out = BTreeSet::new();
        for head in self.repo.heads() {
            let mut cur = head;
            let mut ok = true;
            for _ in 0..n {
                match self.repo.parents_of(&cur).into_iter().next() {
                    Some(parent) => cur = parent,
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                out.insert(cur);
            }
        }
        out
    }

    /// Changes whose version-id hex starts with `prefix` (case-insensitive).
    fn id_prefix(&self, prefix: &str) -> BTreeSet<Oid> {
        let needle = prefix.to_ascii_lowercase();
        self.order
            .iter()
            .filter(|id| loot_core::hex::encode(&id.0).starts_with(&needle))
            .cloned()
            .collect()
    }

    /// Changes authored by a key whose hex starts with `name` (case-insensitive).
    /// The peer-nickname registry lives above loot-core (in the CLI), so this
    /// crate matches the intrinsic author pubkey, not a human alias.
    fn by_author(&self, name: &str) -> BTreeSet<Oid> {
        let needle = name.to_ascii_lowercase();
        self.order
            .iter()
            .filter(|id| {
                self.repo
                    .change_author(id)
                    .is_some_and(|pk| loot_core::hex::encode(&pk).starts_with(&needle))
            })
            .cloned()
            .collect()
    }

    /// Changes whose message contains `pat` — case-sensitive substring match.
    /// (The workspace carries no regex dependency, so a substring is the honest,
    /// dependency-free default; see the crate docs.)
    fn by_description(&self, pat: &str) -> BTreeSet<Oid> {
        self.order
            .iter()
            .filter(|id| {
                self.messages.get(*id).is_some_and(|m| m.contains(pat))
            })
            .cloned()
            .collect()
    }

    /// A change is *visible* when this repo's key oracle can open every content
    /// object in its tree at `now`. An empty-tree change (no paths) is trivially
    /// visible. A change carrying any object we lack the key for (or that is
    /// still embargoed at `now`) is not.
    fn visible(&self) -> BTreeSet<Oid> {
        self.order
            .iter()
            .filter(|id| {
                let Some(tree) = self.repo.change_tree(id) else {
                    return false;
                };
                tree.values().all(|(oid, _vis)| self.repo.open(oid, self.now).is_some())
            })
            .cloned()
            .collect()
    }

    /// `seed` plus every change reachable from it by walking parent edges
    /// (inclusive). Iterative to stay flat on deep histories.
    fn ancestors(&self, seed: &BTreeSet<Oid>) -> BTreeSet<Oid> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<Oid> = seed.iter().cloned().collect();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            for parent in self.repo.parents_of(&cur) {
                if !seen.contains(&parent) {
                    stack.push(parent);
                }
            }
        }
        seen
    }

    /// `seed` plus every change that reaches it (inclusive) — the reverse walk,
    /// over the precomputed child map.
    fn descendants(&self, seed: &BTreeSet<Oid>) -> BTreeSet<Oid> {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<Oid> = seed.iter().cloned().collect();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(kids) = self.children.get(&cur) {
                for kid in kids {
                    if !seen.contains(kid) {
                        stack.push(kid.clone());
                    }
                }
            }
        }
        seen
    }
}
