//! Liveness — the one home for the rule the `!` marker renders (map #215,
//! #216): **live = in-graph ∧ ¬abandoned ∧ ¬superseded**, plus "divergent
//! co-versions stay flat" (#198/#203) and "a parked working change is not a
//! mergeable line" (#203). Before this module the rule was consulted or
//! re-derived at ~13 sites across the engine, the Workspace, and the CLI —
//! each of the 2026-07-12 converge bugs was one clause missing at one site.
//!
//! A `Liveness` is a **view built once per operation** from the change graph,
//! the local-only abandoned set (`.loot/abandoned`), and the sibling docks'
//! parked working pointers. The superseded scan (O(nodes)) runs exactly once
//! at construction; every query answers from the cached view. The per-line
//! ancestry predicate `DagRepo::supersedes` is deliberately *not* part of this
//! module — "is this version dead on this line" is a different question from
//! the global view, used by the merge_dock/reconcile short-circuits.

use std::collections::{BTreeMap, BTreeSet};

use crate::Oid;

/// The global liveness view for one operation. Construct via
/// [`crate::DagRepo::liveness`]; the Workspace supplies the store-owned
/// inputs (abandoned set, parked pointers).
pub struct Liveness {
    in_graph: BTreeSet<Oid>,
    abandoned: BTreeSet<Oid>,
    superseded: BTreeSet<Oid>,
    parked: BTreeSet<Oid>,
    cid_of: BTreeMap<Oid, [u8; 16]>,
    live_by_cid: BTreeMap<[u8; 16], Vec<Oid>>,
    divergent: BTreeSet<[u8; 16]>,
}

/// [`Liveness::partition`]'s answer to "given these graph heads, what may
/// converge do" (the head partition, map #215): drop `stale` without merging
/// (ADR 0032), leave `flat` as live heads (never content-merged — divergent
/// co-versions and parked working changes, #198/#203), fold `fold` (the
/// genuinely independent concurrent lines), all onto `ours` — the line the
/// dock actually materialized, **never a parked head** (the #203 pull footgun,
/// made unrepresentable here rather than guarded at call sites).
pub struct HeadPartition {
    pub ours: Option<Oid>,
    pub stale: Vec<Oid>,
    pub flat: Vec<Oid>,
    pub fold: Vec<Oid>,
}

impl Liveness {
    /// Build the view from `(version id, change id, predecessors)` triples —
    /// the graph's node projection — plus the store-owned sets. A
    /// `predecessors` entry only supersedes a version of the **same** change
    /// id (a cross-change claim is meaningless), and the naming version's own
    /// abandoned/superseded state is deliberately ignored: the graph is
    /// append-only, so a direct claim, once made, stands forever — abandon
    /// means kill, never revert (ADR 0032).
    pub(crate) fn compute(
        nodes: Vec<(Oid, Option<[u8; 16]>, Vec<Oid>)>,
        abandoned: BTreeSet<Oid>,
        parked: BTreeSet<Oid>,
    ) -> Liveness {
        let mut in_graph = BTreeSet::new();
        let mut cid_of = BTreeMap::new();
        for (id, cid, _) in &nodes {
            in_graph.insert(id.clone());
            if let Some(c) = cid {
                cid_of.insert(id.clone(), *c);
            }
        }
        let mut superseded = BTreeSet::new();
        for (_, cid, preds) in &nodes {
            let Some(cid) = cid else { continue };
            for p in preds {
                if cid_of.get(p) == Some(cid) {
                    superseded.insert(p.clone());
                }
            }
        }
        let mut live_by_cid: BTreeMap<[u8; 16], Vec<Oid>> = BTreeMap::new();
        for (id, cid, _) in &nodes {
            if abandoned.contains(id) || superseded.contains(id) {
                continue;
            }
            if let Some(c) = cid {
                live_by_cid.entry(*c).or_default().push(id.clone());
            }
        }
        let divergent = live_by_cid
            .iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(c, _)| *c)
            .collect();
        Liveness { in_graph, abandoned, superseded, parked, cid_of, live_by_cid, divergent }
    }

    /// live = in-graph ∧ ¬abandoned ∧ ¬superseded. Legacy/keyless nodes
    /// (no change id) can be live; they can never be superseded or divergent.
    pub fn is_live(&self, id: &Oid) -> bool {
        self.in_graph.contains(id)
            && !self.abandoned.contains(id)
            && !self.superseded.contains(id)
    }

    /// The live versions carrying `change_id` (graph order). `loot abandon`
    /// resolves its target among these; `loot edit` reopens the single one;
    /// ingest asks it whether an incoming co-version forms a divergence.
    pub fn live_of(&self, change_id: &[u8; 16]) -> Vec<Oid> {
        self.live_by_cid.get(change_id).cloned().unwrap_or_default()
    }

    /// The change ids carried by more than one live version — what `log`/
    /// `status` render with the trailing `!` (S3, ADR 0029/0032).
    pub fn divergent(&self) -> &BTreeSet<[u8; 16]> {
        &self.divergent
    }

    /// The versions some same-change-id version names in `predecessors`.
    pub fn superseded(&self) -> &BTreeSet<Oid> {
        &self.superseded
    }

    /// Whether `id` is a sibling dock's parked working change — in-flight
    /// unsigned WIP, not a line (#203).
    pub fn is_parked(&self, id: &Oid) -> bool {
        self.parked.contains(id)
    }

    /// The head partition (see [`HeadPartition`]). `base` is the caller's
    /// claim of the tip the working directory reflects (the pre-pull head);
    /// `anchor` is the dock's finalized anchor. Selection order for `ours`:
    /// base, then anchor, then the first non-parked head, then the first head
    /// — a candidate must be a non-stale head and is **rejected if parked**.
    /// Callers that drop `stale` heads should re-partition afterwards:
    /// dropping a head can restore its parents as heads the first pass never
    /// saw.
    pub fn partition(
        &self,
        heads: &[Oid],
        base: Option<&Oid>,
        anchor: Option<&Oid>,
    ) -> HeadPartition {
        let stale: Vec<Oid> =
            heads.iter().filter(|h| self.superseded.contains(*h)).cloned().collect();
        let remaining: Vec<Oid> =
            heads.iter().filter(|h| !self.superseded.contains(*h)).cloned().collect();
        let pick = |cand: Option<&Oid>| {
            cand.filter(|c| remaining.contains(c) && !self.parked.contains(c)).cloned()
        };
        let ours = pick(base)
            .or_else(|| pick(anchor))
            .or_else(|| remaining.iter().find(|h| !self.parked.contains(h)).cloned())
            .or_else(|| remaining.first().cloned());
        let mut flat = Vec::new();
        let mut fold = Vec::new();
        for h in &remaining {
            if Some(h) == ours.as_ref() {
                continue;
            }
            let divergent_cid =
                self.cid_of.get(h).is_some_and(|c| self.divergent.contains(c));
            if self.parked.contains(h) || divergent_cid {
                flat.push(h.clone());
            } else {
                fold.push(h.clone());
            }
        }
        HeadPartition { ours, stale, flat, fold }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> Oid {
        Oid([n; 32])
    }
    const CID: [u8; 16] = [7; 16];
    const CID2: [u8; 16] = [9; 16];

    /// X superseded by X′ (solo amend): X is stale, X′ live, no divergence.
    #[test]
    fn solo_amend_is_stale_never_divergent() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),          // X
                (oid(2), Some(CID), vec![oid(1)]),    // X' supersedes X
            ],
            Default::default(),
            Default::default(),
        );
        assert!(!lv.is_live(&oid(1)), "X is superseded");
        assert!(lv.is_live(&oid(2)));
        assert_eq!(lv.live_of(&CID), vec![oid(2)]);
        assert!(lv.divergent().is_empty(), "a solo amend is never divergence");

        let p = lv.partition(&[oid(1), oid(2)], Some(&oid(2)), None);
        assert_eq!(p.stale, vec![oid(1)], "the superseded head drops");
        assert_eq!(p.ours, Some(oid(2)));
        assert!(p.flat.is_empty() && p.fold.is_empty());
    }

    /// Two live versions of one change id: divergent, and both stay FLAT —
    /// converge mints no merge (#198/#203).
    #[test]
    fn co_versions_are_divergent_and_stay_flat() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),          // X
                (oid(2), Some(CID), vec![oid(1)]),    // ours' amend
                (oid(3), Some(CID), vec![oid(1)]),    // their amend
            ],
            Default::default(),
            Default::default(),
        );
        assert!(lv.divergent().contains(&CID));
        assert_eq!(lv.live_of(&CID).len(), 2);

        let p = lv.partition(&[oid(2), oid(3)], Some(&oid(2)), None);
        assert_eq!(p.ours, Some(oid(2)), "tip stays on ours");
        assert_eq!(p.flat, vec![oid(3)], "the co-version stays a live head");
        assert!(p.fold.is_empty(), "divergence is never content-merged");
    }

    /// A cross-change predecessors claim is meaningless and supersedes nothing.
    #[test]
    fn cross_change_claim_is_ignored() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),
                (oid(2), Some(CID2), vec![oid(1)]), // wrong cid names X
            ],
            Default::default(),
            Default::default(),
        );
        assert!(lv.is_live(&oid(1)), "a cross-change claim supersedes nothing");
    }

    /// An abandoned co-version leaves the live view: the survivor is sole and
    /// the change is not divergent.
    #[test]
    fn abandoned_versions_leave_the_live_view() {
        let lv = Liveness::compute(
            vec![
                (oid(2), Some(CID), vec![]),
                (oid(3), Some(CID), vec![]),
            ],
            BTreeSet::from([oid(3)]),
            Default::default(),
        );
        assert!(!lv.is_live(&oid(3)));
        assert_eq!(lv.live_of(&CID), vec![oid(2)]);
        assert!(lv.divergent().is_empty());
    }

    /// Parked WIP stays flat, and can NEVER be ours — not even when the caller
    /// passes it as the base (the live #203 pull footgun).
    #[test]
    fn parked_wip_is_flat_and_never_ours() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),   // main's tip
                (oid(4), Some(CID2), vec![]),  // sibling dock's parked WIP
            ],
            Default::default(),
            BTreeSet::from([oid(4)]),
        );
        let heads = [oid(4), oid(1)]; // parked sorts first — the footgun shape

        // Caller passes the parked head as base: rejected, anchor wins.
        let p = lv.partition(&heads, Some(&oid(4)), Some(&oid(1)));
        assert_eq!(p.ours, Some(oid(1)), "a parked base never becomes ours");
        assert_eq!(p.flat, vec![oid(4)], "parked WIP is not a line to converge");
        assert!(p.fold.is_empty());

        // No base, no anchor: first NON-parked head wins.
        let p = lv.partition(&heads, None, None);
        assert_eq!(p.ours, Some(oid(1)));
    }

    /// Genuinely independent concurrent lines fold; legacy nodes (no change
    /// id) are ordinary foldable lines.
    #[test]
    fn independent_lines_fold() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),
                (oid(5), Some(CID2), vec![]), // independent line
                (oid(6), None, vec![]),       // legacy node
            ],
            Default::default(),
            Default::default(),
        );
        let p = lv.partition(&[oid(1), oid(5), oid(6)], Some(&oid(1)), None);
        assert_eq!(p.ours, Some(oid(1)));
        assert!(p.flat.is_empty());
        assert_eq!(p.fold, vec![oid(5), oid(6)], "independent lines merge as today");
    }

    /// Selection order: base beats anchor beats first-non-parked.
    #[test]
    fn ours_selection_order() {
        let lv = Liveness::compute(
            vec![
                (oid(1), Some(CID), vec![]),
                (oid(2), Some(CID2), vec![]),
            ],
            Default::default(),
            Default::default(),
        );
        let heads = [oid(1), oid(2)];
        assert_eq!(lv.partition(&heads, Some(&oid(2)), Some(&oid(1))).ours, Some(oid(2)));
        assert_eq!(lv.partition(&heads, None, Some(&oid(2))).ours, Some(oid(2)));
        assert_eq!(lv.partition(&heads, None, None).ours, Some(oid(1)));
        // A base that is not a head at all falls through to the anchor.
        assert_eq!(lv.partition(&heads, Some(&oid(9)), Some(&oid(2))).ours, Some(oid(2)));
    }
}
