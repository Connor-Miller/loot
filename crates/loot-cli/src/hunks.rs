//! Hunks — the write-side line-redistribution engine behind `loot absorb`
//! (#399): the read-side twin of [`crate::blame`]. Where blame answers "which
//! ancestor last modified this line?", hunks answers "given the working
//! change's line edits, which ancestor should each edit fold back into, and
//! what does that ancestor's content become?"
//!
//! The whole line algebra — LCS alignment, hunk decomposition, ancestor
//! attribution, and the splice that re-applies a hunk onto a *different*
//! ancestor content — lives behind a small interface in terms of **bytes**:
//! [`attribute`] builds a per-path [`PathHunks`] plan from the parent/working
//! content and blame's owners, and [`PathHunks::apply_at`] rebuilds one
//! ancestor's content. `absorb` never sees a `LineHunk` or a line vector; it
//! deals only in oids, trees, and sealed bytes. That is the point of the seam:
//! the splice math is unit-testable here without a `Workspace`, and `absorb`
//! shrinks to the chain-walk plus sealing/superseding it alone can do.
//!
//! The one interface contract: `owners` is one [`blame::Attr`] per line of
//! `parent_bytes` under [`blame::split_lines`] — always true because owners
//! come from a blame walk, which splits the same way.

use crate::blame::{self, Attr};
use loot_core::Oid;
use std::collections::BTreeMap;

/// Why a hunk could not be absorbed and so stays in the working change. Absorb
/// only moves what it can attribute to a *readable* ancestor (the key-oracle
/// rule `blame`/`grep` share); everything else is left exactly where it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stay {
    /// No ancestor cleanly owns the lines the hunk touches — a new file, a
    /// deletion, or lines with no origin in the walked history.
    NoAncestor,
    /// The ancestor that owns the lines is sealed to this identity (its content
    /// cannot be opened), so `blame` renders its origin `<sealed>` and absorb
    /// refuses to fold blindly into content it cannot read.
    Sealed,
}

/// One path's movable edits, attributed to owning ancestors — built pure by
/// [`attribute`] (Phase A, immutable reads) and applied per-ancestor by
/// [`apply_at`](Self::apply_at) (Phase B, as `absorb` rebuilds the span). Holds
/// the parent-side line content each hunk is defined against; a hunk targeting
/// chain index `j` is in effect at every descendant `i <= j`.
pub struct PathHunks {
    parent_lines: Vec<String>,
    /// Each movable hunk paired with the first-parent chain index of the
    /// nearest ancestor that owns the parent lines it touches (smaller =
    /// nearer/newer).
    movable: Vec<(LineHunk, usize)>,
}

/// Attribute a path's parent→working line delta to the ancestors that own the
/// touched lines (Phase A). Returns the movable [`PathHunks`] plan (`None` when
/// no hunk had a clear ancestor) plus one [`Stay`] per hunk left behind.
///
/// `owners` must be one [`blame::Attr`] per line of `parent_bytes` (blame's
/// per-line output); `index_of` maps each change in the first-parent chain to
/// its distance from the working change (index 0 is the working change itself).
pub fn attribute(
    parent_bytes: &[u8],
    working_bytes: &[u8],
    owners: &[Attr],
    index_of: &BTreeMap<Oid, usize>,
) -> (Option<PathHunks>, Vec<Stay>) {
    let parent_lines = blame::split_lines(parent_bytes);
    let working_lines = blame::split_lines(working_bytes);
    let mut movable = Vec::new();
    let mut stayed = Vec::new();
    for h in diff_hunks(&parent_lines, &working_lines) {
        match attribute_hunk(&h, owners, index_of, parent_lines.len()) {
            HunkTarget::Ancestor(idx) => movable.push((h, idx)),
            HunkTarget::Stay(reason) => stayed.push(reason),
        }
    }
    let plan = (!movable.is_empty()).then_some(PathHunks { parent_lines, movable });
    (plan, stayed)
}

impl PathHunks {
    /// The owning-ancestor chain index of each movable hunk — one item per
    /// hunk, in plan order (repeats when several hunks share an owner).
    pub fn targets(&self) -> impl Iterator<Item = usize> + '_ {
        self.movable.iter().map(|(_, j)| *j)
    }

    /// Rebuild ancestor `i`'s content by splicing in every hunk in effect there
    /// (targeting `i` or newer). Returns the new bytes, preserving `base_bytes`'
    /// own trailing-newline so an unchanged re-seal keeps its oid — or `None`
    /// to leave the ancestor untouched: no hunk is in effect at `i`, or the
    /// splice would not land cleanly (a hunk's parent lines are not a contiguous
    /// run in `base`, or two hunks' target regions overlap — refuse, don't
    /// corrupt).
    pub fn apply_at(&self, i: usize, base_bytes: &[u8]) -> Option<Vec<u8>> {
        let in_effect: Vec<&LineHunk> =
            self.movable.iter().filter(|(_, j)| *j >= i).map(|(h, _)| h).collect();
        if in_effect.is_empty() {
            return None;
        }
        let base_lines = blame::split_lines(base_bytes);
        let new_lines = apply_hunks(&base_lines, &self.parent_lines, &in_effect)?;
        Some(join_lines(&new_lines, base_bytes.last() == Some(&b'\n')))
    }
}

// --- internals: the line algebra, invisible to callers ---

/// One contiguous changed region turning a path's parent-side content into its
/// working-side content: parent lines `[p0, p1)` are replaced by `lines` (the
/// working-side text of the region). A pure insertion has `p0 == p1`; a pure
/// deletion has empty `lines`.
#[derive(Debug, PartialEq, Eq)]
struct LineHunk {
    p0: usize,
    p1: usize,
    lines: Vec<String>,
}

/// Where a hunk was routed by [`attribute_hunk`]: the chain index of the
/// nearest owning ancestor, or a reason it stays in the working change.
enum HunkTarget {
    Ancestor(usize),
    Stay(Stay),
}

/// Rejoin lines into bytes, restoring a trailing newline when the source had
/// one — so a re-sealed ancestor's content matches on-disk content byte-for-byte
/// where the plaintext is unchanged (letting the snapshot dedup reuse its oid).
fn join_lines(lines: &[String], trailing_nl: bool) -> Vec<u8> {
    let mut s = lines.join("\n");
    if trailing_nl && !lines.is_empty() {
        s.push('\n');
    }
    s.into_bytes()
}

/// Decompose one path's parent→working line delta into [`LineHunk`]s, using the
/// same LCS alignment `blame` walks ([`blame::lcs_match`]): the matched lines are
/// unchanged anchors, and every maximal run of non-anchor parent and/or working
/// lines between two anchors (and before the first / after the last) is one hunk.
fn diff_hunks(p: &[String], s: &[String]) -> Vec<LineHunk> {
    let p_to_s = blame::lcs_match(p, s);
    let mut anchors: Vec<(usize, usize)> = Vec::new();
    for (pi, m) in p_to_s.iter().enumerate() {
        if let Some(sj) = *m {
            anchors.push((pi, sj));
        }
    }
    anchors.push((p.len(), s.len())); // sentinel that closes the trailing region
    let mut out = Vec::new();
    let (mut prev_p, mut prev_s) = (0usize, 0usize);
    for (pi, sj) in anchors {
        if pi > prev_p || sj > prev_s {
            out.push(LineHunk { p0: prev_p, p1: pi, lines: s[prev_s..sj].to_vec() });
        }
        prev_p = pi + 1;
        prev_s = sj + 1;
    }
    out
}

/// Apply hunks (defined against the parent content `p`) onto a *different*
/// content `base` — an ancestor's own version of the path — that shares the
/// parent lines each hunk touches. The lines a hunk targets trace (via blame)
/// to `base`'s change or older, so they appear verbatim and contiguous in
/// `base`; [`blame::lcs_match`] locates them. Returns `None` (leave the hunk
/// unabsorbed rather than corrupt the ancestor) if a hunk's parent lines are not
/// present as a contiguous run, or if two hunks' target regions overlap.
fn apply_hunks(base: &[String], p: &[String], hunks: &[&LineHunk]) -> Option<Vec<String>> {
    let p_to_base = blame::lcs_match(p, base);
    let mut splices: Vec<(usize, usize, Vec<String>)> = Vec::new();
    for h in hunks {
        if h.p1 > h.p0 {
            // A modification/deletion: the removed parent lines must all be
            // present in `base` and contiguous there.
            let mut mapped = Vec::with_capacity(h.p1 - h.p0);
            for k in h.p0..h.p1 {
                mapped.push((*p_to_base.get(k)?)?);
            }
            for w in mapped.windows(2) {
                if w[1] != w[0] + 1 {
                    return None;
                }
            }
            let b0 = mapped[0];
            let b1 = mapped[mapped.len() - 1] + 1;
            splices.push((b0, b1, h.lines.clone()));
        } else {
            // A pure insertion: anchor on the parent line before it (else after,
            // else the end of `base`).
            let bpos = if h.p0 > 0 {
                (*p_to_base.get(h.p0 - 1)?)? + 1
            } else if h.p0 < p.len() {
                (*p_to_base.get(h.p0)?)?
            } else {
                base.len()
            };
            splices.push((bpos, bpos, h.lines.clone()));
        }
    }
    splices.sort_by_key(|s| s.0);
    let mut out = Vec::new();
    let mut cur = 0usize;
    for (b0, b1, lines) in splices {
        if b0 < cur {
            return None; // overlapping splices — refuse rather than corrupt
        }
        out.extend_from_slice(&base[cur..b0]);
        out.extend(lines);
        cur = b1;
    }
    out.extend_from_slice(&base[cur..]);
    Some(out)
}

/// Attribute one hunk to the NEAREST ancestor that last modified the parent
/// lines it touches, via the parent-side blame `owners` (one [`blame::Attr`] per
/// parent line). `index_of` maps a change to its first-parent chain index
/// (smaller = nearer/newer), so the nearest owner is the one with the smallest
/// index. A modification/deletion touches its removed lines; a pure insertion
/// touches the parent lines bracketing the insertion point. A touched line whose
/// origin is `<sealed>` sends the whole hunk to [`Stay::Sealed`]; no ancestor
/// owner at all is [`Stay::NoAncestor`].
fn attribute_hunk(
    h: &LineHunk,
    owners: &[Attr],
    index_of: &BTreeMap<Oid, usize>,
    p_len: usize,
) -> HunkTarget {
    let mut touched: Vec<usize> = Vec::new();
    if h.p1 > h.p0 {
        touched.extend(h.p0..h.p1);
    } else {
        if h.p0 > 0 {
            touched.push(h.p0 - 1);
        }
        if h.p0 < p_len {
            touched.push(h.p0);
        }
    }
    if touched.is_empty() {
        return HunkTarget::Stay(Stay::NoAncestor);
    }
    let mut best: Option<usize> = None;
    for t in touched {
        match owners.get(t) {
            Some(Attr::Change(id)) => {
                if let Some(&idx) = index_of.get(id) {
                    best = Some(best.map_or(idx, |b: usize| b.min(idx)));
                }
            }
            Some(Attr::Sealed) => return HunkTarget::Stay(Stay::Sealed),
            None => {}
        }
    }
    match best {
        // index 0 is the working change itself (a novel line) — not an ancestor.
        Some(idx) if idx >= 1 => HunkTarget::Ancestor(idx),
        _ => HunkTarget::Stay(Stay::NoAncestor),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- the line-algebra internals (white-box, same-module access) ---

    #[test]
    fn diff_hunks_decomposes_a_modification_and_an_insertion() {
        let p = blame::split_lines(b"a\nb\nc\n");
        // Modify "b" -> "B" and insert "x" after "c".
        let s = blame::split_lines(b"a\nB\nc\nx\n");
        assert_eq!(
            diff_hunks(&p, &s),
            vec![
                LineHunk { p0: 1, p1: 2, lines: vec!["B".into()] },
                LineHunk { p0: 3, p1: 3, lines: vec!["x".into()] },
            ]
        );
    }

    #[test]
    fn apply_hunks_splices_into_a_smaller_ancestor_content() {
        // Parent has 4 lines; the ancestor (base) has only the first three (the
        // 4th was added later). A hunk over the parent's line 0 still lands.
        let p = blame::split_lines(b"alpha\nbeta\ngamma\ndelta\n");
        let base = blame::split_lines(b"alpha\nbeta\ngamma\n");
        let hunk = LineHunk { p0: 0, p1: 1, lines: vec!["alphaX".into()] };
        assert_eq!(
            apply_hunks(&base, &p, &[&hunk]).unwrap(),
            blame::split_lines(b"alphaX\nbeta\ngamma\n")
        );
    }

    #[test]
    fn apply_hunks_refuses_non_contiguous_parent_lines() {
        // The two removed parent lines are not adjacent in `base` — refuse.
        let p = blame::split_lines(b"a\nb\nc\n");
        let base = blame::split_lines(b"a\nX\nc\n");
        let hunk = LineHunk { p0: 0, p1: 3, lines: vec!["z".into()] };
        assert_eq!(apply_hunks(&base, &p, &[&hunk]), None);
    }

    #[test]
    fn attribute_hunk_routes_a_sealed_owner_to_stay() {
        let owners = vec![Attr::Sealed, Attr::Change(Oid([9; 32]))];
        let index_of = BTreeMap::from([(Oid([9; 32]), 1usize)]);
        let sealed = LineHunk { p0: 0, p1: 1, lines: vec!["x".into()] };
        assert!(matches!(
            attribute_hunk(&sealed, &owners, &index_of, 2),
            HunkTarget::Stay(Stay::Sealed)
        ));
        let clean = LineHunk { p0: 1, p1: 2, lines: vec!["y".into()] };
        assert!(matches!(
            attribute_hunk(&clean, &owners, &index_of, 2),
            HunkTarget::Ancestor(1)
        ));
    }

    // --- the public interface (bytes in, plan out) ---

    #[test]
    fn attribute_routes_two_hunks_to_their_owning_ancestors() {
        // parent line 0 owned by ancestor at index 2, line 2 by index 1.
        let owners = vec![
            Attr::Change(Oid([2; 32])),
            Attr::Change(Oid([2; 32])),
            Attr::Change(Oid([1; 32])),
        ];
        let index_of = BTreeMap::from([(Oid([2; 32]), 2usize), (Oid([1; 32]), 1usize)]);
        // Edit line 0 (a->A) and line 2 (c->C).
        let (plan, stayed) =
            attribute(b"a\nb\nc\n", b"A\nb\nC\n", &owners, &index_of);
        assert!(stayed.is_empty(), "both hunks attributed");
        let plan = plan.expect("a movable plan");
        let mut targets: Vec<usize> = plan.targets().collect();
        targets.sort();
        assert_eq!(targets, vec![1, 2], "one hunk to each owning ancestor");
    }

    #[test]
    fn attribute_leaves_a_novel_line_as_no_ancestor() {
        // A pure insertion of a line owned by nobody (index 0 is the wip itself).
        let owners = vec![Attr::Change(Oid([1; 32]))];
        let index_of = BTreeMap::from([(Oid([1; 32]), 0usize)]);
        let (plan, stayed) = attribute(b"a\n", b"a\nnovel\n", &owners, &index_of);
        assert!(plan.is_none(), "nothing movable");
        assert_eq!(stayed, vec![Stay::NoAncestor]);
    }

    #[test]
    fn apply_at_folds_only_hunks_in_effect_and_preserves_trailing_newline() {
        // Two hunks: one targeting ancestor index 2, one index 1.
        let owners = vec![
            Attr::Change(Oid([2; 32])),
            Attr::Change(Oid([2; 32])),
            Attr::Change(Oid([1; 32])),
        ];
        let index_of = BTreeMap::from([(Oid([2; 32]), 2usize), (Oid([1; 32]), 1usize)]);
        let (plan, _) = attribute(b"a\nb\nc\n", b"A\nb\nC\n", &owners, &index_of);
        let plan = plan.unwrap();

        // At ancestor index 2, both hunks (index >= 2 is just the a->A one, and
        // index 1 < 2 is NOT in effect here). Its base is the parent content.
        let at2 = plan.apply_at(2, b"a\nb\nc\n").unwrap();
        assert_eq!(at2, b"A\nb\nc\n", "only the index-2 hunk folds at ancestor 2");
        assert_eq!(at2.last(), Some(&b'\n'), "trailing newline preserved");

        // At ancestor index 1, both hunks are in effect (1 and 2 both >= 1).
        let at1 = plan.apply_at(1, b"a\nb\nc\n").unwrap();
        assert_eq!(at1, b"A\nb\nC\n", "both hunks fold at ancestor 1");

        // A base with no trailing newline stays that way.
        let no_nl = plan.apply_at(2, b"a\nb\nc").unwrap();
        assert_eq!(no_nl.last(), Some(&b'c'), "no trailing newline added");
    }

    #[test]
    fn apply_at_returns_none_when_no_hunk_is_in_effect() {
        let owners = vec![Attr::Change(Oid([1; 32])), Attr::Change(Oid([1; 32]))];
        let index_of = BTreeMap::from([(Oid([1; 32]), 1usize)]);
        let (plan, _) = attribute(b"a\nb\n", b"A\nb\n", &owners, &index_of);
        let plan = plan.unwrap();
        // The only hunk targets index 1; at index 2 nothing is in effect.
        assert_eq!(plan.apply_at(2, b"a\nb\n"), None);
    }
}
