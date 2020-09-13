//! `loot blame` — line-level authorship annotation (#389).
//!
//! git's `blame` answers "which change last touched this line, and who wrote
//! it?". loot's answer walks the change graph for one path, decrypting each
//! version through the key oracle to find, per line, the newest change that
//! introduced it — then resolves that change's author to a peer name.
//!
//! Three loot-specific rules shape it (the ticket's notes):
//!
//! * **The key oracle gates every read.** A version this identity cannot open
//!   (sealed / embargoed / burned) is never an error — the lines whose origin
//!   hides behind it render `<sealed>` (their author unknown to us), and the
//!   whole file being sealed is reported, not thrown.
//! * **Content-address reuse (#98) short-circuits the walk.** A path whose
//!   sealed object is byte-identical across adjacent changes was *not* modified
//!   there; [`distinct_versions`] collapses such a run to the **oldest** change
//!   bearing that content — the change that truly last modified it.
//! * The walk is over the live lineage (parent edges of the resolved point),
//!   which already reflects ADR 0032 amends (a superseding version carries its
//!   original's clean parentage), so the annotation tracks the live history.
//!
//! The pure core ([`lcs_match`], [`distinct_versions`], [`blame_lines`]) is a
//! function of its inputs and is unit-tested below without a `Workspace`;
//! [`run`] is the thin glue that feeds it the graph and renders the result.

use crate::emit::{Emit, Message};
use crate::error::CliError;
use crate::render::{short, short_change};
use crate::workspace::{Graph, Workspace};
use loot_core::Oid;
use loot_identity::PeerRegistry;
use std::fmt::Write as _;
use std::path::Path;

/// What one line's origin resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    /// The change that introduced (last modified) the line.
    Change(Oid),
    /// The line predates a version this identity cannot open — its true origin
    /// is hidden behind a seal, so we honestly refuse to name a change.
    Sealed,
}

/// One distinct content version of the path along the walked lineage, newest
/// first. `content` is the decrypted bytes, or `None` when the key oracle
/// cannot open this version for the current identity (sealed / embargoed /
/// burned). An absent path (a deletion boundary) is modelled as `Some(empty)`.
#[derive(Debug, Clone)]
pub struct BlameVersion {
    pub change: Oid,
    pub content: Option<Vec<u8>>,
}

/// Split raw bytes into display lines. Lossy-UTF8 so a stray non-text byte
/// annotates rather than aborts (blame is a best-effort read, never a gate).
fn split_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes).lines().map(str::to_string).collect()
}

/// A longest-common-subsequence alignment of `a` onto `b`: for each index in
/// `a`, the index in `b` it matches under one LCS, or `None` when the `a` line
/// is not in the subsequence (i.e. it was introduced relative to `b`). The
/// matching is strictly increasing in both, which is exactly the "unchanged
/// line" relation blame needs to carry a line further back through history.
pub fn lcs_match(a: &[String], b: &[String]) -> Vec<Option<usize>> {
    let (n, m) = (a.len(), b.len());
    // dp[i][j] = LCS length of a[i..] and b[j..].
    let mut dp = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            dp[i][j] = if a[i] == b[j] {
                dp[i + 1][j + 1] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    let mut out = vec![None; n];
    let (mut i, mut j) = (0usize, 0usize);
    while i < n && j < m {
        if a[i] == b[j] {
            out[i] = Some(j);
            i += 1;
            j += 1;
        } else if dp[i + 1][j] >= dp[i][j + 1] {
            i += 1;
        } else {
            j += 1;
        }
    }
    out
}

/// Collapse a newest-first linear chain of changes into the newest-first list
/// of **distinct content boundaries** for the path: one entry per change that
/// actually produced a new content address, a run of an unchanged address
/// (#98) collapsed to the **oldest** change bearing it. `file_oid` looks up the
/// path's content address at a change (`None` = the path is absent there — a
/// deletion / not-yet-created boundary, kept as its own distinct value).
pub fn distinct_versions(
    chain: &[Oid],
    file_oid: impl Fn(&Oid) -> Option<Oid>,
) -> Vec<(Oid, Option<Oid>)> {
    let mut old_to_new: Vec<(Oid, Option<Oid>)> = Vec::new();
    let mut prev: Option<Option<Oid>> = None;
    // Oldest first: the first change to bear a given address is its producer.
    for id in chain.iter().rev() {
        let fo = file_oid(id);
        if prev.as_ref() != Some(&fo) {
            old_to_new.push((id.clone(), fo.clone()));
            prev = Some(fo);
        }
    }
    old_to_new.reverse();
    old_to_new
}

/// Attribute each line of the newest version to a change (or `<sealed>`).
///
/// `versions` is newest-first (`versions[0]` is the version being blamed and
/// must be openable — the caller reports a fully-sealed file separately). The
/// walk carries each still-unattributed line back through successive versions:
/// a line matched by [`lcs_match`] into the older version existed before this
/// change, so it is carried further; an unmatched line was introduced here and
/// is attributed to this change. A line that survives to the oldest version
/// originates there. When the older version is sealed, the origin of every
/// still-carried line is hidden — those lines become [`Attr::Sealed`].
pub fn blame_lines(versions: &[BlameVersion]) -> Vec<Attr> {
    let Some(first) = versions.first() else { return Vec::new() };
    let Some(target_bytes) = first.content.as_ref() else { return Vec::new() };
    let n = split_lines(target_bytes).len();

    let mut attr: Vec<Option<Attr>> = vec![None; n];
    // `carried[k]` is the current-version line index of the k-th still-open
    // line; `targ[k]` is which target line index it maps back to.
    let mut carried: Vec<usize> = (0..n).collect();
    let mut targ: Vec<usize> = (0..n).collect();

    for i in 0..versions.len() {
        if carried.is_empty() {
            break;
        }
        let Some(a_bytes) = versions[i].content.as_ref() else {
            // Defensive: only reachable if a caller hands a sealed non-first
            // version we advanced into, which the loop below never does.
            for &t in &targ {
                attr[t] = Some(Attr::Sealed);
            }
            break;
        };
        let a_lines = split_lines(a_bytes);

        match versions.get(i + 1) {
            // An older version exists — diff against it to peel off this
            // change's own introductions.
            Some(older) => match older.content.as_ref() {
                None => {
                    // Older version sealed: what predates this change is hidden.
                    for &t in &targ {
                        attr[t] = Some(Attr::Sealed);
                    }
                    break;
                }
                Some(b_bytes) => {
                    let b_lines = split_lines(b_bytes);
                    let matched = lcs_match(&a_lines, &b_lines);
                    let mut next_carried = Vec::new();
                    let mut next_targ = Vec::new();
                    for k in 0..carried.len() {
                        let a_idx = carried[k];
                        let t = targ[k];
                        match matched.get(a_idx).copied().flatten() {
                            // Existed before this change — carry it further back.
                            Some(b_idx) => {
                                next_carried.push(b_idx);
                                next_targ.push(t);
                            }
                            // Introduced (last modified) by this change.
                            None => attr[t] = Some(Attr::Change(versions[i].change.clone())),
                        }
                    }
                    carried = next_carried;
                    targ = next_targ;
                }
            },
            // Oldest version reached — every surviving line originates here.
            None => {
                for &t in &targ {
                    attr[t] = Some(Attr::Change(versions[i].change.clone()));
                }
                break;
            }
        }
    }

    let newest = versions[0].change.clone();
    attr.into_iter().map(|a| a.unwrap_or_else(|| Attr::Change(newest.clone()))).collect()
}

/// Open a stored object for the ambient identity, mapping any failure (no key,
/// embargoed, burned, missing) to `None` — the key-oracle contract: blame never
/// fails on content it cannot read, it renders the origin `<sealed>` instead.
fn open_content(g: &Graph, oid: &Oid) -> Option<Vec<u8>> {
    g.content(oid).ok()
}

/// Resolve an author pubkey to a display name: the ambient identity for our own
/// key, else the peer registry's nickname, else a short hex of the key.
fn author_name(reg: &PeerRegistry, own: Option<&[u8; 32]>, author: Option<[u8; 32]>) -> String {
    match author {
        Some(pk) if own == Some(&pk) => String::new(), // caller substitutes identity
        Some(pk) => {
            for (name, line) in reg.list() {
                if PeerRegistry::parse_pubkey_bytes_from_line(line).map_or(false, |k| k == pk) {
                    return name.to_string();
                }
            }
            format!("{}…", loot_core::hex::encode(&pk[..4]))
        }
        None => String::new(),
    }
}

/// The path's content address at `id`, if the change records it in its tree.
fn file_oid_at(g: &Graph, id: &Oid, path: &Path) -> Option<Oid> {
    g.tree(id).and_then(|t| t.get(path).map(|(oid, _vis)| oid.clone()))
}

/// `loot blame <path> [<selector>]` — annotate each line of `<path>` with the
/// change and author that last modified it. `<selector>` (the #305 grammar:
/// `@`, `HEAD`, `HEAD~<n>`, an id prefix) picks the version to blame; it
/// defaults to the working change (`@`), falling back to `HEAD` when there is
/// none. Read-only: it blames the last-captured content, never snapshotting.
pub fn run(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    let positionals: Vec<&str> =
        args.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
    let path_arg = *positionals.first().ok_or("usage: loot blame <path> [<selector>]")?;
    let path = Path::new(path_arg);

    let ws = Workspace::open().map_err(CliError::no_repo)?;
    let g = ws.graph();

    // Resolve the point to blame: an explicit selector, else `@`, else `HEAD`.
    let target = match positionals.get(1) {
        Some(sel) => ws.resolve_selector(sel)?,
        None => ws.resolve_selector("@").or_else(|_| ws.resolve_selector("HEAD"))?,
    };

    // The path must exist at the blamed point.
    if file_oid_at(&g, &target, path).is_none() {
        return Err(format!(
            "{} is not present at the blamed change — nothing to annotate",
            path.display()
        )
        .into());
    }

    // Newest-first linear (first-parent) lineage from the target back to a root.
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut cur = Some(target.clone());
    while let Some(c) = cur {
        if !seen.insert(c.clone()) {
            break; // cycle guard (a DAG never has one, but never loop forever)
        }
        chain.push(c.clone());
        cur = g.parents(&c).into_iter().next();
    }

    // Collapse to distinct content boundaries (#98), then open each version.
    let versions: Vec<BlameVersion> = distinct_versions(&chain, |id| file_oid_at(&g, id, path))
        .into_iter()
        .map(|(change, fo)| BlameVersion {
            change,
            content: match fo {
                Some(oid) => open_content(&g, &oid),
                None => Some(Vec::new()), // an absent boundary is empty content
            },
        })
        .collect();

    // A fully-sealed newest version has no readable lines to annotate.
    let Some(target_bytes) = versions.first().and_then(|v| v.content.clone()) else {
        return Ok(Box::new(Message::new(format!(
            "{} is sealed to {} at the blamed change — no readable lines to annotate\n",
            path.display(),
            ws.identity()
        ))));
    };

    let target_lines = split_lines(&target_bytes);
    if target_lines.is_empty() {
        return Ok(Box::new(Message::new(format!(
            "{} is empty at the blamed change\n",
            path.display()
        ))));
    }

    let attrs = blame_lines(&versions);
    let reg = PeerRegistry::load(ws.dot());
    let own = ws.author_pubkey();

    let mut out = String::new();
    for (i, (line, attr)) in target_lines.iter().zip(attrs).enumerate() {
        let (change_col, author_col) = match attr {
            Attr::Sealed => ("<sealed>".to_string(), String::new()),
            Attr::Change(id) => {
                // Prefer the durable change-id handle (letters, ADR 0029); fall
                // back to the version id hex for a legacy/unauthored change.
                let handle =
                    g.change_id(&id).map(|c| short_change(&c)).unwrap_or_else(|| short(&id));
                let mut name = author_name(&reg, own.as_ref(), g.author(&id));
                if name.is_empty() && own.as_ref() == g.author(&id).as_ref() && g.author(&id).is_some()
                {
                    name = ws.identity().to_string();
                }
                (handle, name)
            }
        };
        let _ = writeln!(out, "{change_col:<8} {author_col:<14} {:>4}) {line}", i + 1);
    }
    Ok(Box::new(Message::new(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    fn v(change: u8, content: Option<&str>) -> BlameVersion {
        BlameVersion { change: oid(change), content: content.map(|s| s.as_bytes().to_vec()) }
    }

    #[test]
    fn single_version_attributes_every_line_to_that_change() {
        let versions = vec![v(1, Some("a\nb\nc"))];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Change(oid(1)), Attr::Change(oid(1)), Attr::Change(oid(1))]
        );
    }

    #[test]
    fn a_new_line_is_blamed_on_the_change_that_added_it() {
        // Newer (change 2) added "b" between the two original lines.
        let versions = vec![v(2, Some("a\nb\nc")), v(1, Some("a\nc"))];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Change(oid(1)), Attr::Change(oid(2)), Attr::Change(oid(1))]
        );
    }

    #[test]
    fn a_modified_line_is_blamed_newer_untouched_lines_stay_old() {
        // Change 2 rewrote the middle line only.
        let versions = vec![v(2, Some("a\nB\nc")), v(1, Some("a\nb\nc"))];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Change(oid(1)), Attr::Change(oid(2)), Attr::Change(oid(1))]
        );
    }

    #[test]
    fn lines_surviving_across_three_versions_trace_to_the_oldest() {
        // "a" present throughout -> oldest (1); "b" added in 2; "c" added in 3.
        let versions =
            vec![v(3, Some("a\nb\nc")), v(2, Some("a\nb")), v(1, Some("a"))];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Change(oid(1)), Attr::Change(oid(2)), Attr::Change(oid(3))]
        );
    }

    #[test]
    fn a_sealed_older_version_hides_the_origin_of_predating_lines() {
        // Change 3 (readable) added "new" over readable change 2; "a"/"b" trace
        // back past change 2 into the *sealed* change 1, so their origin is
        // hidden (`<sealed>`) rather than guessed, while "new" is still cleanly
        // attributed to change 3 — the useful mixed case.
        let versions = vec![v(3, Some("a\nnew\nb")), v(2, Some("a\nb")), v(1, None)];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Sealed, Attr::Change(oid(3)), Attr::Sealed]
        );
    }

    #[test]
    fn a_sealed_immediate_parent_hides_every_line() {
        // No readable predecessor at all: nothing can be diffed, so every line
        // of the readable newest version is of indeterminate (sealed) origin —
        // the honest answer, never a guess.
        let versions = vec![v(2, Some("a\nnew\nb")), v(1, None)];
        assert_eq!(
            blame_lines(&versions),
            vec![Attr::Sealed, Attr::Sealed, Attr::Sealed]
        );
    }

    #[test]
    fn a_sealed_newest_version_yields_no_attributions() {
        // The caller reports the fully-sealed file; blame_lines has no lines.
        let versions = vec![v(2, None), v(1, Some("a"))];
        assert!(blame_lines(&versions).is_empty());
    }

    #[test]
    fn distinct_versions_collapses_unchanged_address_runs_to_the_oldest() {
        // Chain newest->oldest: 4,3,2,1. Path oid: 4&3 share addr X (unchanged
        // since 3), 2 has addr Y, 1 absent. Boundaries: producer of X is 3
        // (oldest bearing it), producer of Y is 2, plus the absent boundary 1.
        let chain = vec![oid(4), oid(3), oid(2), oid(1)];
        let addr = |id: &Oid| match id.0[0] {
            4 | 3 => Some(oid(0xAA)),
            2 => Some(oid(0xBB)),
            _ => None,
        };
        let got = distinct_versions(&chain, addr);
        assert_eq!(
            got,
            vec![
                (oid(3), Some(oid(0xAA))),
                (oid(2), Some(oid(0xBB))),
                (oid(1), None),
            ]
        );
    }

    #[test]
    fn lcs_match_aligns_unchanged_lines_and_flags_introductions() {
        let a = split_lines(b"a\nx\nb");
        let b = split_lines(b"a\nb");
        // "a"->0, "x" introduced (None), "b"->1.
        assert_eq!(lcs_match(&a, &b), vec![Some(0), None, Some(1)]);
    }
}
