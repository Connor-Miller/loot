//! Verb output rendering (R5, #181): compute-then-render, one home.
//!
//! Every function here **returns a `String`** and performs no I/O — the verb
//! computes a value (a [`HistoryView`], an outcome map, a buoy resolution),
//! rendering turns it into the exact bytes `main` prints, and tests assert on
//! the returned string. This is deliberately *not* ADR 0023's rejected global
//! renderer: no machine contracts are added here (those live in
//! `loot_core::verdict`); this is only the human text, separated from
//! `println!` so it has a test surface.
//!
//! Anything registry-coupled (resolving a pubkey to a peer name) stays with
//! the caller and arrives as a closure — rendering knows names, not keyrings.

use crate::workspace::{HistoryRow, HistoryView, WorkingRow};
use loot_core::{MergeOutcome, Oid};
use std::collections::BTreeMap;
use std::fmt::Write as _;

/// The em dash shown where an id is absent — a legacy change with no change id,
/// or the empty working change's not-yet-computed version (ADR 0029/0030).
pub const NO_ID: &str = "—";

/// Human phrasing for a merge outcome, naming the relay role explicitly.
pub fn describe(o: &MergeOutcome) -> &'static str {
    match o {
        MergeOutcome::Converged => "converged",
        MergeOutcome::Merged => "merged",
        MergeOutcome::Conflict { .. } => "conflict (needs resolution)",
        MergeOutcome::RelayedUnmerged => "relayed (sealed — you lack the key)",
    }
}

/// A version id's short display: the first 4 bytes as hex digits.
pub fn short(oid: &Oid) -> String {
    oid.0[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Annotate a dock/change with its sealed/embargoed file counts, or "" if all
/// public — the `docks` summary token. Distinct from [`vis_col`], which is the
/// compact `log` column over the same counts.
pub fn seal_hint(total: usize, restricted: usize, embargoed: usize) -> String {
    match (restricted, embargoed) {
        (0, 0) => String::new(),
        (r, 0) => format!("  [{r}/{total} sealed]"),
        (0, e) => format!("  [{e}/{total} embargoed]"),
        (r, e) => format!("  [{r} sealed, {e} embargoed / {total}]"),
    }
}

/// A change id's short display: the first 4 bytes as reverse-hex **letters**
/// (ADR 0029), e.g. `qsouzmpr` — the durable-handle twin of [`short`]'s hex
/// **digits**. The two alphabets disambiguate the ids at a glance.
pub fn short_change(cid: &[u8; 16]) -> String {
    loot_core::hex::short_letters(cid, 4)
}

/// The change-id column for `log`/`status` (ADR 0029/0030): the reverse-hex
/// letters, with a trailing **`!`** when the change is **divergent** — one change
/// id carrying more than one live version (S3). `None` (a legacy/unsigned change)
/// renders as the absent-id dash and can never be divergent.
pub fn change_col(cid: Option<[u8; 16]>, divergent: &std::collections::BTreeSet<[u8; 16]>) -> String {
    match cid {
        Some(c) if divergent.contains(&c) => format!("{}!", short_change(&c)),
        Some(c) => short_change(&c),
        None => NO_ID.to_string(),
    }
}

/// Header + one row of the columnar `log`/`status` display (ADR 0030): the two
/// ids ride their own columns so a change can carry both legibly. Column order
/// is **change · version · message · vis · author**.
pub fn log_header() -> String {
    log_row("change", "version", "message", "vis", "author")
}

/// One columnar row (see [`log_header`] for the column order).
pub fn log_row(change: &str, version: &str, message: &str, vis: &str, author: &str) -> String {
    // Trailing whitespace trimmed so empty tail columns don't dangle.
    format!("{change:<10} {version:<9} {message:<30} {vis:<12} {author}")
        .trim_end()
        .to_string()
}

/// The compact `vis` column for a finalized change: the count of sealed and/or
/// embargoed paths, or empty when the change is fully public.
pub fn vis_col(_total: usize, restricted: usize, embargoed: usize) -> String {
    match (restricted, embargoed) {
        (0, 0) => String::new(),
        (r, 0) => format!("{r} sealed"),
        (0, e) => format!("{e} embargoed"),
        (r, e) => format!("{r} sealed, {e} emb"),
    }
}

/// The working-change row for `log` (ADR 0030): the durable change id
/// (letters) + the live version id (hex, `—` when the change is empty), the
/// message, and the current identity as author. Shares the columnar shape with
/// the finalized rows so the two ids line up.
fn working_row_line(
    identity: &str,
    row: &WorkingRow,
    divergent: &std::collections::BTreeSet<[u8; 16]>,
) -> String {
    let change = change_col(row.change_id, divergent);
    let (version, message) = if row.empty {
        (NO_ID.to_string(), "(working change, empty)".to_string())
    } else {
        (short(&row.version), row.message.clone())
    };
    log_row(&change, &version, &message, "", identity)
}

/// The full human `log` output for a [`HistoryView`] (R1/R5): the flat listing
/// when history is one change line, the per-head fork view when it forked.
/// `name_of` resolves an author pubkey to a display name (peer registry + self
/// — the caller's knowledge, not rendering's).
pub fn render_history(
    view: &HistoryView,
    identity: &str,
    name_of: &dyn Fn(Option<&[u8; 32]>) -> String,
) -> String {
    let mut out = String::new();
    let push_row = |out: &mut String, row: &HistoryRow| {
        let _ = writeln!(
            out,
            "{}",
            log_row(
                &change_col(row.change_id, &view.divergent),
                &short(&row.version),
                &row.message,
                &vis_col(row.total, row.restricted, row.embargoed),
                &name_of(row.author.as_ref()),
            )
        );
        for (attester, role) in &row.attestations {
            let _ = writeln!(out, "    + attested by {} ({})", name_of(Some(attester)), role);
        }
    };

    match &view.graph {
        None => {
            let _ = writeln!(out, "{}", log_header());
            for row in &view.rows {
                push_row(&mut out, row);
            }
            if let Some(row) = &view.working {
                let _ = writeln!(out, "{}", working_row_line(identity, row, &view.divergent));
            }
        }
        Some(g) => {
            let _ = writeln!(out, "{} heads — diverged; run `loot apply` to converge", g.heads.len());
            for (hi, head) in g.heads.iter().enumerate() {
                let _ = writeln!(out);
                let _ = writeln!(out, "head {} — {}", hi + 1, short(head));
                let _ = writeln!(out, "{}", log_header());
                for row in &g.per_head[hi] {
                    push_row(&mut out, row);
                }
            }
            if !g.shared.is_empty() {
                let _ = writeln!(out);
                let _ = writeln!(out, "shared history");
                let _ = writeln!(out, "{}", log_header());
                for row in &g.shared {
                    push_row(&mut out, row);
                }
            }
        }
    }
    out
}

/// The per-path outcome block shared by `apply`/`pull`/`ferry`/`dock merge`
/// human output: `  <path, left-padded>  <describe(outcome)>` per row.
pub fn outcome_rows(outcomes: &BTreeMap<std::path::PathBuf, MergeOutcome>) -> String {
    let mut out = String::new();
    for (path, outcome) in outcomes {
        let _ = writeln!(out, "  {:<24} {}", path.display(), describe(outcome));
    }
    out
}

/// The human buoy report (CA4, ADR 0025) — the machine shapes live in
/// `loot_core::verdict::BuoyVerdict`; this is only the prose.
pub fn render_buoy_human(
    result: &loot_core::buoy::BuoyResult,
    role: &str,
    name_of: &dyn Fn(&[u8; 32]) -> String,
) -> String {
    use loot_core::buoy::BuoyResult;
    let mut out = String::new();
    match result {
        BuoyResult::Resolved { change, attesters } => {
            let names: Vec<String> = attesters.iter().map(name_of).collect();
            let _ = writeln!(out, "buoy ({}): {} — attested by {}", role, short(change), names.join(", "));
        }
        BuoyResult::Ambiguous { candidates } => {
            let _ = writeln!(
                out,
                "ambiguous: {role} is attested on {} concurrent changes — attest one to resolve:",
                candidates.len()
            );
            for c in candidates {
                let names: Vec<String> = c.attesters.iter().map(name_of).collect();
                let _ = writeln!(out, "  {} (attested by {})", short(&c.change), names.join(", "));
            }
            let _ = writeln!(out, "  run `loot attest <id> {role}` to pin one as the buoy");
        }
        BuoyResult::None => {
            let _ = writeln!(out, "no buoy for role '{role}'");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn oid(b: u8) -> Oid {
        Oid([b; 32])
    }

    fn row(b: u8, msg: &str) -> HistoryRow {
        HistoryRow {
            version: oid(b),
            message: msg.into(),
            total: 1,
            restricted: 0,
            embargoed: 0,
            change_id: Some([b; 16]),
            author: Some([b; 32]),
            attestations: vec![],
        }
    }

    fn names(pk: Option<&[u8; 32]>) -> String {
        match pk {
            Some(p) => format!("peer{:02x}", p[0]),
            None => String::new(),
        }
    }

    #[test]
    fn history_flat_listing_renders_header_rows_and_working() {
        let view = HistoryView {
            rows: vec![row(2, "second"), row(1, "first")],
            divergent: BTreeSet::new(),
            working: Some(WorkingRow {
                change_id: Some([9; 16]),
                version: oid(9),
                message: "wip".into(),
                entries: vec![],
                empty: true,
            }),
            graph: None,
        };
        let out = render_history(&view, "alice", &names);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], log_header());
        assert!(lines[1].contains("second") && lines[1].contains("peer02"), "{}", lines[1]);
        assert!(lines[2].contains("first"));
        // Empty working change renders the dash version + placeholder message.
        assert!(lines[3].contains(NO_ID) && lines[3].contains("(working change, empty)"));
        assert!(lines[3].ends_with("alice"));
    }

    #[test]
    fn history_renders_attestations_under_their_row() {
        let mut r = row(1, "reviewed change");
        r.attestations.push(([7; 32], "reviewed".into()));
        let view = HistoryView {
            rows: vec![r],
            divergent: BTreeSet::new(),
            working: None,
            graph: None,
        };
        let out = render_history(&view, "alice", &names);
        assert!(out.contains("    + attested by peer07 (reviewed)"), "{out}");
    }

    #[test]
    fn history_fork_view_renders_heads_and_shared() {
        let view = HistoryView {
            rows: vec![],
            divergent: BTreeSet::new(),
            working: None,
            graph: Some(crate::workspace::GraphHistory {
                heads: vec![oid(1), oid(2)],
                per_head: vec![vec![row(1, "left")], vec![row(2, "right")]],
                shared: vec![row(3, "base")],
            }),
        };
        let out = render_history(&view, "alice", &names);
        assert!(out.starts_with("2 heads — diverged"), "{out}");
        assert!(out.contains("head 1 —") && out.contains("left"));
        assert!(out.contains("head 2 —") && out.contains("right"));
        assert!(out.contains("shared history") && out.contains("base"));
    }

    #[test]
    fn outcome_rows_render_paths_with_descriptions() {
        let mut m = BTreeMap::new();
        m.insert(std::path::PathBuf::from("a.txt"), MergeOutcome::Merged);
        m.insert(
            std::path::PathBuf::from("b.txt"),
            MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) },
        );
        let out = outcome_rows(&m);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("  a.txt") && lines[0].ends_with("merged"));
        assert!(lines[1].contains("conflict (needs resolution)"));
    }

    #[test]
    fn buoy_human_covers_all_three_outcomes() {
        let single = |pk: &[u8; 32]| format!("peer{:02x}", pk[0]);
        let resolved = loot_core::buoy::BuoyResult::Resolved { change: oid(1), attesters: vec![[7; 32]] };
        assert!(render_buoy_human(&resolved, "reviewed", &single).contains("attested by peer07"));
        let none = loot_core::buoy::BuoyResult::None;
        assert_eq!(render_buoy_human(&none, "reviewed", &single), "no buoy for role 'reviewed'\n");
        let ambiguous = loot_core::buoy::BuoyResult::Ambiguous {
            candidates: vec![loot_core::buoy::Candidate { change: oid(1), attesters: vec![[7; 32]] }],
        };
        let out = render_buoy_human(&ambiguous, "base", &single);
        assert!(out.contains("ambiguous: base is attested on 1 concurrent changes"));
        assert!(out.contains("run `loot attest <id> base`"));
    }
}
