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

use crate::workspace::{EditReport, HistoryRow, HistoryView, PathDelta, WorkingRow};
use loot_core::{verdict, MergeOutcome, Oid, Visibility};
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

/// The `loot edit` confirmation (ADR 0032): the durable handle stays, the named
/// version is superseded once the amend finalizes, and undo walks it back.
pub fn edit_done(r: &EditReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "editing change {} — reopened version {} as the working change",
        short_change(&r.change_id),
        short(&r.superseded),
    );
    let _ = writeln!(
        out,
        "  finalize (`loot new`) to supersede {} with your amended version; `loot undo` walks this back",
        short(&r.superseded),
    );
    out
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

// --- the shared path-delta line (#306, Variant A) ---------------------------
//
// The one human-format seam every delta-rendering verb shares — `loot diff`
// (#1) lands it, `loot status` (#7) and `loot diff --conflict` (#13) consume
// it. Machine output stays on the `verdict` porcelain/json encoders; this is
// only the human line. The contract (#306):
//
//     {X}  {label}    {visibility}
//
// a 2-space git-style gutter carrying the delta class (`+`/`M`/`-`), the path
// left-padded so the visibility token trails, and the token itself with two
// human refinements: an embargo humanized to a date, and a visibility change
// shown inline as `was → now`. When the path is sealed to the caller the label
// degrades to the content address and the token to its bare class, tagged
// `(sealed — no key)` — you learn *that* a restricted path changed and its
// class, never its name.

// The computed value — [`PathDelta`] and its [`DeltaClass`] — lives in
// `workspace.rs` beside the other compute-value types (`HistoryView`,
// `WorkingRow`), the direction this module's header describes: the verb
// computes, rendering turns the value into bytes.

/// Min-width of the label column so the visibility token lines up; a longer
/// path (or a sealed address) just pushes the token right, git-style (#306).
const LABEL_WIDTH: usize = 22;

/// The human path-delta line (#306 Variant A). See the section comment for the
/// contract; `#7`/`#13` call this per row rather than re-deriving the shape.
pub fn delta_line(d: &PathDelta) -> String {
    let (label, token) = if d.sealed {
        // The caller can't read a sealed path's name: show the content address
        // and keep only the visibility *class*, tagged so the fallback is legible.
        (format!("{}…", short(&d.oid)), vis_class(&d.visibility).to_string())
    } else {
        let token = match &d.prev_visibility {
            Some(prev) if prev != &d.visibility => {
                format!("{} → {}", vis_human(prev), vis_human(&d.visibility))
            }
            _ => vis_human(&d.visibility),
        };
        (d.path.display().to_string(), token)
    };
    let mut line = format!("  {}  {:<width$} {}", d.class.gutter(), label, token, width = LABEL_WIDTH);
    if d.sealed {
        line.push_str("   (sealed — no key)");
    }
    line
}

/// The visibility token for the human delta line: reuses the `verdict` token
/// (`public` / `restricted=a,b`) but humanizes an embargo to a calendar date
/// (`embargoed until 2027-01-15`) — porcelain/json keep the raw `embargoed@<ts>`.
fn vis_human(vis: &Visibility) -> String {
    match vis {
        Visibility::Embargoed { reveal_at } => format!("embargoed until {}", civil_date(*reveal_at)),
        other => verdict::visibility_token(other),
    }
}

/// The bare visibility *class* — what a sealed path shows when the caller can't
/// read its recipients: `public` / `restricted` / `embargoed`.
fn vis_class(vis: &Visibility) -> &'static str {
    match vis {
        Visibility::Public => "public",
        Visibility::Restricted(_) => "restricted",
        Visibility::Embargoed { .. } => "embargoed",
    }
}

/// `YYYY-MM-DD` (UTC) for a unix timestamp, so an embargo reveal reads as a
/// date. Howard Hinnant's `civil_from_days` (epoch 1970-01-01) — no date crate,
/// keeping the CLI dependency-light (ADR 0005).
fn civil_date(unix_secs: u64) -> String {
    let z = (unix_secs / 86_400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
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
    use crate::workspace::DeltaClass;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

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

    fn delta(class: DeltaClass, path: &str, vis: Visibility) -> PathDelta {
        PathDelta {
            class,
            path: PathBuf::from(path),
            oid: oid(0x3f),
            sealed: false,
            visibility: vis,
            prev_visibility: None,
        }
    }

    #[test]
    fn delta_line_renders_added_modified_deleted_gutters() {
        let added = delta_line(&delta(DeltaClass::Added, "README.md", Visibility::Public));
        let modified = delta_line(&delta(
            DeltaClass::Modified,
            "src/main.rs",
            Visibility::Restricted(vec!["alice".into(), "bob".into()]),
        ));
        let deleted = delta_line(&delta(DeltaClass::Deleted, "docs/old-notes.md", Visibility::Public));
        assert_eq!(added, "  +  README.md              public");
        assert!(modified.starts_with("  M  src/main.rs") && modified.ends_with("restricted=alice,bob"));
        assert!(deleted.starts_with("  -  docs/old-notes.md") && deleted.ends_with("public"));
    }

    #[test]
    fn delta_line_humanizes_an_embargo_to_a_date() {
        // 1799971200 = 2027-01-15 00:00:00 UTC (the #306 sample).
        let line = delta_line(&delta(
            DeltaClass::Added,
            "RELEASE.md",
            Visibility::Embargoed { reveal_at: 1_799_971_200 },
        ));
        assert!(line.ends_with("embargoed until 2027-01-15"), "{line}");
    }

    #[test]
    fn delta_line_shows_a_visibility_transition_inline() {
        let mut d = delta(
            DeltaClass::Modified,
            ".env",
            Visibility::Restricted(vec!["alice".into()]),
        );
        d.prev_visibility = Some(Visibility::Public);
        let line = delta_line(&d);
        assert!(line.ends_with("public → restricted=alice"), "{line}");
    }

    #[test]
    fn delta_line_with_equal_visibility_shows_no_transition() {
        let mut d = delta(DeltaClass::Modified, "a.txt", Visibility::Public);
        d.prev_visibility = Some(Visibility::Public);
        let line = delta_line(&d);
        assert!(line.ends_with("public") && !line.contains('→'), "{line}");
    }

    #[test]
    fn delta_line_seals_the_name_when_the_key_is_not_held() {
        let mut d = delta(
            DeltaClass::Modified,
            "secret/plan.md",
            Visibility::Restricted(vec!["alice".into()]),
        );
        d.sealed = true;
        let line = delta_line(&d);
        // The path name never leaks; the address stands in, class kept, tag added.
        assert!(!line.contains("secret/plan.md"), "{line}");
        assert!(line.contains(&short(&oid(0x3f))) && line.contains('…'), "{line}");
        assert!(line.contains("restricted") && !line.contains("alice"), "{line}");
        assert!(line.ends_with("(sealed — no key)"), "{line}");
    }

    #[test]
    fn civil_date_maps_known_timestamps() {
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(civil_date(1_735_689_600), "2025-01-01");
        assert_eq!(civil_date(1_799_971_200), "2027-01-15");
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
