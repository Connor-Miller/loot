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

use crate::workspace::{
    ConflictSide, ConflictView, DeltaClass, EditReport, HistoryRow, HistoryView, PathDelta,
    WorkingRow,
};
use loot_core::manifest::GrantEntry;
use loot_core::{verdict, MergeOutcome, Oid, Visibility};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

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

/// The human visibility label (`public` / `restricted=a,b` / `embargoed until
/// <date>`) — the shared `vis_human` rendering, exposed for the first-seal
/// summary `loot new` prints (#63, ADR 0038 §1).
pub fn visibility_label(vis: &Visibility) -> String {
    vis_human(vis)
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

/// `YYYY-MM-DD HH:MM:SS UTC` for a unix timestamp — [`civil_date`]'s
/// time-of-day twin, for callers (`grant-status`, #5) that want a grant's
/// `granted_at` at full precision rather than a bare calendar date.
fn civil_datetime(unix_secs: u64) -> String {
    let secs_of_day = unix_secs % 86_400;
    let h = secs_of_day / 3600;
    let m = (secs_of_day % 3600) / 60;
    let s = secs_of_day % 60;
    format!("{} {h:02}:{m:02}:{s:02} UTC", civil_date(unix_secs))
}

/// The human `loot diff --conflict <path>` view (#13): both sides of a
/// conflict, each rendered through the shared #306 [`delta_line`] so the
/// path/visibility/sealed-fallback shape matches `diff` and `status`, followed
/// by the side's decrypted content when the key is held. A sealed side shows
/// only its `delta_line` — the content address stands in for the plaintext it
/// cannot open, which is the #306 key-not-held fallback (and AC "show both
/// OIDs").
pub fn conflict_sides(view: &ConflictView) -> String {
    let mut out = format!("conflict at {}\n", view.path.display());
    for (label, side) in [("ours", &view.ours), ("theirs", &view.theirs)] {
        let _ = write!(out, "\n  {label}:\n{}\n", delta_line(&side_delta(view, side)));
        if let Some(bytes) = &side.content {
            out.push_str(&indented_content(bytes));
        }
    }
    out
}

/// Cast one conflict side as a [`PathDelta`] so it renders through the shared
/// #306 line. A conflict is two competing writes to one path, so each side reads
/// as `Modified`; `prev_visibility` stays `None` — the two sides are
/// alternatives, not a before/after transition.
fn side_delta(view: &ConflictView, side: &ConflictSide) -> PathDelta {
    PathDelta {
        class: DeltaClass::Modified,
        path: view.path.clone(),
        oid: side.oid.clone(),
        // A side the caller can't decrypt has no content — that is the #306
        // sealed case, so the address stands in for the name.
        sealed: side.content.is_none(),
        visibility: side.visibility.clone(),
        prev_visibility: None,
    }
}

/// A held side's content, indented under its label. Valid UTF-8 prints verbatim;
/// binary is summarized rather than dumped as terminal-breaking bytes — this is
/// a human inspection view, not a byte pipe (scripts use `loot conflicts`).
fn indented_content(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.lines().map(|l| format!("    {l}\n")).collect(),
        Err(_) => format!("    ({} bytes of binary content)\n", bytes.len()),
    }
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

/// The `loot grant-status <path>` report (#5): every grantee currently
/// holding a grant for `path`'s content — a sanity check before running
/// `loot maroon`. `entries` is the [`GrantEntry`] set for that path's current
/// oid (`Manifest::grants_for`, caller-resolved so this stays a pure
/// render — no `Workspace` in the test surface); `name_of` resolves a
/// grantor pubkey to a peer name, falling back to its hex form when no
/// registered peer matches (the same contract `render_buoy_human` uses).
/// Delivery method is [`GrantEntry::has_grantor`]'s existing split (ADR
/// 0008/0015): a file-based (tag-1) grant carries no envelope so no verified
/// grantor; a relay-delivered (tag-3) grant does.
pub fn render_grant_status(
    path: &Path,
    entries: &[&GrantEntry],
    name_of: &dyn Fn(&[u8; 32]) -> String,
) -> String {
    let mut out = String::new();
    if entries.is_empty() {
        let _ = writeln!(out, "no grants found for {}", path.display());
        return out;
    }
    let _ = writeln!(out, "grants for {}:", path.display());
    let _ = writeln!(out);
    let _ = writeln!(out, "{:<16} {:<24} {:<6} grantor", "grantee", "granted_at", "via");
    let _ = writeln!(out, "{}", "-".repeat(72));
    let mut sorted: Vec<&&GrantEntry> = entries.iter().collect();
    sorted.sort_by_key(|e| (e.granted_at, e.grantee.clone()));
    for e in sorted {
        let via = if e.has_grantor() { "relay" } else { "file" };
        let grantor = if e.has_grantor() { name_of(&e.grantor_pubkey) } else { "(file)".to_string() };
        let _ = writeln!(
            out,
            "{:<16} {:<24} {:<6} {}",
            e.grantee,
            civil_datetime(e.granted_at),
            via,
            grantor
        );
    }
    out
}

/// The `loot embargo-status <path>` report (#15): one of three states, read
/// straight off `path`'s recorded [`Visibility`] against the clock — the same
/// time gate `sealed::open` enforces (embargo is a property of time, checked
/// before key custody, even for a keyholder). Pure render — `vis`/`now` are
/// caller-resolved (`Workspace::path_history_entry`, `Workspace::now`), same
/// no-`Workspace`-in-the-test-surface shape as `render_grant_status`:
///
/// - `Embargoed { reveal_at }` with `now < reveal_at` — **embargoed until**
///   `reveal_at`, key withheld (ADR 0007: `open` refuses everyone, even the
///   keyholder, until then).
/// - `Embargoed { reveal_at }` with `now >= reveal_at` — **revealed**, the
///   embargo has lapsed.
/// - anything else (`Public`/`Restricted`) — **not embargoed**, plain
///   visibility rules apply.
pub fn render_embargo_status(path: &Path, vis: &Visibility, now: u64) -> String {
    match vis {
        Visibility::Embargoed { reveal_at } if now < *reveal_at => {
            format!(
                "{}: embargoed until {} ({})\n",
                path.display(),
                reveal_at,
                civil_datetime(*reveal_at)
            )
        }
        Visibility::Embargoed { .. } => format!("{}: revealed\n", path.display()),
        _ => format!("{}: not embargoed\n", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn conflict_side(vis: Visibility, content: Option<&[u8]>) -> ConflictSide {
        ConflictSide { oid: oid(0x3f), visibility: vis, content: content.map(<[u8]>::to_vec) }
    }

    #[test]
    fn conflict_sides_prints_both_sides_and_their_content_when_the_key_is_held() {
        let view = ConflictView {
            path: PathBuf::from("a.txt"),
            ours: conflict_side(Visibility::Public, Some(b"home side\n")),
            theirs: conflict_side(
                Visibility::Restricted(vec!["alice".into()]),
                Some(b"feature side\n"),
            ),
        };
        let out = conflict_sides(&view);
        assert!(out.contains("conflict at a.txt"), "{out}");
        assert!(out.contains("ours:") && out.contains("theirs:"), "both sides labeled: {out}");
        // Each side renders the shared #306 delta line (M gutter, path, token).
        assert!(out.contains("  M  a.txt"), "the shared delta line: {out}");
        assert!(out.contains("public") && out.contains("restricted=alice"), "{out}");
        // ...and the decrypted content of both sides is shown, indented.
        assert!(out.contains("    home side") && out.contains("    feature side"), "{out}");
    }

    #[test]
    fn conflict_sides_falls_back_to_the_oid_when_a_side_is_sealed() {
        let view = ConflictView {
            path: PathBuf::from("secret.txt"),
            ours: conflict_side(Visibility::Public, Some(b"readable\n")),
            theirs: conflict_side(Visibility::Restricted(vec!["alice".into()]), None),
        };
        let out = conflict_sides(&view);
        // Held side shows content; sealed side shows the OID + tag, never plaintext.
        assert!(out.contains("readable"), "held side content shown: {out}");
        assert!(out.contains(&short(&oid(0x3f))) && out.contains('…'), "sealed side OID: {out}");
        assert!(out.contains("(sealed — no key)"), "{out}");
        // The class survives; recipients never leak on the sealed side.
        assert!(out.contains("restricted") && !out.contains("alice"), "{out}");
    }

    #[test]
    fn conflict_sides_summarizes_binary_content_rather_than_dumping_bytes() {
        let view = ConflictView {
            path: PathBuf::from("blob.bin"),
            ours: conflict_side(Visibility::Public, Some(&[0xff, 0xfe, 0x00, 0x01])),
            theirs: conflict_side(Visibility::Public, Some(b"text\n")),
        };
        let out = conflict_sides(&view);
        assert!(out.contains("4 bytes of binary content"), "{out}");
        assert!(out.contains("    text"), "the text side still prints: {out}");
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

    #[test]
    fn civil_datetime_adds_time_of_day_to_the_civil_date() {
        // 1799971200 = 2027-01-15 00:00:00 UTC (the #306 sample); +3661s = 01:01:01.
        assert_eq!(civil_datetime(1_799_971_200), "2027-01-15 00:00:00 UTC");
        assert_eq!(civil_datetime(1_799_971_200 + 3_661), "2027-01-15 01:01:01 UTC");
    }

    fn grant(grantee: &str, grantor_pk: Option<u8>, granted_at: u64) -> GrantEntry {
        let grantor_pubkey = match grantor_pk {
            Some(b) => [b; 32],
            None => loot_core::manifest::UNKNOWN_PUBKEY,
        };
        GrantEntry {
            oid: oid(0x3f),
            grantee: grantee.into(),
            grantee_pubkey: [0xee; 32],
            grantor_pubkey,
            granted_at,
            expires_at: None,
        }
    }

    /// A peer-registry fixture: known pubkeys resolve to a name, anything else
    /// falls back to its hex form — the same shape `resolve_pubkey_name` uses
    /// in `main.rs`, reproduced here so `render_grant_status` stays testable
    /// without a real `Workspace`/`PeerRegistry`.
    fn peer_names(known: &'static [(u8, &'static str)]) -> impl Fn(&[u8; 32]) -> String {
        move |pk: &[u8; 32]| {
            known
                .iter()
                .find(|(b, _)| pk[0] == *b)
                .map(|(_, name)| name.to_string())
                .unwrap_or_else(|| format!("{:02x}…", pk[0]))
        }
    }

    #[test]
    fn grant_status_reports_no_grants_found_when_empty() {
        let out = render_grant_status(&PathBuf::from("secret.env"), &[], &peer_names(&[]));
        assert_eq!(out, "no grants found for secret.env\n");
    }

    #[test]
    fn grant_status_lists_every_grantee_with_delivery_method_and_grantor_name() {
        let alice = grant("alice", None, 1_799_971_200); // file-based (tag-1)
        let bob = grant("bob", Some(0xbb), 1_799_971_200 + 60); // relay-delivered (tag-3)
        let entries: Vec<&GrantEntry> = vec![&alice, &bob];
        let out = render_grant_status(
            &PathBuf::from("secret.env"),
            &entries,
            &peer_names(&[(0xbb, "carol")]),
        );

        assert!(out.contains("grants for secret.env:"), "{out}");
        // Multi-grantee: both rows present.
        let alice_line = out.lines().find(|l| l.starts_with("alice")).expect(&out);
        let bob_line = out.lines().find(|l| l.starts_with("bob")).expect(&out);
        // File-based grant: "file" delivery, no envelope grantor to resolve.
        assert!(alice_line.contains("file") && alice_line.contains("(file)"), "{alice_line}");
        assert!(alice_line.contains("2027-01-15"), "{alice_line}");
        // Relay-delivered grant: "relay" delivery, grantor resolved to its peer name.
        assert!(bob_line.contains("relay") && bob_line.contains("carol"), "{bob_line}");
    }

    #[test]
    fn grant_status_falls_back_to_pubkey_when_grantor_is_an_unknown_peer() {
        let stranger = grant("mallory", Some(0xcc), 1_799_971_200);
        let entries: Vec<&GrantEntry> = vec![&stranger];
        // No peer named for 0xcc — the resolver's fallback path.
        let out = render_grant_status(&PathBuf::from("secret.env"), &entries, &peer_names(&[]));

        assert!(out.contains("relay"), "{out}");
        assert!(out.contains("cc…"), "unresolved grantor falls back to its pubkey: {out}");
        assert!(!out.contains("(file)"), "a relay grant is never labelled file-based: {out}");
    }

    // --- `loot embargo-status <path>` (#15) ---

    #[test]
    fn embargo_status_reports_embargoed_until_before_reveal() {
        let vis = Visibility::Embargoed { reveal_at: 1_799_971_200 };
        let out = render_embargo_status(&PathBuf::from("plans.md"), &vis, 1_799_971_199);
        assert_eq!(out, "plans.md: embargoed until 1799971200 (2027-01-15 00:00:00 UTC)\n");
    }

    #[test]
    fn embargo_status_reports_embargoed_at_the_exact_reveal_instant() {
        // `now == reveal_at` is the boundary `sealed::open` treats as revealed
        // (its gate is `now < reveal_at`, not `<=`) — pin the same edge here.
        let vis = Visibility::Embargoed { reveal_at: 1_799_971_200 };
        let out = render_embargo_status(&PathBuf::from("plans.md"), &vis, 1_799_971_200);
        assert_eq!(out, "plans.md: revealed\n");
    }

    #[test]
    fn embargo_status_reports_revealed_once_reveal_at_has_passed() {
        let vis = Visibility::Embargoed { reveal_at: 100 };
        let out = render_embargo_status(&PathBuf::from("plans.md"), &vis, 101);
        assert_eq!(out, "plans.md: revealed\n");
    }

    #[test]
    fn embargo_status_reports_not_embargoed_for_public() {
        let out = render_embargo_status(&PathBuf::from("readme.md"), &Visibility::Public, 0);
        assert_eq!(out, "readme.md: not embargoed\n");
    }

    #[test]
    fn embargo_status_reports_not_embargoed_for_restricted() {
        let vis = Visibility::Restricted(vec!["alice".into()]);
        let out = render_embargo_status(&PathBuf::from("secret.env"), &vis, 0);
        assert_eq!(out, "secret.env: not embargoed\n");
    }
}
