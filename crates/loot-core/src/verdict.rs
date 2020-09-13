//! Machine-facing verdict output for the reconciliation verbs (CA3, ADR 0023).
//!
//! The converge classifier already computes a per-path [`MergeOutcome`]; the CLI
//! historically threw it away at the `println!` boundary, forcing an agent to
//! scrape prose to learn whether to re-drive or escalate. This module lifts that
//! outcome into one small serializable value — [`PathVerdict`] — and offers two
//! encoders over it, with no divergent logic between them:
//!
//!   - [`porcelain`] — the default machine format: one path per line, a leading
//!     status char, tab-separated columns, no repeated keys. Token-lean and
//!     human-glanceable (git's `--porcelain` precedent).
//!   - [`json`] — the opt-in fallback for the one case porcelain handles poorly:
//!     a path containing a tab or newline, where JSON escaping is clean.
//!
//! Scope (CA3): the base/incoming content addresses are carried only where the
//! outcome already holds them — a [`MergeOutcome::Conflict`] (`ours`/`theirs`).
//! Every other row renders `-` in those columns. Widening them to every row
//! would mean threading both trees through `Repo::apply`; per ADR 0023 the
//! column order and status chars are a **frozen contract** once agents parse
//! them, so that is a deliberate later (and breaking) change.
//!
//! `status` is a different animal: it reports the working change, not a merge,
//! so it never runs the classifier. Its machine shape lives here too
//! ([`status_porcelain`] / [`status_json`]) but has its own leading marker and
//! its own columns — a distinct, per-verb frozen contract.

use crate::{format, hex, MergeOutcome, Oid, Visibility};
use std::path::PathBuf;

/// Contract version for the machine output, versioned alongside the artifact
/// format major (ADR 0019 / S1) so the porcelain columns and status chars can
/// evolve safely. Bump only on a breaking change to a column or status char.
pub const VERDICT_CONTRACT: u8 = format::FORMAT_MAJOR;

/// Placeholder for an absent content address in porcelain columns.
const NONE_ADDR: &str = "-";

/// Leading marker for a `status` working-change line — distinct from the merge
/// status chars below, because a working-change entry is not a merge outcome.
pub const WORKING_MARK: char = '~';

/// Leading marker for the `status` change-identity header line (ADR 0029/0030):
/// carries the working change's durable `change_id` and its live, non-durable
/// version id, ahead of the `~` per-path rows. Distinct from `~` so a parser
/// keys the header and the path rows apart; both are a frozen contract.
pub const CHANGE_MARK: char = '@';

/// One reconciliation verdict: the classifier's outcome for a single path.
/// The base/incoming addresses are derived from the outcome (present only for a
/// `Conflict`), so this stays a thin lift of the value the classifier computes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathVerdict {
    pub path: PathBuf,
    pub outcome: MergeOutcome,
}

impl PathVerdict {
    pub fn new(path: impl Into<PathBuf>, outcome: MergeOutcome) -> Self {
        Self { path: path.into(), outcome }
    }

    /// The frozen status char (ADR 0023).
    pub fn status_char(&self) -> char {
        status_char(&self.outcome)
    }

    /// (base, incoming) content addresses — present only for a `Conflict`
    /// (its `ours`/`theirs`), `None` otherwise (see the module-level scope note).
    pub fn addrs(&self) -> (Option<Oid>, Option<Oid>) {
        match &self.outcome {
            MergeOutcome::Conflict { ours, theirs } => (Some(ours.clone()), Some(theirs.clone())),
            _ => (None, None),
        }
    }
}

/// The frozen per-path status char (ADR 0023): `=` converged, `M` merged,
/// `C` conflict, `R` relayed.
pub fn status_char(o: &MergeOutcome) -> char {
    match o {
        MergeOutcome::Converged => '=',
        MergeOutcome::Merged => 'M',
        MergeOutcome::Conflict { .. } => 'C',
        MergeOutcome::RelayedUnmerged => 'R',
    }
}

/// The human/porcelain rendering of a visibility policy: `public`,
/// `restricted=a,b`, or `embargoed@<ts>`. One home for a token both the human
/// `status` and its machine form share.
pub fn visibility_token(vis: &Visibility) -> String {
    match vis {
        Visibility::Public => "public".to_string(),
        Visibility::Restricted(ids) => format!("restricted={}", ids.join(",")),
        Visibility::Embargoed { reveal_at } => format!("embargoed@{reveal_at}"),
    }
}

fn addr_col(oid: Option<Oid>) -> String {
    oid.map(|o| hex::encode(&o.0)).unwrap_or_else(|| NONE_ADDR.to_string())
}

// --- reconciliation verdict encoders (apply / conflicts / dock merge) ---

/// Porcelain: `status \t path \t base \t incoming`, one row per verdict.
/// Rows are emitted in the order given (callers pass a sorted `BTreeMap`
/// iteration, so output is deterministic). Empty input yields the empty string.
pub fn porcelain(verdicts: &[PathVerdict]) -> String {
    let mut out = String::new();
    for v in verdicts {
        let (base, incoming) = v.addrs();
        out.push(v.status_char());
        out.push('\t');
        out.push_str(&v.path.to_string_lossy());
        out.push('\t');
        out.push_str(&addr_col(base));
        out.push('\t');
        out.push_str(&addr_col(incoming));
        out.push('\n');
    }
    out
}

/// JSON: `{"contract":<n>,"verdicts":[{status,path,base,incoming},...]}`.
/// The opt-in fallback where a path's bytes (tab/newline) would corrupt
/// porcelain columns; paths are escaped, so this is always lossless.
pub fn json(verdicts: &[PathVerdict]) -> String {
    let mut s = String::new();
    s.push_str("{\"contract\":");
    s.push_str(&VERDICT_CONTRACT.to_string());
    s.push_str(",\"verdicts\":[");
    for (i, v) in verdicts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let (base, incoming) = v.addrs();
        s.push_str("{\"status\":\"");
        s.push(v.status_char());
        s.push_str("\",\"path\":");
        json_string(&v.path.to_string_lossy(), &mut s);
        s.push_str(",\"base\":");
        json_opt_addr(base, &mut s);
        s.push_str(",\"incoming\":");
        json_opt_addr(incoming, &mut s);
        s.push('}');
    }
    s.push_str("]}");
    s
}

// --- status encoders (the working change — a distinct shape) ---

/// The 16-byte durable change id as full lowercase hex, or `-` when absent
/// (a keyless/legacy working change). Machine output uses hex, not the human
/// reverse-hex letters — a parser wants the raw bytes.
fn change_col(change_id: Option<[u8; 16]>) -> String {
    change_id.map(|c| hex::encode(&c)).unwrap_or_else(|| NONE_ADDR.to_string())
}

/// Porcelain for `status`: a leading `@ \t change \t version` header row (the
/// working change's durable change id + its live, non-durable version id, ADR
/// 0029/0030), then `~ \t path \t visibility`, one working-change entry per
/// line. Its own frozen shape — `@`/`~` mark the two row kinds, `change` is hex
/// (`-` if none), `version` is hex (`-` when the change is empty), and a `~`
/// row's third column is a visibility token, not an OID.
///
/// **Limitation:** path bytes are written verbatim. A path containing a tab or
/// newline corrupts the column structure — use [`status_json`] when paths may
/// contain control characters.
pub fn status_porcelain(
    change_id: Option<[u8; 16]>,
    version: Option<&Oid>,
    entries: &[(PathBuf, Visibility)],
) -> String {
    let mut out = String::new();
    out.push(CHANGE_MARK);
    out.push('\t');
    out.push_str(&change_col(change_id));
    out.push('\t');
    out.push_str(&addr_col(version.cloned()));
    out.push('\n');
    for (path, vis) in entries {
        out.push(WORKING_MARK);
        out.push('\t');
        out.push_str(&path.to_string_lossy());
        out.push('\t');
        out.push_str(&visibility_token(vis));
        out.push('\n');
    }
    out
}

/// JSON for `status`: `{"contract":<n>,"change":<hex|null>,"version":<hex|null>,
/// "working":[{path,visibility},...]}`. `change` is the durable change id;
/// `version` is the live, non-durable version id (`null` when the change is
/// empty, ADR 0030).
pub fn status_json(
    change_id: Option<[u8; 16]>,
    version: Option<&Oid>,
    entries: &[(PathBuf, Visibility)],
) -> String {
    let mut s = String::new();
    s.push_str("{\"contract\":");
    s.push_str(&VERDICT_CONTRACT.to_string());
    s.push_str(",\"change\":");
    match change_id {
        Some(c) => json_string(&hex::encode(&c), &mut s),
        None => s.push_str("null"),
    }
    s.push_str(",\"version\":");
    json_opt_addr(version.cloned(), &mut s);
    s.push_str(",\"working\":[");
    for (i, (path, vis)) in entries.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"path\":");
        json_string(&path.to_string_lossy(), &mut s);
        s.push_str(",\"visibility\":");
        json_string(&visibility_token(vis), &mut s);
        s.push('}');
    }
    s.push_str("]}");
    s
}

// --- buoy encoders (the resolver — a distinct, per-verb frozen shape) ---

/// The buoy resolver's outcome, lifted to a serializable value so its frozen
/// machine contract (ADR 0025) has one tested encoder home beside the
/// reconciliation and status shapes, sharing the escaping and contract-version
/// plumbing. The *shape* is ADR 0025's and deliberately not the merge table:
/// `B`/`A` rows, exit codes 0/2/3/1 carried by the CLI. Human rendering stays
/// with the CLI (it needs the peer registry for attester names).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuoyVerdict {
    /// Exactly one maximal candidate — the buoy.
    Resolved { role: String, change: Oid, attesters: Vec<[u8; 32]> },
    /// More than one maximal candidate (concurrent attested changes).
    Ambiguous { role: String, candidates: Vec<(Oid, Vec<[u8; 32]>)> },
    /// No candidate for the role.
    None { role: String },
}

impl BuoyVerdict {
    /// Porcelain (ADR 0025, frozen): `B \t change-id-hex \t role` when resolved,
    /// one `A \t change-id-hex \t role` row per candidate when ambiguous, and
    /// **no rows** when there is no buoy — the exit code carries that outcome.
    pub fn porcelain(&self) -> String {
        match self {
            BuoyVerdict::Resolved { role, change, .. } => {
                format!("B\t{}\t{role}\n", hex::encode(&change.0))
            }
            BuoyVerdict::Ambiguous { role, candidates } => {
                let mut out = String::new();
                for (change, _) in candidates {
                    out.push_str(&format!("A\t{}\t{role}\n", hex::encode(&change.0)));
                }
                out
            }
            BuoyVerdict::None { .. } => String::new(),
        }
    }

    /// JSON (ADR 0025, frozen): `{"contract":<n>,"role":...,"status":"resolved",
    /// "buoy":"<hex>","attesters":[...]}` / `"status":"ambiguous","candidates":
    /// [{"change":"<hex>","attesters":[...]},...]` / `"status":"none"`.
    ///
    /// Escaping note (ratified with R4, #180): roles now escape through the
    /// shared [`json_string`], which handles control characters the pre-R4
    /// inline encoder passed through raw — those bytes were **invalid JSON**,
    /// so no conforming parser depended on them; every role that previously
    /// produced valid JSON serializes byte-identically.
    pub fn json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"contract\":");
        s.push_str(&VERDICT_CONTRACT.to_string());
        s.push_str(",\"role\":");
        match self {
            BuoyVerdict::Resolved { role, change, attesters } => {
                json_string(role, &mut s);
                s.push_str(",\"status\":\"resolved\",\"buoy\":");
                json_string(&hex::encode(&change.0), &mut s);
                s.push_str(",\"attesters\":[");
                json_attesters(attesters, &mut s);
                s.push_str("]}");
            }
            BuoyVerdict::Ambiguous { role, candidates } => {
                json_string(role, &mut s);
                s.push_str(",\"status\":\"ambiguous\",\"candidates\":[");
                for (i, (change, attesters)) in candidates.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str("{\"change\":");
                    json_string(&hex::encode(&change.0), &mut s);
                    s.push_str(",\"attesters\":[");
                    json_attesters(attesters, &mut s);
                    s.push_str("]}");
                }
                s.push_str("]}");
            }
            BuoyVerdict::None { role } => {
                json_string(role, &mut s);
                s.push_str(",\"status\":\"none\"}");
            }
        }
        s
    }
}

fn json_attesters(attesters: &[[u8; 32]], out: &mut String) {
    for (i, pk) in attesters.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_string(&hex::encode(pk), out);
    }
}

// --- minimal JSON string encoding (dependency-free; loot-core carries no serde) ---

fn json_opt_addr(oid: Option<Oid>, out: &mut String) {
    match oid {
        Some(o) => json_string(&hex::encode(&o.0), out),
        None => out.push_str("null"),
    }
}

/// Append `s` as a quoted, escaped JSON string. Handles the RFC 8259 required
/// escapes plus any other control char via `\u00XX` — so a path containing a
/// tab or newline round-trips cleanly (the whole reason `--json` exists).
fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn oid(byte: u8) -> Oid {
        Oid([byte; 32])
    }

    #[test]
    fn status_chars_are_the_frozen_contract() {
        assert_eq!(status_char(&MergeOutcome::Converged), '=');
        assert_eq!(status_char(&MergeOutcome::Merged), 'M');
        assert_eq!(status_char(&MergeOutcome::RelayedUnmerged), 'R');
        assert_eq!(
            status_char(&MergeOutcome::Conflict { ours: oid(0), theirs: oid(1) }),
            'C'
        );
    }

    #[test]
    fn porcelain_columns_and_scoped_addrs() {
        let verdicts = vec![
            PathVerdict::new("README.md", MergeOutcome::Converged),
            PathVerdict::new("src/util.rs", MergeOutcome::Merged),
            PathVerdict::new("relayed.bin", MergeOutcome::RelayedUnmerged),
            PathVerdict::new(
                "src/auth.rs",
                MergeOutcome::Conflict { ours: oid(0xab), theirs: oid(0xcd) },
            ),
        ];
        let out = porcelain(&verdicts);
        let lines: Vec<&str> = out.lines().collect();
        // Non-conflict rows carry `-` in both address columns (CA3 scope).
        assert_eq!(lines[0], "=\tREADME.md\t-\t-");
        assert_eq!(lines[1], "M\tsrc/util.rs\t-\t-");
        assert_eq!(lines[2], "R\trelayed.bin\t-\t-");
        // A conflict carries ours -> base, theirs -> incoming (full hex).
        assert_eq!(
            lines[3],
            format!("C\tsrc/auth.rs\t{}\t{}", hex::encode(&[0xab; 32]), hex::encode(&[0xcd; 32]))
        );
        // Exactly four tab-separated columns per row.
        for line in &lines {
            assert_eq!(line.split('\t').count(), 4);
        }
    }

    #[test]
    fn json_escapes_paths_with_tab_or_newline() {
        let verdicts = vec![PathVerdict::new(
            PathBuf::from("weird\tname\nfile.rs"),
            MergeOutcome::Converged,
        )];
        let out = json(&verdicts);
        assert!(out.contains("\\t"), "tab escaped: {out}");
        assert!(out.contains("\\n"), "newline escaped: {out}");
        // No raw control byte leaks into the JSON.
        assert!(!out.contains('\t'));
        assert!(!out.contains('\n'));
        assert!(out.starts_with(&format!("{{\"contract\":{VERDICT_CONTRACT},")));
    }

    #[test]
    fn porcelain_does_not_escape_tabs_columns_break_for_adversarial_paths() {
        // porcelain writes path bytes verbatim; a tab in the path overflows into
        // the address columns. This is the known limitation documented in
        // status_porcelain's doc comment — agents MUST use --json for such paths.
        let verdicts = vec![PathVerdict::new(
            PathBuf::from("weird\tname"),
            MergeOutcome::Converged,
        )];
        let out = porcelain(&verdicts);
        let line = out.lines().next().unwrap();
        // Five tab-separated tokens instead of four confirms corruption.
        assert_ne!(line.split('\t').count(), 4, "path tab corrupts column count: {line}");
    }

    #[test]
    fn json_carries_conflict_addrs_and_null_elsewhere() {
        let verdicts = vec![
            PathVerdict::new("a", MergeOutcome::Converged),
            PathVerdict::new("b", MergeOutcome::Conflict { ours: oid(1), theirs: oid(2) }),
        ];
        let out = json(&verdicts);
        assert!(out.contains("\"base\":null"), "converged has null base: {out}");
        assert!(
            out.contains(&format!("\"incoming\":\"{}\"", hex::encode(&[2u8; 32]))),
            "conflict carries incoming: {out}"
        );
    }

    #[test]
    fn empty_input_is_empty_output() {
        assert_eq!(porcelain(&[]), "");
        assert_eq!(json(&[]), format!("{{\"contract\":{VERDICT_CONTRACT},\"verdicts\":[]}}"));
        // status always emits the `@` change header, even with no path rows; an
        // absent change id and version render `-`.
        assert_eq!(status_porcelain(None, None, &[]), "@\t-\t-\n");
        assert_eq!(
            status_json(None, None, &[]),
            format!("{{\"contract\":{VERDICT_CONTRACT},\"change\":null,\"version\":null,\"working\":[]}}")
        );
    }

    #[test]
    fn status_has_its_own_shape() {
        let entries = vec![
            (PathBuf::from("README.md"), Visibility::Public),
            (PathBuf::from(".env"), Visibility::Restricted(vec!["alice".into(), "bob".into()])),
            (PathBuf::from("fix.patch"), Visibility::Embargoed { reveal_at: 42 }),
        ];
        let out = status_porcelain(Some([0xAB; 16]), Some(&oid(0x3f)), &entries);
        let lines: Vec<&str> = out.lines().collect();
        // The `@` header carries the change id (hex) and live version id (hex).
        assert_eq!(lines[0], format!("@\t{}\t{}", hex::encode(&[0xAB; 16]), hex::encode(&[0x3f; 32])));
        assert_eq!(lines[1], "~\tREADME.md\tpublic");
        assert_eq!(lines[2], "~\t.env\trestricted=alice,bob");
        assert_eq!(lines[3], "~\tfix.patch\tembargoed@42");
    }

    #[test]
    fn status_json_escapes_and_tags_contract() {
        let entries = vec![(PathBuf::from("a\tb"), Visibility::Public)];
        let out = status_json(Some([0xAB; 16]), Some(&oid(0x3f)), &entries);
        assert!(out.contains("\\t"), "path tab escaped: {out}");
        assert!(out.contains(&format!("\"contract\":{VERDICT_CONTRACT}")));
        assert!(out.contains("\"visibility\":\"public\""));
        assert!(out.contains(&format!("\"change\":\"{}\"", hex::encode(&[0xAB; 16]))));
        assert!(out.contains(&format!("\"version\":\"{}\"", hex::encode(&[0x3f; 32]))));
    }

    #[test]
    fn buoy_porcelain_rows_are_the_frozen_contract() {
        // ADR 0025: `B`/`A` rows, tab-separated, change id as full hex; no rows
        // for `None` (the exit code carries that outcome).
        let resolved = BuoyVerdict::Resolved {
            role: "reviewed".into(),
            change: oid(0xab),
            attesters: vec![[1; 32]],
        };
        assert_eq!(resolved.porcelain(), format!("B\t{}\treviewed\n", hex::encode(&[0xab; 32])));

        let ambiguous = BuoyVerdict::Ambiguous {
            role: "base".into(),
            candidates: vec![(oid(1), vec![[1; 32]]), (oid(2), vec![[2; 32]])],
        };
        assert_eq!(
            ambiguous.porcelain(),
            format!("A\t{}\tbase\nA\t{}\tbase\n", hex::encode(&[1u8; 32]), hex::encode(&[2u8; 32]))
        );

        assert_eq!(BuoyVerdict::None { role: "reviewed".into() }.porcelain(), "");
    }

    #[test]
    fn buoy_json_shapes_and_contract_tag() {
        let resolved = BuoyVerdict::Resolved {
            role: "reviewed".into(),
            change: oid(0xab),
            attesters: vec![[1; 32], [2; 32]],
        };
        assert_eq!(
            resolved.json(),
            format!(
                "{{\"contract\":{VERDICT_CONTRACT},\"role\":\"reviewed\",\"status\":\"resolved\",\"buoy\":\"{}\",\"attesters\":[\"{}\",\"{}\"]}}",
                hex::encode(&[0xab; 32]),
                hex::encode(&[1u8; 32]),
                hex::encode(&[2u8; 32])
            )
        );

        let ambiguous = BuoyVerdict::Ambiguous {
            role: "base".into(),
            candidates: vec![(oid(1), vec![[1; 32]])],
        };
        assert_eq!(
            ambiguous.json(),
            format!(
                "{{\"contract\":{VERDICT_CONTRACT},\"role\":\"base\",\"status\":\"ambiguous\",\"candidates\":[{{\"change\":\"{}\",\"attesters\":[\"{}\"]}}]}}",
                hex::encode(&[1u8; 32]),
                hex::encode(&[1u8; 32])
            )
        );

        assert_eq!(
            BuoyVerdict::None { role: "reviewed".into() }.json(),
            format!("{{\"contract\":{VERDICT_CONTRACT},\"role\":\"reviewed\",\"status\":\"none\"}}")
        );
    }

    #[test]
    fn buoy_json_escapes_adversarial_roles() {
        // Roles are free-form Strings (ADR 0025); quotes and control chars must
        // not corrupt the JSON envelope.
        let v = BuoyVerdict::None { role: "re\"view\ned".into() };
        let j = v.json();
        assert!(j.contains("re\\\"view\\ned"), "escaped role: {j}");
        assert!(!j.contains('\n'), "no raw control bytes: {j}");
    }

    #[test]
    fn status_empty_change_has_null_version() {
        // An empty working change (no delta) renders `-`/null for the version.
        let out = status_porcelain(Some([0xAB; 16]), None, &[]);
        assert_eq!(out, format!("@\t{}\t-\n", hex::encode(&[0xAB; 16])));
        let j = status_json(Some([0xAB; 16]), None, &[]);
        assert!(j.contains("\"version\":null"), "empty version is null: {j}");
    }
}
