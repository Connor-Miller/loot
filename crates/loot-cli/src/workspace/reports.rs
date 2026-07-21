//! CLI report DTOs (candidate 5: DTOs out of workspace.rs). The plain-data
//! values Workspace verbs return for the CLI to render — no behaviour, just the
//! shape of an outcome. Gathered here so a verb-output change edits this small
//! module instead of the 8,000-line workspace.rs, and re-exported from
//! `workspace` so `workspace::EditReport` etc. stay stable for main.rs and
//! render.rs. `super::*` brings the shared types (Oid, PathBuf, Visibility,
//! MergeOutcome, …) into scope.

use super::*;

/// The live working-change row `status`/`log` render (ADR 0030). `change_id` is
/// the durable handle (`None` only for a keyless/legacy working change);
/// `version` is the live, non-durable content fingerprint; `empty` is true when
/// the working tree has no delta over the tip, so callers show `—` for the
/// version and omit the per-path listing.
pub struct WorkingRow {
    pub change_id: Option<[u8; 16]>,
    pub version: Oid,
    pub message: String,
    pub entries: Vec<(PathBuf, Visibility)>,
    pub empty: bool,
}

impl WorkingRow {
    /// The working version as full hex — the form the `wip` ledger stores, so
    /// the loot-first review-currency guard (ADR 0033) compares like with like
    /// without reaching into the `Oid` newtype at the call site.
    pub fn version_hex(&self) -> String {
        loot_core::hex::encode(&self.version.0)
    }
}

/// What `loot edit` did, for CLI reporting (ADR 0032).
#[derive(Debug)]
pub struct EditReport {
    /// The durable handle the reopened change keeps.
    pub change_id: [u8; 16],
    /// The finalized version that was reopened — superseded when the amend
    /// finalizes (`loot new`).
    pub superseded: Oid,
}

/// The delta class of one path across two trees: added, modified, or deleted
/// (#306). `#7`'s first-change-in-repo case renders every path `Added`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaClass {
    Added,
    Modified,
    Deleted,
}

impl DeltaClass {
    /// The frozen gutter char (#306): `+` added · `M` modified · `-` deleted.
    pub fn gutter(self) -> char {
        match self {
            DeltaClass::Added => '+',
            DeltaClass::Modified => 'M',
            DeltaClass::Deleted => '-',
        }
    }
}

/// One path's computed delta — the value [`diff`](Workspace::diff) produces and
/// [`crate::render::delta_line`] renders (#1/#306). `path` and `oid` are the
/// same tree entry's two faces: the name and its content address. When `sealed`
/// the caller lacks the key, so the renderer shows the address in place of the
/// name (which they cannot read) and degrades the token to the visibility
/// *class*. `prev_visibility` is `Some` only when the visibility differs across
/// the two sides (a transition) — the demotion/mis-seal signal #63 builds on;
/// it is always `None` for `#7` (a working change has one side).
pub struct PathDelta {
    pub class: DeltaClass,
    pub path: PathBuf,
    pub oid: Oid,
    pub sealed: bool,
    pub visibility: Visibility,
    pub prev_visibility: Option<Visibility>,
}

/// One side of a conflict — the value [`conflict_at`](Graph::conflict_at)
/// produces and [`crate::render::conflict_sides`] renders (#13). `oid` is the
/// side's content address and `visibility` its stored class. `content` is `Some`
/// only when the ambient identity holds the key; `None` means the side is sealed
/// to this caller, and the renderer shows the OID in place of plaintext — the
/// same key-not-held fallback #1 uses (#306). Sealed is thus exactly
/// `content.is_none()`, so it is derived at render time rather than stored.
#[derive(Debug)]
pub struct ConflictSide {
    pub oid: Oid,
    pub visibility: Visibility,
    pub content: Option<Vec<u8>>,
}

/// A conflict at one path, both sides packaged for rendering (#13). `ours` is
/// the side kept on disk after the conflicted merge; `theirs` the incoming side
/// preserved in the recorded conflict.
#[derive(Debug)]
pub struct ConflictView {
    pub path: PathBuf,
    pub ours: ConflictSide,
    pub theirs: ConflictSide,
}

/// What `loot adopt <version>` did, for CLI reporting (#244).
#[derive(Debug)]
pub struct AdoptReport {
    /// The landed change the dock now sits on.
    pub target: Oid,
    /// The competing heads (the discarded divergent line) abandoned to settle.
    pub abandoned: Vec<Oid>,
    /// Whether a live working change or uncaptured disk edits were dropped
    /// (`--discard-wip`).
    pub discarded_wip: bool,
    /// The dock was already on `target` with a clean tree — a no-op with a note.
    pub already_there: bool,
}

/// The outcome of a no-arg `loot adopt` (harbor catch-up merge, ADR 0034).
#[derive(Debug)]
pub struct AdoptCatchupReport {
    /// The harbor's landed main head this dock caught up to.
    pub harbor: Oid,
    /// The dock was already at or ahead of the harbor head — a no-op with a note.
    pub already_current: bool,
    /// The local line was folded in (a merge or a fast-forward advanced the tip).
    pub merged: bool,
    /// Per-path merge outcomes when a reconcile ran (empty on a fast-forward).
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
}

/// The outcome of a pull (#219). Carries the folded per-path merge outcomes,
/// plus the working change id when capture-first *deferred* convergence — a
/// dirty tree was captured and the working-change guard left the freshly
/// ingested heads flat for this pass. `deferred: None` is the ordinary
/// converged pull; `Some(id)` is the CLI's cue to print the "finalize then
/// re-run" note (ADR 0030 amendment).
#[derive(Debug)]
pub struct PullReport {
    /// The folded per-path merge outcomes, for rendering the verdict rows.
    pub outcomes: BTreeMap<PathBuf, MergeOutcome>,
    /// The captured working change id when converge was deferred, else `None`.
    pub deferred: Option<Oid>,
}

/// What a completed `undo`/`op restore` did, for CLI reporting (ADR 0031).
#[derive(Debug)]
pub struct StepReport {
    /// Its human description (e.g. `undid op 7 (new)`).
    pub description: String,
    /// The 1-based ordinal of the op whose view is now current.
    pub restored_to: u32,
    /// The change-graph heads the view now sits on.
    pub heads: Vec<Oid>,
    /// The working change now in progress, if any.
    pub working: Option<Oid>,
}

/// What `loot burn` destroyed (ADR 0038, #344), for the CLI to report.
#[derive(Debug)]
pub struct BurnReport {
    /// The honesty tier the burn achieved (never-pushed ⇒ complete; pushed ⇒
    /// best-effort with a purge event).
    pub tier: loot_core::BurnTier,
    /// The destroyed `(oid, path)` pairs.
    pub burned: Vec<(Oid, PathBuf)>,
    /// Referencing changes that were projected into the git mirror, as
    /// `(version-id, git-sha)` — non-empty means the git-side guidance applies.
    pub projected: Vec<(Oid, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delta_class_gutter_is_the_frozen_306_mapping() {
        assert_eq!(DeltaClass::Added.gutter(), '+');
        assert_eq!(DeltaClass::Modified.gutter(), 'M');
        assert_eq!(DeltaClass::Deleted.gutter(), '-');
    }

    #[test]
    fn working_row_version_hex_is_full_hex_of_the_version() {
        let row = WorkingRow {
            change_id: None,
            version: Oid([0xab; 32]),
            message: String::new(),
            entries: Vec::new(),
            empty: true,
        };
        let hex = row.version_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c == 'a' || c == 'b'));
    }
}
