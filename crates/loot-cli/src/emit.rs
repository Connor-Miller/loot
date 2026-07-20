//! One rendering seam for the Verdict output contract (#321, ADR 0023).
//!
//! Before this module, the contract was split three ways: `loot_core::verdict`
//! held the porcelain/json encoders, `render.rs` held the human text, and
//! `main.rs` held 11 hand-written `match fmt { Human/Porcelain/Json }` blocks
//! that wired the two together — one duplicated three-way branch per
//! machine-output verb, and neither formatter file ever saw the format
//! selector. Adding a verb meant touching three places and re-deriving the
//! wiring by hand each time.
//!
//! This module *is* that wiring, lifted to one place: each verb builds a
//! small **shape** — the data its machine encoders need (verbatim from
//! `loot_core::verdict`) plus a `human` field already rendered to the verb's
//! exact prose — and calls [`Emit::render`] once. `main.rs`'s `cmd_*`
//! handlers hold zero `match fmt` blocks as a result; the three-way branch
//! lives here, exactly once per shape, instead of once per verb.
//!
//! Byte-identical is the whole point (ADR 0023, `format::FORMAT_MAJOR` ADR
//! 0019 — see `loot_core::verdict`'s module doc): every shape's `render`
//! reproduces its verb's pre-#321 print sequence exactly. `Porcelain` prints
//! the encoder's string as-is (already newline-terminated per row, or empty);
//! `Json` appends the one trailing newline `println!` used to add; `Human` is
//! the verb's own prose, pre-built into a `String` the same way `render.rs`
//! already builds its human text (`write!`/`writeln!`) — proven
//! byte-identical against the pre-refactor code by the black-box
//! characterization tests in `tests/emit_snapshot.rs`.
//!
//! A shape never invents a rendering the verb didn't already have — CA3 froze
//! the machine columns and status chars per verb (`loot_core::verdict`'s
//! docs); this module only relocates *dispatch*, never widens a contract.
//!
//! Two verbs build their `human` field lazily, gated on `fmt == Human`,
//! rather than always: `status`'s human text alone re-reads the working tree
//! (`Workspace::working_delta`, a disk I/O the porcelain/json branches never
//! paid for pre-#321), so `cmd_status` still decides *whether* to build that
//! field before calling `render`. That single `if` is not a "match on
//! OutFmt" in the sense this ticket removes — it decides whether to compute a
//! field, never how to print one, and every other shape's `human` field is
//! cheap pure formatting built unconditionally.

use loot_core::verdict::{self, BuoyVerdict, LaneRow};
use loot_core::{Oid, PathVerdict, Visibility};
use std::path::PathBuf;

/// Machine-output selector (CA3, ADR 0023): which of the three renderings a
/// verb's [`Emit`] shape should produce. Lives beside the trait it
/// parameterizes rather than in `main.rs` — flag parsing (`out_fmt`,
/// `has_flag`) stays there; this is the value it produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutFmt {
    Human,
    Porcelain,
    Json,
}

/// One verb output shape, rendering all three [`OutFmt`] variants from
/// already-computed data. `render` is pure formatting/format selection —
/// never I/O, never fallible. Every `cmd_*` handler *returns* one of these
/// (boxed) instead of writing to stdout; `main.rs`'s dispatcher renders it
/// once with the resolved [`OutFmt`] and prints it. That single return is the
/// in-process test seam: a verb's output is a value a test can assert on
/// without spawning the binary.
pub trait Emit {
    fn render(&self, fmt: OutFmt) -> String;
}

/// A plain-text verb output: prose (or nothing) identical across every
/// [`OutFmt`]. Verbs with no machine-output contract — the ~49 that only ever
/// printed human text and never accepted `--porcelain`/`--json` — build their
/// exact output into one of these and return it, so the dispatcher renders
/// every verb through the same [`Emit`] seam and no `cmd_*` writes stdout
/// itself. `render` ignores the format because these verbs have only one.
pub struct Message(pub String);

impl Message {
    pub fn new(text: impl Into<String>) -> Self {
        Self(text.into())
    }
}

impl Emit for Message {
    fn render(&self, _fmt: OutFmt) -> String {
        self.0.clone()
    }
}

/// The `status` shape (ADR 0023/0029/0030): the working-change header plus
/// its per-path rows — a distinct contract from every other shape here, so it
/// carries `loot_core::verdict::status_porcelain`/`status_json`'s own
/// arguments instead of a `Vec<PathVerdict>`. Used only by `cmd_status`
/// (main.rs), which has two call sites (no working change / a working
/// change present) that each build one `Status` and render it once.
pub struct Status {
    pub change_id: Option<[u8; 16]>,
    pub version: Option<Oid>,
    pub entries: Vec<(PathBuf, Visibility)>,
    /// Pre-rendered human text — built only when `fmt == Human` will actually
    /// print it (see the module doc's note on `status`'s disk read).
    pub human: String,
}

impl Emit for Status {
    fn render(&self, fmt: OutFmt) -> String {
        match fmt {
            OutFmt::Human => self.human.clone(),
            OutFmt::Porcelain => {
                verdict::status_porcelain(self.change_id, self.version.as_ref(), &self.entries)
            }
            OutFmt::Json => {
                format!(
                    "{}\n",
                    verdict::status_json(self.change_id, self.version.as_ref(), &self.entries)
                )
            }
        }
    }
}

/// The shared reconciliation-verdict shape (CA3, ADR 0023): a merge/apply
/// outcome per path, encoded via `loot_core::verdict::porcelain`/`json`. Five
/// verbs share this exact machine contract and differ only in prose: `apply`,
/// `ferry`, `lane merge`, `conflicts`, `pull`.
pub struct Reconciliation {
    pub verdicts: Vec<PathVerdict>,
    pub human: String,
}

impl Emit for Reconciliation {
    fn render(&self, fmt: OutFmt) -> String {
        match fmt {
            OutFmt::Human => self.human.clone(),
            OutFmt::Porcelain => verdict::porcelain(&self.verdicts),
            OutFmt::Json => format!("{}\n", verdict::json(&self.verdicts)),
        }
    }
}

/// The `loot lanes` shape (#232): one row per registered lane, encoded via
/// `loot_core::verdict::lanes_porcelain`/`lanes_json`. `lane new` and `lane
/// list` (`lanes`) share it — `new`'s machine row is the freshly spawned
/// lane's own entry, filtered from the same registry read `list` uses.
pub struct Lanes {
    pub rows: Vec<LaneRow>,
    pub human: String,
}

impl Emit for Lanes {
    fn render(&self, fmt: OutFmt) -> String {
        match fmt {
            OutFmt::Human => self.human.clone(),
            OutFmt::Porcelain => verdict::lanes_porcelain(&self.rows),
            OutFmt::Json => format!("{}\n", verdict::lanes_json(&self.rows)),
        }
    }
}

/// The `buoy` shape (CA4, ADR 0025): resolved/ambiguous/none, encoded via
/// `loot_core::verdict::BuoyVerdict`. Human rendering needs the peer registry
/// (attester names) — registry-coupled, so `main.rs` builds it
/// (`render::render_buoy_human`) and hands it in already-rendered, same as
/// every other shape's `human` field.
pub struct Buoy {
    verdict: BuoyVerdict,
    human: String,
}

impl Buoy {
    /// Lift a resolved [`loot_core::buoy::BuoyResult`] plus its role into the
    /// shape. `human` must already be rendered — building it here would pull
    /// the peer registry into this module, which the human-rendering split
    /// (R5, #181) deliberately keeps out.
    pub fn new(result: loot_core::buoy::BuoyResult, role: &str, human: String) -> Self {
        use loot_core::buoy::BuoyResult;
        let verdict = match result {
            BuoyResult::Resolved { change, attesters } => BuoyVerdict::Resolved {
                role: role.to_string(),
                change,
                attesters,
            },
            BuoyResult::Ambiguous { candidates } => BuoyVerdict::Ambiguous {
                role: role.to_string(),
                candidates: candidates
                    .into_iter()
                    .map(|c| (c.change, c.attesters))
                    .collect(),
            },
            BuoyResult::None => BuoyVerdict::None {
                role: role.to_string(),
            },
        };
        Self { verdict, human }
    }
}

impl Emit for Buoy {
    fn render(&self, fmt: OutFmt) -> String {
        match fmt {
            OutFmt::Human => self.human.clone(),
            OutFmt::Porcelain => self.verdict.porcelain(),
            OutFmt::Json => format!("{}\n", self.verdict.json()),
        }
    }
}
