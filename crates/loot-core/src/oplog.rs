//! Operation log and undo (S4, ADR 0031).
//!
//! Every command that changes the repo's **view** — the change-graph heads, each
//! dock's `working`/`tip` pointers, and the `conflicts` set — is recorded as one
//! [`Operation`] in an append-only, repo-wide, **local-only** log (`.loot/ops`).
//! `loot undo` / `loot op restore` step that view backward or to any past point;
//! `loot op log` lists it. This is the safety net that makes ADR 0030's implicit
//! auto-snapshot safe to trust: anything a command recorded, you can walk back.
//!
//! **Undo is a pointer reset over an append-only graph.** Restoring is a *new
//! compensating operation* whose view equals the target's — nothing is deleted
//! from the change graph or object store. Because the log only grows, "undo the
//! undo" (redo) always has a later operation to land on (`loot op restore`).
//!
//! **Barriers undo will not cross.** `grant` / `maroon` / `pull-grants` mutate
//! restricted keys and `push` discloses to a relay — one-way acts that a *view*
//! reset cannot retract (the keyring/manifest/escrow are never touched by undo).
//! They are recorded as [`Operation::barrier`] ops; `undo` refuses to step across
//! one and names the real remedy instead.
//!
//! **Local-only, never synced.** The view is captured as the *raw bytes* of the
//! pointer files it resets, so the log is decoupled from every artifact codec and
//! is trivially rebuildable-from-nothing. It never enters a bundle: `bundle`
//! serializes changes/objects/keys/manifest/attestations and never reads
//! `.loot/ops` (like `heads`/`working`/the git marks).

use crate::bundle_codec::{put_bytes, put_u32};
use crate::format::{self, Cursor};
use crate::{Oid, RepoError, RepoStore};

/// One dock's restorable pointer state — the raw bytes of its per-dock process
/// files, `None` when a file is absent (which restore reproduces by removing it).
#[derive(Clone, Debug, PartialEq, Eq)]
struct DockView {
    name: String,
    working: Option<Vec<u8>>,
    tip: Option<Vec<u8>>,
    tree_hash: Option<Vec<u8>>,
    next_change: Option<Vec<u8>>,
}

/// The repo-wide **view** an operation captures: the shared change-graph heads,
/// the in-progress working-change node, the conflict set, and every dock's
/// working/tip pointers. Stored as raw file bytes so the log needs no knowledge
/// of any artifact codec — restore is a pure pointer reset that touches neither
/// the object store nor the append-only graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    heads: Option<Vec<u8>>,
    working_change: Option<Vec<u8>>,
    conflicts: Option<Vec<u8>>,
    /// The ambient-dock pointer (`.loot/dock`), so undoing a `dock` switch
    /// returns to the dock you were on. Absent means the home dock.
    dock_pointer: Option<Vec<u8>>,
    docks: Vec<DockView>,
}

impl View {
    /// Snapshot the current on-disk view from `store`. Reads only pointer/cache
    /// files (heads, working-change, conflicts, and each dock's working/tip/
    /// tree-hash/next-change); never the object store or the finalized graph.
    pub fn capture(store: &RepoStore) -> View {
        let read = |p: std::path::PathBuf| std::fs::read(p).ok();
        let docks = store
            .list_docks()
            .into_iter()
            .map(|name| {
                let sel = dock_selector(&name);
                DockView {
                    working: read(store.working(sel)),
                    tip: read(store.tip(sel)),
                    tree_hash: read(store.tree_hash(sel)),
                    next_change: read(store.next_change(sel)),
                    name,
                }
            })
            .collect();
        View {
            heads: read(store.heads()),
            working_change: read(store.working_change()),
            conflicts: read(store.conflicts()),
            dock_pointer: read(store.dock_pointer()),
            docks,
        }
    }

    /// Reset the on-disk view to this snapshot: rewrite every recorded pointer
    /// file, and *remove* any that were absent when captured. Only pointer files
    /// are touched — the graph and object store (append-only) are never mutated,
    /// so pointing back at an older head or working change is always valid.
    pub fn restore(&self, store: &RepoStore) -> std::io::Result<()> {
        put_file(&store.heads(), self.heads.as_deref())?;
        put_file(&store.working_change(), self.working_change.as_deref())?;
        put_file(&store.conflicts(), self.conflicts.as_deref())?;
        put_file(&store.dock_pointer(), self.dock_pointer.as_deref())?;
        for d in &self.docks {
            let sel = dock_selector(&d.name);
            if sel.is_some() {
                store.ensure_dock_dir(&d.name)?;
            }
            put_file(&store.working(sel), d.working.as_deref())?;
            put_file(&store.tip(sel), d.tip.as_deref())?;
            put_file(&store.tree_hash(sel), d.tree_hash.as_deref())?;
            put_file(&store.next_change(sel), d.next_change.as_deref())?;
        }
        Ok(())
    }

    /// The change-graph heads this view records, decoded for display.
    pub fn heads(&self) -> Vec<Oid> {
        decode_oids(self.heads.as_deref().unwrap_or_default())
    }
}

/// One recorded operation: the resulting view plus the metadata `op log` shows.
/// `index` is its stable 1-based ordinal (the append-only log never renumbers, so
/// `op restore <index>` is a durable reference). `pos` is the *logical position*
/// the view sits at — for a normal command `pos == index`, but a compensating
/// undo/restore op carries the `pos` of the operation it reproduced, which is how
/// repeated `undo` walks the history back one step at a time.
#[derive(Clone, Debug)]
pub struct Operation {
    pub index: u32,
    pub pos: u32,
    pub time: u64,
    pub command: String,
    pub dock: String,
    pub description: String,
    pub barrier: bool,
    view: View,
}

impl Operation {
    /// The change-graph heads at this operation, decoded for display.
    pub fn heads(&self) -> Vec<Oid> {
        self.view.heads()
    }
}

/// Why a view step could not be taken.
#[derive(Debug)]
pub enum StepError {
    /// There is nothing earlier to move to (the log is empty or already at the
    /// initial operation).
    Nothing(String),
    /// The step would cross a non-undoable barrier operation (a push/grant/…).
    Barrier(BarrierRefusal),
    /// Reading or writing the log failed.
    Io(String),
}

/// A refused barrier crossing: the offending op plus everything `undo` needs to
/// print the "why + real remedy" message (ADR 0031).
#[derive(Debug, Clone)]
pub struct BarrierRefusal {
    pub index: u32,
    pub command: String,
    pub description: String,
}

impl From<RepoError> for StepError {
    fn from(e: RepoError) -> Self {
        StepError::Io(e.to_string())
    }
}

/// Read the full operation log for `store`, oldest first. An absent log is empty.
pub fn read(store: &RepoStore) -> Result<Vec<Operation>, RepoError> {
    let bytes = match std::fs::read(store.ops()) {
        Ok(b) => b,
        Err(_) => return Ok(Vec::new()),
    };
    decode(&bytes)
}

/// Record one view-changing command: capture the current on-disk view and append
/// it as a fresh operation (`index = len + 1`, `pos = index`). `barrier` marks a
/// one-way op (push/grant/maroon/pull-grants) that `undo` must refuse to cross.
pub fn record(
    store: &RepoStore,
    command: &str,
    dock: &str,
    description: &str,
    barrier: bool,
    now: u64,
) -> Result<Operation, RepoError> {
    let mut ops = read(store)?;
    let index = ops.len() as u32 + 1;
    let op = Operation {
        index,
        pos: index,
        time: now,
        command: command.to_string(),
        dock: dock.to_string(),
        description: description.to_string(),
        barrier,
        view: View::capture(store),
    };
    ops.push(op.clone());
    write(store, &ops)?;
    Ok(op)
}

/// The outcome of a successful view step (undo or restore): the compensating op
/// that was appended, and the id of the op whose view was reproduced.
#[derive(Debug)]
pub struct Stepped {
    pub appended: Operation,
    pub restored_to: u32,
}

/// Step the view back one operation (`loot undo`). Refuses if the operation being
/// reverted is a barrier. On success: restore the target view's pointer files and
/// append a compensating `undo` op (so the log grows and redo has a landing spot).
pub fn undo(store: &RepoStore, dock: &str, now: u64) -> Result<Stepped, StepError> {
    let ops = read(store)?;
    let latest = ops.last().ok_or_else(|| {
        StepError::Nothing("nothing to undo — no operations recorded yet".into())
    })?;
    let current = latest.pos;
    let reverted = op_at(&ops, current)
        .ok_or_else(|| StepError::Nothing("nothing to undo — no operations recorded yet".into()))?;
    if reverted.barrier {
        return Err(StepError::Barrier(BarrierRefusal {
            index: reverted.index,
            command: reverted.command.clone(),
            description: reverted.description.clone(),
        }));
    }
    let target = current.checked_sub(1).filter(|t| *t >= 1).ok_or_else(|| {
        StepError::Nothing("nothing to undo — already at the initial operation".into())
    })?;
    let desc = format!("undid op {current} ({})", reverted.command);
    let appended = restore_view_op(store, &ops, target, dock, "undo", &desc, now)?;
    Ok(Stepped { appended, restored_to: target })
}

/// Jump the view to operation `target` (`loot op restore <target>`). A backward
/// jump refuses to cross a barrier, exactly like `undo`; a forward jump (redo)
/// always lands. Appends a compensating `restore` op.
pub fn restore(store: &RepoStore, dock: &str, target: u32, now: u64) -> Result<Stepped, StepError> {
    let ops = read(store)?;
    if op_at(&ops, target).is_none() {
        return Err(StepError::Nothing(format!(
            "no operation {target} in the log (see `loot op log`)"
        )));
    }
    let current = ops.last().map(|o| o.pos).unwrap_or(0);
    // A backward restore un-does every op in (target, current]; refuse if any is
    // a one-way barrier, so `op restore` can't silently sidestep the undo guard.
    if target < current {
        for op in &ops {
            if op.pos > target && op.pos <= current && op.barrier {
                return Err(StepError::Barrier(BarrierRefusal {
                    index: op.index,
                    command: op.command.clone(),
                    description: op.description.clone(),
                }));
            }
        }
    }
    let desc = format!("restored to op {target}");
    let appended = restore_view_op(store, &ops, target, dock, "restore", &desc, now)?;
    Ok(Stepped { appended, restored_to: target })
}

/// Restore op `target`'s view to disk and append a compensating op carrying that
/// view and `pos = target`. Shared by `undo` and `restore`.
fn restore_view_op(
    store: &RepoStore,
    ops: &[Operation],
    target: u32,
    dock: &str,
    command: &str,
    description: &str,
    now: u64,
) -> Result<Operation, StepError> {
    let view = op_at(ops, target)
        .ok_or_else(|| StepError::Nothing(format!("no operation {target} in the log")))?
        .view
        .clone();
    view.restore(store).map_err(|e| StepError::Io(e.to_string()))?;
    let index = ops.len() as u32 + 1;
    let op = Operation {
        index,
        pos: target,
        time: now,
        command: command.to_string(),
        dock: dock.to_string(),
        description: description.to_string(),
        barrier: false,
        view,
    };
    let mut all = ops.to_vec();
    all.push(op.clone());
    write(store, &all)?;
    Ok(op)
}

/// The op with 1-based ordinal `index`, if present.
fn op_at(ops: &[Operation], index: u32) -> Option<&Operation> {
    (index >= 1).then(|| ops.get((index - 1) as usize)).flatten()
}

/// Map a dock name to the [`RepoStore`] selector: the home dock uses the root
/// files (`None`), a named dock its `.loot/docks/<name>/` subtree.
fn dock_selector(name: &str) -> Option<&str> {
    (name != crate::HOME_DOCK).then_some(name)
}

/// Write `bytes` to `path`, or remove the file when `None` (best-effort removal),
/// so a captured-absent pointer restores to absent.
fn put_file(path: &std::path::Path, bytes: Option<&[u8]>) -> std::io::Result<()> {
    match bytes {
        Some(b) => std::fs::write(path, b),
        None => {
            let _ = std::fs::remove_file(path);
            Ok(())
        }
    }
}

fn decode_oids(b: &[u8]) -> Vec<Oid> {
    b.chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            Oid(a)
        })
        .collect()
}

// --- codec (local-only, versioned like every durable artifact) ---

fn write(store: &RepoStore, ops: &[Operation]) -> Result<(), RepoError> {
    std::fs::write(store.ops(), encode(ops)).map_err(|e| RepoError::Backend(e.to_string()))
}

fn encode(ops: &[Operation]) -> Vec<u8> {
    let mut out = Vec::new();
    format::put_version(&mut out);
    put_u32(&mut out, ops.len());
    for op in ops {
        put_u32(&mut out, op.index as usize);
        put_u32(&mut out, op.pos as usize);
        out.extend_from_slice(&op.time.to_le_bytes());
        put_bytes(&mut out, op.command.as_bytes());
        put_bytes(&mut out, op.dock.as_bytes());
        put_bytes(&mut out, op.description.as_bytes());
        out.push(op.barrier as u8);
        encode_view(&mut out, &op.view);
    }
    out
}

fn encode_view(out: &mut Vec<u8>, v: &View) {
    put_opt(out, v.heads.as_deref());
    put_opt(out, v.working_change.as_deref());
    put_opt(out, v.conflicts.as_deref());
    put_opt(out, v.dock_pointer.as_deref());
    put_u32(out, v.docks.len());
    for d in &v.docks {
        put_bytes(out, d.name.as_bytes());
        put_opt(out, d.working.as_deref());
        put_opt(out, d.tip.as_deref());
        put_opt(out, d.tree_hash.as_deref());
        put_opt(out, d.next_change.as_deref());
    }
}

/// Optional blob: a presence byte, then the length-prefixed bytes when present.
fn put_opt(out: &mut Vec<u8>, b: Option<&[u8]>) {
    match b {
        Some(b) => {
            out.push(1);
            put_bytes(out, b);
        }
        None => out.push(0),
    }
}

fn decode(bytes: &[u8]) -> Result<Vec<Operation>, RepoError> {
    let mut c = Cursor { b: bytes, i: 0 };
    format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut ops = Vec::with_capacity(n);
    for _ in 0..n {
        let index = c.u32()? as u32;
        let pos = c.u32()? as u32;
        let time = c.u64()?;
        let command = c.string()?;
        let dock = c.string()?;
        let description = c.string()?;
        let barrier = c.take(1)?[0] != 0;
        let view = decode_view(&mut c)?;
        ops.push(Operation { index, pos, time, command, dock, description, barrier, view });
    }
    Ok(ops)
}

fn decode_view(c: &mut Cursor) -> Result<View, RepoError> {
    let heads = take_opt(c)?;
    let working_change = take_opt(c)?;
    let conflicts = take_opt(c)?;
    let dock_pointer = take_opt(c)?;
    let n = c.u32()?;
    let mut docks = Vec::with_capacity(n);
    for _ in 0..n {
        let name = c.string()?;
        let working = take_opt(c)?;
        let tip = take_opt(c)?;
        let tree_hash = take_opt(c)?;
        let next_change = take_opt(c)?;
        docks.push(DockView { name, working, tip, tree_hash, next_change });
    }
    Ok(View { heads, working_change, conflicts, dock_pointer, docks })
}

fn take_opt(c: &mut Cursor) -> Result<Option<Vec<u8>>, RepoError> {
    if c.take(1)?[0] != 0 {
        Ok(Some(c.bytes()?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(tag: &str) -> (RepoStore, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("loot-oplog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (RepoStore::new(&dir), dir)
    }

    fn write_view(store: &RepoStore, heads: &[u8]) {
        std::fs::write(store.heads(), heads).unwrap();
    }

    #[test]
    fn record_appends_and_round_trips() {
        let (s, dir) = store("rt");
        write_view(&s, &[1; 32]);
        let a = record(&s, "new", "main", "finalize aa", false, 10).unwrap();
        write_view(&s, &[2; 32]);
        let b = record(&s, "describe", "main", "drafting", false, 20).unwrap();
        assert_eq!((a.index, a.pos), (1, 1));
        assert_eq!((b.index, b.pos), (2, 2));

        let back = read(&s).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].command, "new");
        assert_eq!(back[1].description, "drafting");
        assert_eq!(back[1].heads(), vec![Oid([2; 32])]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undo_grows_the_log_and_walks_back_one_step() {
        let (s, dir) = store("walk");
        // Three view-changing ops: heads 1 -> 2 -> 3.
        write_view(&s, &[1; 32]);
        record(&s, "init", "main", "init", false, 1).unwrap();
        write_view(&s, &[2; 32]);
        record(&s, "new", "main", "finalize", false, 2).unwrap();
        write_view(&s, &[3; 32]);
        record(&s, "describe", "main", "drafting", false, 3).unwrap();

        // First undo: revert op 3, land on op 2's view (heads == 2). Log grows.
        let u1 = undo(&s, "main", 4).unwrap();
        assert_eq!(u1.restored_to, 2);
        assert_eq!(decode_oids(&std::fs::read(s.heads()).unwrap()), vec![Oid([2; 32])]);
        assert_eq!(read(&s).unwrap().len(), 4, "undo is itself an op — the log grows");

        // Second undo walks back one more: land on op 1's view (heads == 1).
        let u2 = undo(&s, "main", 5).unwrap();
        assert_eq!(u2.restored_to, 1);
        assert_eq!(decode_oids(&std::fs::read(s.heads()).unwrap()), vec![Oid([1; 32])]);
        assert_eq!(read(&s).unwrap().len(), 5);

        // Redo via restore: jump forward to op 3's view.
        let r = restore(&s, "main", 3, 6).unwrap();
        assert_eq!(r.restored_to, 3);
        assert_eq!(decode_oids(&std::fs::read(s.heads()).unwrap()), vec![Oid([3; 32])]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn undo_refuses_to_cross_a_barrier() {
        let (s, dir) = store("barrier");
        write_view(&s, &[1; 32]);
        record(&s, "new", "main", "finalize", false, 1).unwrap();
        write_view(&s, &[2; 32]);
        record(&s, "push", "main", "push → origin", true, 2).unwrap();

        match undo(&s, "main", 3) {
            Err(StepError::Barrier(b)) => {
                assert_eq!(b.index, 2);
                assert_eq!(b.command, "push");
            }
            other => panic!("expected barrier refusal, got {other:?}"),
        }
        // The refusal changed nothing — heads still at the post-push view.
        assert_eq!(decode_oids(&std::fs::read(s.heads()).unwrap()), vec![Oid([2; 32])]);
        assert_eq!(read(&s).unwrap().len(), 2, "a refused undo appends no op");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bundle_never_reads_the_oplog() {
        use crate::Repo;
        let (s, dir) = store("bundle");
        let repo = crate::engine::DagRepo::init(dir.clone(), "connor").unwrap();
        let before = repo.bundle(&[]).unwrap().0;
        // A populated local oplog (including a barrier op) must not leak into —
        // or even perturb — the shared, syncable bundle (ADR 0031 local-only).
        record(&s, "new", "main", "finalize", false, 1).unwrap();
        record(&s, "push", "main", "push → origin", true, 2).unwrap();
        assert!(s.ops().exists(), "the oplog exists on disk");
        let after = repo.bundle(&[]).unwrap().0;
        assert_eq!(before, after, "bundle bytes are independent of the local oplog");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_reproduces_absent_pointer_files() {
        let (s, dir) = store("absent");
        // Op 1 has a working change on disk; op 2 has none (file removed).
        std::fs::write(s.working(None), [7; 32]).unwrap();
        write_view(&s, &[1; 32]);
        record(&s, "describe", "main", "wip", false, 1).unwrap();
        std::fs::remove_file(s.working(None)).unwrap();
        write_view(&s, &[1; 32]);
        record(&s, "new", "main", "finalize", false, 2).unwrap();

        // Restoring op 1 must bring the working pointer back.
        restore(&s, "main", 1, 3).unwrap();
        assert_eq!(std::fs::read(s.working(None)).unwrap(), [7; 32]);
        // Restoring op 2 must remove it again (absent captured -> absent restored).
        restore(&s, "main", 2, 4).unwrap();
        assert!(!s.working(None).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
