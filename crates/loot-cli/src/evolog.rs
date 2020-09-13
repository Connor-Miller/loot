//! `loot evolog` — the per-change-id evolution log (#397).
//!
//! `jj evolog` shows every version a single change id has ever had — its
//! evolution across amendments. loot already records this: the durable
//! **change id** (ADR 0029) is carried unchanged across every re-snapshot and
//! amend, while each version gets a fresh **version id**, and an amend records
//! the version it replaces in its `predecessors` (the *supersedes* edges of ADR
//! 0032). This verb only *walks and renders* that data — it is strictly
//! read-only; nothing here mints or mutates a change.
//!
//! The walk seeds from the change's **live** version(s) — [`Liveness::live_of`]
//! (a divergent `!` change has more than one) — and follows `predecessors`
//! edges back through every superseded version. Versions are rendered
//! newest-first, like `loot log`: ordered by *supersede depth* (the length of
//! the longest predecessor chain reaching a version), so the live tip leads and
//! the original version trails, with a deterministic version-id tiebreak for the
//! co-versions of a divergent change (equal depth).
//!
//! Each version renders its **version id**, **subject**, **parent**, and
//! **timestamp**. loot changes carry no wall-clock time (ADR 0028); the
//! timestamp is the deterministic commit date `BASE_EPOCH + generation` the git
//! bridge uses — a version's ancestor depth, not a clock. Amended versions that
//! re-anchor on the moving tip step forward in that date; versions that share a
//! DAG parent share it. It is faithful to what the graph records, not invented.
//!
//! The pure core ([`build_evolog`]) is a function of closures over the graph, so
//! it is unit-tested below over a real in-memory [`DagRepo`] without a
//! `Workspace` (and thus without the shared-store cwd hazard).

use crate::emit::{Emit, OutFmt};
use crate::error::CliError;
use crate::render::{self, civil_datetime, short, short_change};
use crate::workspace::Workspace;
use loot_core::bridge::commit_timestamp;
use loot_core::hex;
use loot_core::verdict::{json_string, VERDICT_CONTRACT};
use loot_core::Oid;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// One version in a change's evolution. Position in [`Evolog::rows`] carries the
/// newest-first order; the fields are exactly the four the ticket names.
pub struct EvologRow {
    pub version: Oid,
    /// The change's DAG parent(s) — its base, not the version it supersedes.
    /// Several only at a merge; empty at a root.
    pub parents: Vec<Oid>,
    pub subject: String,
    /// Deterministic commit date (unix seconds), `BASE_EPOCH + generation`.
    pub timestamp: u64,
}

/// The computed evolution of one change id (#397): its durable handle and every
/// version it has had, newest-first.
pub struct Evolog {
    pub change_id: [u8; 16],
    pub rows: Vec<EvologRow>,
}

/// Walk the supersedes (predecessor) chain back from the live `seeds` and order
/// the versions newest-first. Pure: the graph is reached only through the four
/// closures, so this is a total function of its inputs (tested directly).
///
/// `predecessors(v)` names the versions `v` supersedes; `parents(v)` the change's
/// DAG parents; `subject(v)` its message; `timestamp(v)` its deterministic date.
pub fn build_evolog(
    change_id: [u8; 16],
    seeds: &[Oid],
    predecessors: &dyn Fn(&Oid) -> Vec<Oid>,
    parents: &dyn Fn(&Oid) -> Vec<Oid>,
    subject: &dyn Fn(&Oid) -> String,
    timestamp: &dyn Fn(&Oid) -> u64,
) -> Evolog {
    // The evolution set: every version reachable from a live seed through
    // predecessor edges (the seed included).
    let mut set: BTreeSet<Oid> = BTreeSet::new();
    let mut stack: Vec<Oid> = seeds.to_vec();
    while let Some(v) = stack.pop() {
        if set.insert(v.clone()) {
            stack.extend(predecessors(&v));
        }
    }

    // Newest-first = by supersede depth, descending: the longest predecessor
    // chain reaching a version. The live tip has the deepest chain; the original
    // (no predecessors in the set) is depth 0. A shared ancestor of two divergent
    // co-versions is emitted once, after both. Ties break on the version bytes so
    // the co-versions of a `!` change render in a stable order.
    let mut depth: BTreeMap<Oid, usize> = BTreeMap::new();
    for v in &set {
        supersede_depth(v, &set, predecessors, &mut depth);
    }
    let mut ordered: Vec<Oid> = set.into_iter().collect();
    ordered.sort_by(|a, b| {
        depth[b].cmp(&depth[a]).then_with(|| a.0.cmp(&b.0))
    });

    let rows = ordered
        .into_iter()
        .map(|v| EvologRow {
            parents: parents(&v),
            subject: subject(&v),
            timestamp: timestamp(&v),
            version: v,
        })
        .collect();
    Evolog { change_id, rows }
}

/// Memoized longest predecessor chain from `v` within `set` (edges leaving the
/// set are ignored — the walk that built `set` never followed them either).
fn supersede_depth(
    v: &Oid,
    set: &BTreeSet<Oid>,
    predecessors: &dyn Fn(&Oid) -> Vec<Oid>,
    memo: &mut BTreeMap<Oid, usize>,
) -> usize {
    if let Some(d) = memo.get(v) {
        return *d;
    }
    let d = predecessors(v)
        .iter()
        .filter(|p| set.contains(*p))
        .map(|p| 1 + supersede_depth(p, set, predecessors, memo))
        .max()
        .unwrap_or(0);
    memo.insert(v.clone(), d);
    d
}

impl Evolog {
    /// Human output, `loot log`-style columns: version · subject · parent · when.
    fn human(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "evolution of change {} — {} version(s), newest first",
            short_change(&self.change_id),
            self.rows.len()
        );
        let _ = writeln!(out, "{:<9} {:<30} {:<9} {}", "version", "subject", "parent", "when");
        for r in &self.rows {
            let _ = writeln!(
                out,
                "{:<9} {:<30} {:<9} {}",
                short(&r.version),
                r.subject,
                parent_human(&r.parents),
                civil_datetime(r.timestamp),
            );
        }
        out
    }

    /// Porcelain (CA3, ADR 0023): a `C\t<change-hex>` header, then one
    /// `E\t<version-hex>\t<parents>\t<timestamp>\t<subject>` row per version,
    /// newest-first. `<parents>` is comma-joined hex (`-` at a root); ids are hex
    /// and the timestamp is a raw unix int — a parser wants bytes, not prose.
    fn porcelain(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "C\t{}", hex::encode(&self.change_id));
        for r in &self.rows {
            let _ = writeln!(
                out,
                "E\t{}\t{}\t{}\t{}",
                hex::encode(&r.version.0),
                parent_porcelain(&r.parents),
                r.timestamp,
                r.subject,
            );
        }
        out
    }

    /// JSON (CA3, ADR 0023): `{"contract":N,"change":"<hex>","versions":[…]}`,
    /// each version `{"version","parents":[…],"timestamp","subject"}`.
    fn json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\"contract\":");
        s.push_str(&VERDICT_CONTRACT.to_string());
        s.push_str(",\"change\":");
        json_string(&hex::encode(&self.change_id), &mut s);
        s.push_str(",\"versions\":[");
        for (i, r) in self.rows.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str("{\"version\":");
            json_string(&hex::encode(&r.version.0), &mut s);
            s.push_str(",\"parents\":[");
            for (j, p) in r.parents.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                json_string(&hex::encode(&p.0), &mut s);
            }
            s.push_str("],\"timestamp\":");
            s.push_str(&r.timestamp.to_string());
            s.push_str(",\"subject\":");
            json_string(&r.subject, &mut s);
            s.push('}');
        }
        s.push_str("]}\n");
        s
    }
}

impl Emit for Evolog {
    fn render(&self, fmt: OutFmt) -> String {
        match fmt {
            OutFmt::Human => self.human(),
            OutFmt::Porcelain => self.porcelain(),
            OutFmt::Json => self.json(),
        }
    }
}

/// The parent column for human output: short version ids joined by comma, the
/// absent-id dash at a root.
fn parent_human(parents: &[Oid]) -> String {
    if parents.is_empty() {
        render::NO_ID.to_string()
    } else {
        parents.iter().map(short).collect::<Vec<_>>().join(",")
    }
}

/// The parent column for porcelain: full hex ids joined by comma, `-` at a root.
fn parent_porcelain(parents: &[Oid]) -> String {
    if parents.is_empty() {
        "-".to_string()
    } else {
        parents.iter().map(|p| hex::encode(&p.0)).collect::<Vec<_>>().join(",")
    }
}

/// Resolve `sel` to a durable change id. A letter prefix (`k–z`, ADR 0029) names
/// the change directly and is matched across **every** recorded version — so a
/// divergent (`!`) handle still resolves (unlike a selector, which refuses one).
/// Anything else (`@`, `HEAD`, `HEAD~n`, a hex version prefix) goes through the
/// #305 selector grammar and reports the change id its version carries.
fn resolve_change_id(ws: &Workspace, sel: &str) -> Result<[u8; 16], CliError> {
    let g = ws.graph();
    if !sel.is_empty() && sel.chars().all(|c| ('k'..='z').contains(&c)) {
        let mut cids: BTreeSet<[u8; 16]> = BTreeSet::new();
        for v in ws.version_ids() {
            if let Some(cid) = g.change_id(&v) {
                if hex::letters(&cid).starts_with(sel) {
                    cids.insert(cid);
                }
            }
        }
        return match cids.len() {
            0 => Err(format!("no change matching '{sel}'").into()),
            1 => Ok(cids.into_iter().next().unwrap()),
            n => Err(format!("ambiguous change prefix '{sel}' — matches {n} changes").into()),
        };
    }
    let v = ws.resolve_selector(sel)?;
    g.change_id(&v).ok_or_else(|| {
        format!("{sel} resolves to a legacy/unauthored version with no durable change id").into()
    })
}

/// `loot evolog <change-id>` — render the evolution of one change id (#397).
/// Read-only: it walks the supersedes chain and prints it, never snapshotting.
/// `<change-id>` is a change-id prefix (letters `k–z`) or any #305 selector whose
/// version carries a change id (`@`, `HEAD`, `HEAD~n`, a hex version prefix).
pub fn run(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    let positionals: Vec<&str> =
        args.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
    let sel = *positionals.first().ok_or("usage: loot evolog <change-id>")?;

    let ws = Workspace::open().map_err(CliError::no_repo)?;
    let cid = resolve_change_id(&ws, sel)?;

    // Seed from the live version(s). A change abandoned or fully superseded away
    // has none live; fall back to every recorded version carrying the handle so
    // its evolution stays inspectable rather than a bare "no live version".
    let mut seeds = ws.liveness().live_of(&cid);
    if seeds.is_empty() {
        let g = ws.graph();
        seeds = ws.version_ids().into_iter().filter(|v| g.change_id(v) == Some(cid)).collect();
    }
    if seeds.is_empty() {
        return Err(format!("no versions recorded for change {}", short_change(&cid)).into());
    }

    let g = ws.graph();
    let gens = g.generations();
    let evo = build_evolog(
        cid,
        &seeds,
        &|v| g.predecessors(v),
        &|v| g.parents(v),
        &|v| g.message(v).unwrap_or_default(),
        &|v| commit_timestamp(*gens.get(v).unwrap_or(&0)) as u64,
    );
    Ok(Box::new(evo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::{Change, DagRepo, Oid, Repo};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn oid(n: u8) -> Oid {
        Oid([n; 32])
    }

    /// A change carrying one path so its manifest is non-empty (matches what
    /// every production recorder writes).
    fn change(parents: &[Oid], message: &str, addr: u8) -> Change {
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("a.txt"), (oid(addr), loot_core::Visibility::Public));
        Change { id: oid(0), parents: parents.to_vec(), message: message.into(), tree }
    }

    /// An authored in-memory repo — authorship gives changes a durable change id
    /// (the amend primitive needs one), no disk or cwd involved.
    fn authored_repo() -> DagRepo {
        let mut repo = DagRepo::init(PathBuf::from("/mem"), "tester").unwrap();
        repo.set_author([7; 32]);
        repo
    }

    /// Drive `build_evolog` over a real repo the way `run` does.
    fn evolog_of(repo: &DagRepo, cid: [u8; 16], seeds: &[Oid]) -> Evolog {
        // Generation per version (longest parent chain) — the timestamp source.
        let mut gens: BTreeMap<Oid, u64> = BTreeMap::new();
        for id in repo.change_ids_topo() {
            let g = repo
                .parents_of(&id)
                .iter()
                .filter_map(|p| gens.get(p))
                .max()
                .map(|m| m + 1)
                .unwrap_or(0);
            gens.insert(id, g);
        }
        build_evolog(
            cid,
            seeds,
            &|v| repo.change_predecessors(v),
            &|v| repo.parents_of(v),
            &|v| repo.change_message(v).unwrap_or_default(),
            &|v| commit_timestamp(*gens.get(v).unwrap_or(&0)) as u64,
        )
    }

    #[test]
    fn lists_a_linear_amend_chain_newest_first() {
        let mut repo = authored_repo();
        // A base change, then three versions of one handle: v0 amended to v1
        // amended to v2 (each supersedes the prior) — a solo amend chain.
        let base = repo.record_carrying(change(&[], "base", 10), None).unwrap();
        let v0 = repo.record_superseding(change(&[base.clone()], "draft", 20), None, vec![]).unwrap();
        let cid = repo.change_change_id(&v0).unwrap();
        let v1 = repo
            .record_superseding(change(&[base.clone()], "reword", 21), Some(cid), vec![v0.clone()])
            .unwrap();
        let v2 = repo
            .record_superseding(change(&[base.clone()], "final", 22), Some(cid), vec![v1.clone()])
            .unwrap();

        // Live version is the tip v2.
        let live = repo.liveness(&Default::default(), &[]).live_of(&cid);
        assert_eq!(live, vec![v2.clone()], "only the tip is live");

        let evo = evolog_of(&repo, cid, &live);
        let order: Vec<Oid> = evo.rows.iter().map(|r| r.version.clone()).collect();
        assert_eq!(order, vec![v2.clone(), v1.clone(), v0.clone()], "newest-first, whole chain");

        // Subjects and parent ride along; base is the shared DAG parent.
        assert_eq!(evo.rows[0].subject, "final");
        assert_eq!(evo.rows[2].subject, "draft");
        assert!(evo.rows.iter().all(|r| r.parents == vec![base.clone()]));
    }

    #[test]
    fn divergent_change_shows_both_co_versions_then_the_shared_original() {
        let mut repo = authored_repo();
        let base = repo.record_carrying(change(&[], "base", 10), None).unwrap();
        let v0 = repo.record_superseding(change(&[base.clone()], "orig", 20), None, vec![]).unwrap();
        let cid = repo.change_change_id(&v0).unwrap();
        // Two writers amend v0 independently — a divergent (`!`) change.
        let a = repo
            .record_superseding(change(&[base.clone()], "amend A", 21), Some(cid), vec![v0.clone()])
            .unwrap();
        let b = repo
            .record_superseding(change(&[base.clone()], "amend B", 22), Some(cid), vec![v0.clone()])
            .unwrap();

        let live = repo.liveness(&Default::default(), &[]).live_of(&cid);
        assert_eq!(live.len(), 2, "two live co-versions — divergent");

        let evo = evolog_of(&repo, cid, &live);
        let order: Vec<Oid> = evo.rows.iter().map(|r| r.version.clone()).collect();
        assert_eq!(order.len(), 3, "both co-versions plus the shared original");
        // The original (depth 0) is last; the two co-versions (depth 1) lead, in
        // the deterministic version-byte tiebreak order.
        assert_eq!(order[2], v0, "the shared original trails");
        let mut leads = vec![order[0].clone(), order[1].clone()];
        leads.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(leads, want, "both co-versions lead, once each");
    }

    #[test]
    fn renders_all_three_formats() {
        let mut repo = authored_repo();
        let base = repo.record_carrying(change(&[], "base", 10), None).unwrap();
        let v0 = repo.record_superseding(change(&[base.clone()], "draft", 20), None, vec![]).unwrap();
        let cid = repo.change_change_id(&v0).unwrap();
        let v1 = repo
            .record_superseding(change(&[base.clone()], "final", 21), Some(cid), vec![v0.clone()])
            .unwrap();
        let live = repo.liveness(&Default::default(), &[]).live_of(&cid);
        let evo = evolog_of(&repo, cid, &live);

        let human = evo.render(OutFmt::Human);
        assert!(human.contains("evolution of change"));
        assert!(human.contains("final"));
        assert!(human.contains(&short(&v1)));
        assert!(human.contains(&short(&v0)));

        let porc = evo.render(OutFmt::Porcelain);
        assert!(porc.starts_with(&format!("C\t{}\n", hex::encode(&cid))), "change header first");
        let e_rows: Vec<&str> = porc.lines().filter(|l| l.starts_with("E\t")).collect();
        assert_eq!(e_rows.len(), 2, "one E row per version");
        assert!(e_rows[0].contains(&hex::encode(&v1.0)), "newest E row first");

        let json = evo.render(OutFmt::Json);
        assert!(json.starts_with("{\"contract\":"));
        assert!(json.contains(&format!("\"change\":\"{}\"", hex::encode(&cid))));
        assert!(json.contains("\"versions\":["));
        assert!(json.ends_with("]}\n"));
    }

    #[test]
    fn root_change_with_no_parent_renders_a_dash() {
        // A change born at the repo root (no DAG parent) — the parent column is
        // the absent-id dash, not an empty or panicking read.
        let mut repo = authored_repo();
        let v0 = repo.record_superseding(change(&[], "root", 20), None, vec![]).unwrap();
        let cid = repo.change_change_id(&v0).unwrap();
        let live = repo.liveness(&Default::default(), &[]).live_of(&cid);
        let evo = evolog_of(&repo, cid, &live);
        assert_eq!(evo.rows.len(), 1);
        assert!(evo.rows[0].parents.is_empty());
        assert!(evo.render(OutFmt::Human).contains(render::NO_ID));
        assert!(evo.render(OutFmt::Porcelain).contains("\t-\t"), "porcelain root parent is `-`");
    }
}
