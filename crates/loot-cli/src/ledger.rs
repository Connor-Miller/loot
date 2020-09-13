//! Typed owner of the `pr-map` ledger under `.loot/git-mirror/` — the review
//! lanes the `loot-first` orchestrator opens (`review`) and clears (`land`).
//! It lives in loot-cli (not loot-first) because `loot lanes` reads it to
//! report a lane's in-flight PR (#232) and the workspace dependency points
//! this way; the orchestrator stays its only *writer* (the mirror surface is
//! harbor-owned, ADR 0034). Its sibling `wip` ledger is written by
//! [`crate::ferry`], so its single typed owner lives there
//! ([`crate::ferry::WipState`]). The format is deliberately dumb
//! (whitespace-split rows) and parsed leniently: malformed lines are skipped,
//! never fatal.

/// The one place the `review/<...>` ref-name rule lives (#281): the suffix is
/// the owning position — the isolation-lane id, or the dock name on the
/// primary (whose owner key is empty). `ferry`'s projection/reap and `land`'s
/// collapse both call this; a second copy drifting would silently split the
/// ref naming between open and close.
pub fn review_handle<'a>(owner: &'a str, dock: &'a str) -> &'a str {
    if owner.is_empty() { dock } else { owner }
}

/// One in-flight review lane in the `pr-map` ledger:
/// `<change> <dock> <pr> <owner>`. `change` is the durable change id (hex) —
/// stable across re-snapshots — so a lane survives amends (ADR 0032/0033).
/// `owner` is the position that opened it: an isolation-lane id, or `-` for
/// the primary (#281) — it is what names the `review/<owner>` branch, so two
/// lanes on one dock never share a ref. Written by `review`, cleared by
/// `land`. Pre-#281 three-field rows parse with an empty owner (primary).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrLane {
    pub change: String,
    pub dock: String,
    pub pr: u64,
    /// The owning position's lane id; empty on the primary.
    pub owner: String,
}

/// The `pr-map` ledger: the set of open review lanes keyed by durable change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrMap {
    pub lanes: Vec<PrLane>,
}

impl PrMap {
    /// Parse the ledger. One lane per line, whitespace-separated; three fields
    /// (pre-#281) read as owner-less (primary), four carry the owner (`-`
    /// meaning primary). Blank/short/unparsable lines are skipped (matching
    /// the ps1's tolerance for the file's whitespace-only empty state).
    pub fn parse(text: &str) -> Self {
        let mut lanes = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() == 3 || f.len() == 4 {
                if let Ok(pr) = f[2].parse() {
                    let owner = match f.get(3) {
                        None | Some(&"-") => String::new(),
                        Some(o) => (*o).to_string(),
                    };
                    lanes.push(PrLane { change: f[0].into(), dock: f[1].into(), pr, owner });
                }
            }
        }
        PrMap { lanes }
    }

    /// Serialize back to disk form: `change dock pr owner\n` per lane (owner
    /// `-` for the primary), no trailing blank line when empty.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for l in &self.lanes {
            let owner = if l.owner.is_empty() { "-" } else { l.owner.as_str() };
            out.push_str(&format!("{} {} {} {}\n", l.change, l.dock, l.pr, owner));
        }
        out
    }

    /// The lane a PR number belongs to, if any.
    pub fn lane_for_pr(&self, pr: u64) -> Option<&PrLane> {
        self.lanes.iter().find(|l| l.pr == pr)
    }

    /// The existing lane for a (change, dock, owner) triple — the `review`
    /// idempotency check: a second review round on the same change refreshes,
    /// not re-opens. Owner-keyed (#281): the same change reviewed from two
    /// positions is two review lanes.
    pub fn lane_for(&self, change: &str, dock: &str, owner: &str) -> Option<&PrLane> {
        self.lanes
            .iter()
            .find(|l| l.change == change && l.dock == dock && l.owner == owner)
    }

    /// Record a freshly-opened lane (no dedup — callers gate on [`lane_for`]).
    pub fn push(&mut self, lane: PrLane) {
        self.lanes.push(lane);
    }

    /// Drop a landed lane by PR number.
    pub fn remove_pr(&mut self, pr: u64) {
        self.lanes.retain(|l| l.pr != pr);
    }
}

impl PrLane {
    /// The review branch this lane's PR head lives on (#281).
    pub fn review_branch(&self) -> String {
        format!("review/{}", review_handle(&self.owner, &self.dock))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pr_map_round_trips() {
        let text = "aabb ferry 201 -\nccdd list 202 t67\n";
        let map = PrMap::parse(text);
        assert_eq!(map.lanes.len(), 2);
        assert_eq!(
            map.lanes[0],
            PrLane { change: "aabb".into(), dock: "ferry".into(), pr: 201, owner: "".into() }
        );
        assert_eq!(
            map.lanes[1],
            PrLane { change: "ccdd".into(), dock: "list".into(), pr: 202, owner: "t67".into() }
        );
        assert_eq!(map.encode(), text);
    }

    #[test]
    fn pr_map_parses_legacy_three_field_rows_as_primary() {
        // Pre-#281 ledgers carried no owner column; they read as primary-owned
        // and re-encode with the explicit `-`.
        let map = PrMap::parse("aabb ferry 201\n");
        assert_eq!(map.lanes[0].owner, "");
        assert_eq!(map.encode(), "aabb ferry 201 -\n");
    }

    #[test]
    fn pr_map_empty_and_whitespace_are_empty() {
        // The live ledger's "empty" state is a whitespace-only file.
        assert_eq!(PrMap::parse("").lanes.len(), 0);
        assert_eq!(PrMap::parse("  \n\n").lanes.len(), 0);
        assert_eq!(PrMap::default().encode(), "");
    }

    #[test]
    fn pr_map_skips_malformed_lines() {
        let map = PrMap::parse("aabb ferry 201 -\ngarbage line here now five\naabb ferry notanumber\n");
        assert_eq!(map.lanes.len(), 1);
        assert_eq!(map.lanes[0].pr, 201);
    }

    #[test]
    fn pr_map_lookup_and_mutation() {
        let mut map = PrMap::parse("aabb ferry 201 -\nccdd list 202 t67\n");
        assert_eq!(map.lane_for_pr(202).unwrap().dock, "list");
        assert_eq!(map.lane_for("aabb", "ferry", "").unwrap().pr, 201);
        assert!(map.lane_for("aabb", "wrong-dock", "").is_none());
        // Owner participates in the key: the same (change, dock) from another
        // position is a different review lane (#281).
        assert!(map.lane_for("aabb", "ferry", "t67").is_none());
        assert_eq!(map.lane_for("ccdd", "list", "t67").unwrap().pr, 202);
        map.remove_pr(201);
        assert_eq!(map.lanes.len(), 1);
        assert_eq!(map.lanes[0].pr, 202);
        map.push(PrLane { change: "eeff".into(), dock: "x".into(), pr: 203, owner: "".into() });
        assert_eq!(map.encode(), "ccdd list 202 t67\neeff x 203 -\n");
    }
}
