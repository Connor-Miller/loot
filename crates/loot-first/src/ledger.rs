//! Typed owner of the `pr-map` ledger under `.loot/git-mirror/` — the review
//! lanes the orchestrator opens and clears. Its sibling `wip` ledger is written
//! by `loot_cli::ferry`, so its single typed owner lives there
//! ([`loot_cli::ferry::WipState`]); the orchestrator reads it through that type
//! rather than a duplicate parser here. Same on-disk format as the ps1
//! predecessor, so a shadow-run reads/writes byte-identical files. The format
//! is deliberately dumb (whitespace-split rows) and parsed leniently: malformed
//! lines are skipped, never fatal.

/// One in-flight review lane in the `pr-map` ledger: `<change> <dock> <pr>`.
/// `change` is the durable change id (hex) — stable across re-snapshots — so a
/// lane survives amends (ADR 0032/0033). Written by `review`, cleared by `land`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrLane {
    pub change: String,
    pub dock: String,
    pub pr: u64,
}

/// The `pr-map` ledger: the set of open review lanes keyed by durable change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrMap {
    pub lanes: Vec<PrLane>,
}

impl PrMap {
    /// Parse the ledger. One lane per line, three whitespace-separated fields;
    /// blank/short/unparsable lines are skipped (matching the ps1's tolerance
    /// for the file's whitespace-only empty state).
    pub fn parse(text: &str) -> Self {
        let mut lanes = Vec::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() == 3 {
                if let Ok(pr) = f[2].parse() {
                    lanes.push(PrLane { change: f[0].into(), dock: f[1].into(), pr });
                }
            }
        }
        PrMap { lanes }
    }

    /// Serialize back to disk form: `change dock pr\n` per lane, no trailing
    /// blank line when empty (the ps1 wrote `""` for an empty ledger).
    pub fn encode(&self) -> String {
        let mut out = String::new();
        for l in &self.lanes {
            out.push_str(&format!("{} {} {}\n", l.change, l.dock, l.pr));
        }
        out
    }

    /// The lane a PR number belongs to, if any.
    pub fn lane_for_pr(&self, pr: u64) -> Option<&PrLane> {
        self.lanes.iter().find(|l| l.pr == pr)
    }

    /// The existing lane for a (change, dock) pair — the `review` idempotency
    /// check: a second review round on the same change refreshes, not re-opens.
    pub fn lane_for(&self, change: &str, dock: &str) -> Option<&PrLane> {
        self.lanes.iter().find(|l| l.change == change && l.dock == dock)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pr_map_round_trips() {
        let text = "aabb ferry 201\nccdd list 202\n";
        let map = PrMap::parse(text);
        assert_eq!(map.lanes.len(), 2);
        assert_eq!(map.lanes[0], PrLane { change: "aabb".into(), dock: "ferry".into(), pr: 201 });
        assert_eq!(map.encode(), text);
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
        let map = PrMap::parse("aabb ferry 201\ngarbage line here now\naabb ferry notanumber\n");
        assert_eq!(map.lanes.len(), 1);
        assert_eq!(map.lanes[0].pr, 201);
    }

    #[test]
    fn pr_map_lookup_and_mutation() {
        let mut map = PrMap::parse("aabb ferry 201\nccdd list 202\n");
        assert_eq!(map.lane_for_pr(202).unwrap().dock, "list");
        assert_eq!(map.lane_for("aabb", "ferry").unwrap().pr, 201);
        assert!(map.lane_for("aabb", "wrong-dock").is_none());
        map.remove_pr(201);
        assert_eq!(map.lanes.len(), 1);
        assert_eq!(map.lanes[0].pr, 202);
        map.push(PrLane { change: "eeff".into(), dock: "x".into(), pr: 203 });
        assert_eq!(map.encode(), "ccdd list 202\neeff x 203\n");
    }
}
