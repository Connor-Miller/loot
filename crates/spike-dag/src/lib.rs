//! Bake-off shim for the DAG engine.
//!
//! The engine graduated into `loot_core::engine` (ADR 0002). This crate now
//! only re-exports it as `DagRepo` so the bake-off keeps its DAG-vs-CRDT
//! symmetry and stays reproducible: `cargo test -p spike-dag` runs the same
//! black-box scenarios against the canonical engine that `spike-crdt` runs
//! against the (non-canonical) CRDT model. The engine's own white-box guards
//! live with the engine, in `loot-core`.

pub use loot_core::DagRepo;

#[cfg(test)]
mod tests {
    use super::DagRepo;
    use loot_bench::{
        scenario_concurrent_converge, scenario_embargo, scenario_same_file_concurrent,
        scenario_scale_and_transfer, scenario_write_and_checkout, small_file_workload,
    };
    use loot_core::Repo;
    use std::path::PathBuf;
    use std::time::Instant;

    fn tmp() -> PathBuf {
        tempfile::tempdir().unwrap().keep()
    }

    #[test]
    fn write_and_checkout_passes() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let blobs = small_file_workload(50, "alice");
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "alice", "mallory", 1000).unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    #[test]
    fn embargo_passes() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let res = scenario_embargo(&mut repo, 5000, "anyone").unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    #[test]
    fn concurrent_converge_passes() {
        let base = tmp();
        let res =
            scenario_concurrent_converge::<DagRepo>(&base, "alice", "relaybob", 9999).unwrap();
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    /// Perf signal: ~2000 small files, time commit + checkout for both readers.
    #[test]
    fn perf_signal_2000_files() {
        let mut repo = DagRepo::init(tmp(), "alice").unwrap();
        let blobs = small_file_workload(2000, "alice");

        let t = Instant::now();
        let res =
            scenario_write_and_checkout(&mut repo, &blobs, "alice", "mallory", 1000).unwrap();
        let elapsed = t.elapsed();

        assert!(res.all_passed(), "checks: {:?}", res.checks);
        println!(
            "[engine] write+checkout of 2000 files (encrypt + 2-reader checkout): {elapsed:?}"
        );
    }

    /// VERDICT TEST: 4 keyholders edit the SAME public file concurrently, then
    /// converge. The DAG uses 3-way merge, so conflicts are expected here.
    #[test]
    fn same_file_concurrent_conflict_rate() {
        let base = tmp();
        let res = scenario_same_file_concurrent::<DagRepo>(&base, 4, 9999).unwrap();
        println!(
            "[engine] same-file concurrent (4 peers): conflicts={:?} merged={:?} converged={:?} relayed={:?} surviving={:?}/{:?}",
            res.metric_value("conflicts"),
            res.metric_value("merged"),
            res.metric_value("converged"),
            res.metric_value("relayed"),
            res.metric_value("surviving_peer_edits"),
            res.metric_value("total_peer_edits"),
        );
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }

    /// Scale + transfer: 50k files, report sync bundle size.
    #[test]
    fn scale_and_transfer_50k() {
        let base = tmp();
        let t = Instant::now();
        let res = scenario_scale_and_transfer::<DagRepo>(&base, 50_000, 1000).unwrap();
        println!(
            "[engine] 50k files: bundle_bytes={:?} elapsed={:?}",
            res.metric_value("bundle_bytes"),
            t.elapsed(),
        );
        assert!(res.all_passed(), "checks: {:?}", res.checks);
    }
}
