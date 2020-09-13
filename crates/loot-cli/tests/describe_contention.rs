//! #293 reproduction: describe must stick under concurrent shared-store
//! contention, and no verb may crash on a torn read of a shared file.
//!
//! Two lanes over one shared store. Lane B hammers the shared graph by
//! finalizing changes in a tight loop; lane A describes and each description
//! must survive a reopen. Runs entirely against temp fixtures — never a real
//! `.loot` (the ticket's own hazard).

use loot_cli::workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn unique_area(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loot-t293-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// A keyed primary repo with one finalized base change, ready to spawn lanes.
fn keyed_primary(dir: &Path) -> Workspace {
    Workspace::init_at(dir, "connor").unwrap();
    loot_identity::generate_and_save(&dir.join(".loot"), "connor@loot").unwrap();
    let mut ws = Workspace::open_at(dir).unwrap();
    ws.start_fresh_change().unwrap();
    std::fs::write(dir.join("base.txt"), b"base").unwrap();
    ws.snapshot("base").unwrap();
    ws.finalize_working().unwrap();
    ws
}

#[test]
#[ignore = "timing/contention stress test — not deterministic under parallel-test \
            load; run deliberately with `cargo test -- --ignored` (#476). The \
            atomic-write, retry (store::read_replaced*), and StoreLock invariants \
            are guarded in-gate by deterministic unit tests."]
fn describe_sticks_while_a_concurrent_lane_hammers_the_shared_store() {
    let area = unique_area("describe-sticks");
    let repo = area.join("repo");
    let mut ws = keyed_primary(&repo);

    let lane_a = ws.spawn_lane(None, Some(&area.join("laneA"))).unwrap().dir;
    let lane_b = ws.spawn_lane(None, Some(&area.join("laneB"))).unwrap().dir;

    // Session B: finalize in a tight loop — each `save` rewrites the shared graph.
    let stop = Arc::new(AtomicBool::new(false));
    let bstop = stop.clone();
    let bdir = lane_b.clone();
    let hammer = std::thread::spawn(move || {
        let mut i = 0u64;
        while !bstop.load(Ordering::Relaxed) {
            match Workspace::open_at(&bdir) {
                Ok(mut b) => {
                    let _ = std::fs::write(bdir.join("b.txt"), format!("b{i}"));
                    if b.snapshot(&format!("b change {i}")).is_ok() {
                        let _ = b.finalize_working();
                    }
                }
                Err(_) => {}
            }
            i += 1;
        }
        i
    });

    // Session A: describe, then reopen and require the description to have stuck.
    let mut lost = 0u64;
    let mut open_err = 0u64;
    let rounds = 300u64;
    for i in 0..rounds {
        std::fs::write(lane_a.join(format!("a{i}.txt")), format!("a{i}")).unwrap();
        let msg = format!("a describe {i}");
        // The describe itself (== cmd_describe's snapshot_allowing path).
        match Workspace::open_at(&lane_a) {
            Ok(mut a) => {
                if a.snapshot(&msg).is_err() {
                    open_err += 1;
                    continue;
                }
            }
            Err(_) => {
                open_err += 1;
                continue;
            }
        }
        // Reopen: the description must be durable.
        match Workspace::open_at(&lane_a) {
            Ok(a) => {
                let stuck = a.working_id().is_some()
                    && a.working_message().as_deref() == Some(msg.as_str());
                if !stuck {
                    lost += 1;
                }
            }
            Err(_) => open_err += 1,
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = hammer.join();

    let _ = std::fs::remove_dir_all(&area);
    assert_eq!(
        (lost, open_err),
        (0, 0),
        "describe lost/errored under contention: lost={lost} open_err={open_err} of {rounds}"
    );
}

#[test]
#[ignore = "timing/contention stress test — run with `cargo test -- --ignored` (#476)."]
fn concurrent_finalizes_from_two_lanes_all_survive_in_the_shared_graph() {
    // Defect (a): finalize (`new`) persists the signed change into the shared
    // graph by a read-modify-write (read whole file, union in-memory finalized,
    // write whole file). With no serialization, two concurrent persists can lose
    // one another's just-appended change — the change "reports success but does
    // not stick". Each lane finalizes N changes; afterward EVERY finalized change
    // id must be present in the shared graph.
    let area = unique_area("finalize-survive");
    let repo = area.join("repo");
    let mut ws = keyed_primary(&repo);
    let lane_a = ws.spawn_lane(None, Some(&area.join("laneA"))).unwrap().dir;
    let lane_b = ws.spawn_lane(None, Some(&area.join("laneB"))).unwrap().dir;

    const N: u64 = 60;

    let finalize_loop = |dir: PathBuf, tag: &'static str| -> Vec<loot_core::Oid> {
        let mut ids = Vec::new();
        for i in 0..N {
            let mut w = Workspace::open_at(&dir).unwrap();
            std::fs::write(dir.join(format!("{tag}{i}.txt")), format!("{tag}{i}")).unwrap();
            w.snapshot(&format!("{tag} change {i}")).unwrap();
            w.finalize_working().unwrap();
            ids.push(w.heads()[0].clone());
        }
        ids
    };

    let ad = lane_a.clone();
    let handle_a = std::thread::spawn(move || finalize_loop(ad, "a"));
    let bd = lane_b.clone();
    let handle_b = std::thread::spawn(move || finalize_loop(bd, "b"));
    let a_ids = handle_a.join().unwrap();
    let b_ids = handle_b.join().unwrap();

    // Each lane finalized a chain c0->c1->...->c59 into the shared graph. A
    // lost update (one lane clobbering the other's just-persisted node) would
    // punch a hole in a chain, so reopening a lane and walking its own lineage
    // (reachable from its lane-owned heads) misses the clobbered node. Verify
    // every lane still sees its whole chain — the ADR 0022 lineage filter keeps
    // each lane's view to its own line, so we check each from its own position.
    let mut missing = 0u64;
    for (dir, ids) in [(&lane_a, &a_ids), (&lane_b, &b_ids)] {
        let lane = Workspace::open_at(dir).unwrap();
        for id in ids.iter() {
            if lane.repo().change_message(id).is_none() {
                missing += 1;
            }
        }
    }
    let _ = std::fs::remove_dir_all(&area);
    assert_eq!(
        missing, 0,
        "{missing} of {} concurrently-finalized changes were lost from the shared graph",
        2 * N
    );
}

#[test]
#[ignore = "timing/contention stress test — run with `cargo test -- --ignored` (#476)."]
fn loading_never_tears_while_a_lane_rewrites_the_shared_graph() {
    // A reader (`Workspace::open_at`) must never see a torn/empty shared file
    // while a concurrent writer rewrites it — the write must be atomic so the
    // reader observes either the whole old or the whole new file.
    let area = unique_area("no-tear");
    let repo = area.join("repo");
    let mut ws = keyed_primary(&repo);
    let lane_w = ws.spawn_lane(None, Some(&area.join("laneW"))).unwrap().dir;
    let lane_r = ws.spawn_lane(None, Some(&area.join("laneR"))).unwrap().dir;

    let stop = Arc::new(AtomicBool::new(false));
    let wstop = stop.clone();
    let wdir = lane_w.clone();
    let writer = std::thread::spawn(move || {
        let mut i = 0u64;
        while !wstop.load(Ordering::Relaxed) {
            if let Ok(mut w) = Workspace::open_at(&wdir) {
                let _ = std::fs::write(wdir.join("w.txt"), format!("w{i}"));
                if w.snapshot(&format!("w change {i}")).is_ok() {
                    let _ = w.finalize_working();
                }
            }
            i += 1;
        }
    });

    let mut tear = 0u64;
    for _ in 0..3000 {
        // Reader on its own lane: only ever reads the shared graph/objects.
        if Workspace::open_at(&lane_r).is_err() {
            tear += 1;
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = writer.join();
    let _ = std::fs::remove_dir_all(&area);
    assert_eq!(tear, 0, "reader saw {tear} torn/failed loads of the shared store");
}
