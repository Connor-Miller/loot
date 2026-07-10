//! The "patched binary" of the hard-embargo attack demo (#89, ADR 0027): a
//! client built from the same engine with EVERY client-side time gate removed —
//! the Escrow is flushed at `now = u64::MAX` and the content is read at
//! `now = u64::MAX`, so no embargo comparison can ever fail. Run against a
//! holder's repo before `reveal_at` it still cannot read the embargoed change,
//! because the gates it bypasses were never the protection: the key bytes are
//! not on the machine (they sit at the relay, ECIES-wrapped, until the RELAY's
//! clock passes `reveal_at`).
//!
//! Usage: cargo run -p loot-core --example patched-client -- <repo-root> <identity> <path>
//!
//! Exit codes: 0 = the read SUCCEEDED (embargo bypassed — the demo must treat
//! this as failure before reveal, success after), 3 = the read failed for lack
//! of a key, 2 = usage/load error.

use loot_core::{DagRepo, Repo};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(root), Some(identity), Some(path)) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: patched-client <repo-root> <identity> <path>");
        std::process::exit(2);
    };
    let root = std::path::PathBuf::from(root);
    let dot = root.join(".loot");
    let mut repo = match DagRepo::load(&dot, root.clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("patched-client: load {}: {e}", dot.display());
            std::process::exit(2);
        }
    };
    let oid = match repo.current_tree_oid(std::path::Path::new(&path)) {
        Ok(o) => o,
        Err(_) => {
            eprintln!("patched-client: path '{path}' not found in the current change");
            std::process::exit(2);
        }
    };

    println!("patched client: all time gates removed (flush + read at now = u64::MAX)");
    repo.flush_escrow(u64::MAX);
    match repo.get(&oid, &identity, u64::MAX) {
        Ok(bytes) => {
            println!("READ SUCCEEDED ({} bytes):", bytes.len());
            println!("{}", String::from_utf8_lossy(&bytes));
        }
        Err(e) => {
            println!("read FAILED even with every gate removed: {e}");
            println!("nothing to bypass — the key bytes never arrived on this machine");
            std::process::exit(3);
        }
    }
}
