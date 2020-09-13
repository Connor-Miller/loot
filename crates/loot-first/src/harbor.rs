//! The harbor lock (ADR 0036) — the on-demand serializer that turns N agents'
//! concurrent lands into one linear git-main.
//!
//! The harbor is not a daemon: there is no process to run. It is a single-writer
//! window a `land` briefly holds while it projects its signed change to
//! git-main and pushes. Every lane over one shared store contends on the *same*
//! lock file ([`RepoStore::harbor_lock`](loot_core::store::RepoStore::harbor_lock)),
//! so only one land occupies the git-main-critical section at a time; the others
//! wait a few seconds and then ferry against the just-moved main (ferry's
//! ingest→reconcile already converges the two lines — the lock only removes the
//! *race*, not the merge). A crashed holder can't wedge the harbor forever: a
//! lock older than `stale` is presumed abandoned and broken.
//!
//! The guard is RAII — the lock releases on `drop`, so an early `?` return
//! anywhere in the land flow (a conflict-bounce, a failed push) frees the harbor
//! for the next agent with no manual unlock.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// A held harbor lock. Drop (or [`release`](Self::release)) removes the file.
#[derive(Debug)]
pub struct HarborLock {
    path: PathBuf,
    held: bool,
}

impl HarborLock {
    /// Acquire the harbor lock, waiting up to `wait` for a concurrent land to
    /// release it, and breaking any lock older than `stale` (a crashed land).
    /// Errors only when the lock stays held by a *live* land past `wait`.
    pub fn acquire(path: PathBuf, wait: Duration, stale: Duration) -> Result<Self, String> {
        Self::acquire_polling(path, wait, stale, Duration::from_millis(100))
    }

    /// [`acquire`](Self::acquire) with an explicit poll interval — the tests
    /// drive a zero wait (contention → immediate error) and a zero stale
    /// (break-on-sight) without sleeping.
    pub fn acquire_polling(
        path: PathBuf,
        wait: Duration,
        stale: Duration,
        poll: Duration,
    ) -> Result<Self, String> {
        Self::acquire_contending(path, wait, stale, poll, &|p| {
            format!(
                "another land holds the harbor lock ({}) — one land projects to \
                 git-main at a time (ADR 0036); retry when it releases, or remove \
                 the file if you are sure no land is running",
                p.display()
            )
        })
    }

    /// [`acquire_polling`](Self::acquire_polling) with a caller-supplied
    /// contended-refusal message. The pr-map ledger lock (#336) rides the same
    /// create-new/stale-break/RAII primitive as the harbor, and its refusal
    /// must say what is actually wedged — the harbor's "is a land running?"
    /// advice would mislead an operator staring at a stuck ledger write.
    pub fn acquire_contending(
        path: PathBuf,
        wait: Duration,
        stale: Duration,
        poll: Duration,
        contended: &dyn Fn(&Path) -> String,
    ) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let start = SystemTime::now();
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut f) => {
                    // Best-effort provenance for a human debugging a wedged lock;
                    // the file's *existence* is the lock, its contents advisory.
                    let _ = writeln!(f, "pid={} acquired={}", std::process::id(), now_secs());
                    return Ok(Self { path, held: true });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A lock past its staleness horizon is a crashed holder —
                    // break it and retry at once (do not consume the wait budget).
                    if lock_age(&path).is_none_or(|age| age >= stale) {
                        let _ = std::fs::remove_file(&path);
                        continue;
                    }
                    if start.elapsed().map(|e| e >= wait).unwrap_or(true) {
                        return Err(contended(&path));
                    }
                    std::thread::sleep(poll);
                }
                Err(e) => return Err(format!("lock {}: {e}", path.display())),
            }
        }
    }

    /// Release the lock now, rather than at end of scope.
    pub fn release(mut self) {
        self.remove();
    }

    fn remove(&mut self) {
        if self.held {
            let _ = std::fs::remove_file(&self.path);
            self.held = false;
        }
    }
}

impl Drop for HarborLock {
    fn drop(&mut self) {
        self.remove();
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// How long ago the lock file was last written, or `None` if it vanished
/// (another contender broke it) or its mtime is unreadable.
fn lock_age(path: &Path) -> Option<Duration> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch dir per test, cleaned on drop.
    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            let uniq = format!(
                "loot-harbor-{tag}-{}-{}",
                std::process::id(),
                now_secs_nanos()
            );
            p.push(uniq);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn lock(&self) -> PathBuf {
            self.0.join("harbor.lock")
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn now_secs_nanos() -> u128 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    const HOUR: Duration = Duration::from_secs(3600);

    #[test]
    fn acquires_creates_the_file() {
        let t = Tmp::new("create");
        let lock = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        assert!(t.lock().exists(), "the lock file marks the harbor held");
        lock.release();
    }

    #[test]
    fn release_frees_the_lock_for_the_next_land() {
        let t = Tmp::new("release");
        let l1 = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        l1.release();
        assert!(!t.lock().exists(), "release removes the file");
        // The next land acquires cleanly.
        let l2 = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        l2.release();
    }

    #[test]
    fn drop_releases_the_lock() {
        let t = Tmp::new("drop");
        {
            let _held = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
            assert!(t.lock().exists());
            // An early `?` return anywhere in land drops the guard here.
        }
        assert!(!t.lock().exists(), "drop is the RAII release");
        HarborLock::acquire(t.lock(), Duration::ZERO, HOUR)
            .expect("harbor free after the guard dropped");
    }

    #[test]
    fn contention_with_a_live_lock_times_out() {
        let t = Tmp::new("contend");
        let _held = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        // A second land, wait=0 and a long staleness horizon: the live lock is
        // neither breakable nor waitable, so it must refuse — not false-succeed.
        let err = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap_err();
        assert!(err.contains("another land holds the harbor lock"), "{err}");
    }

    #[test]
    fn a_contended_acquire_reports_the_callers_message() {
        // The pr-map ledger lock (#336) rides this primitive with its own
        // operator message — a wedged ledger must not claim to be a wedged
        // harbor, whose advice ("is a land running?") would mislead.
        let t = Tmp::new("contend-msg");
        let _held = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        let err = HarborLock::acquire_contending(
            t.lock(),
            Duration::ZERO,
            HOUR,
            Duration::from_millis(1),
            &|p| format!("ledger busy at {}", p.display()),
        )
        .unwrap_err();
        assert!(err.contains("ledger busy"), "{err}");
    }

    #[test]
    fn stale_lock_is_broken() {
        let t = Tmp::new("stale");
        let _crashed = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        // stale=0: any existing lock is presumed a crashed land and broken, so
        // the next land gets in even though the file was present.
        let l2 = HarborLock::acquire(t.lock(), Duration::ZERO, Duration::ZERO)
            .expect("a stale lock is broken, not waited on");
        l2.release();
    }

    #[test]
    fn a_freed_lock_lets_a_polling_waiter_in() {
        // The poll-then-acquire path, deterministically (no threads, no real
        // wall-clock dependence): a held-then-freed lock is re-acquirable within
        // the wait budget. The timeout arm of the same poll loop is covered by
        // `contention_with_a_live_lock_times_out`.
        let t = Tmp::new("freed");
        let l1 = HarborLock::acquire(t.lock(), Duration::ZERO, HOUR).unwrap();
        l1.release();
        let l2 = HarborLock::acquire_polling(
            t.lock(),
            Duration::from_secs(5),
            HOUR,
            Duration::from_millis(1),
        )
        .expect("a freed lock is acquirable inside the wait budget");
        l2.release();
    }
}
