//! **Custody**: key management as verbs (#323 — extracted mechanically off
//! the doc-labelled "Custody face" that used to live inline in `engine.rs`,
//! #179). "Permissioning is key management" (ADR 0003/0007/0008/0009/0010/
//! 0027): a [`Custody`] holds this identity's keyring, its escrow of
//! not-yet-revealed embargo keys, the grant [`Manifest`] audit trail, and the
//! pending purge log — and [`DagRepo`] holds one and delegates. No new trait,
//! no adapter: `impl converge::KeyOracle for DagRepo` stays on `DagRepo`
//! (ADR 0002 bake-off symmetry is untouched); this module only relocates
//! state and the verbs that mutate it.
//!
//! Object storage and change-graph access these verbs need (`store`,
//! `entitled`, `object`) stay in `engine.rs` — they are shared with the
//! Reconcile and Sync-negotiation ingest paths (`apply_sync`, `stow`,
//! `apply_with`), not custody-exclusive.

use super::*;
use crate::sealed::Keyring;

/// Key management as verbs — grant, sealed grant, maroon, migrate, escrow
/// flush — plus the manifest/visibility reads that audit it (#323).
pub(super) struct Custody {
    /// This identity's private key custody for non-embargoed content.
    pub(super) keyring: Keyring,
    /// Embargoed content keys awaiting their reveal time. `flush_escrow` promotes
    /// eligible entries to `keyring` before any content-reading operation (ADR 0007).
    pub(super) escrow: Escrow,
    /// Append-only audit trail of grant events (ADR 0008). Travels in bundles.
    pub(super) manifest: Manifest,
    /// Pending purge events: (old-oid, marooned-identity). Shipped in hard-maroon
    /// bundles so cooperating peers remove the marooned identity's key (ADR 0009).
    pub(super) purges: Vec<(Oid, String)>,
}

impl Custody {
    pub(super) fn new() -> Self {
        Custody {
            keyring: Keyring::new(),
            escrow: Escrow::new(),
            manifest: Manifest::new(),
            purges: Vec::new(),
        }
    }
}

/// Returned by `grant`, `maroon`, and `maroon_hard`: the new object address
/// plus any targeted grant bundles the caller should forward to remaining
/// identities (ADR 0008, 0009, 0010).
pub struct MaroonResult {
    pub new_oid: Oid,
    pub grants: Vec<(String, SyncBundle)>,
    /// The id of the re-seal change this maroon recorded. In an authored repo
    /// (one with a keypair) the change is recorded authored-but-**unsigned**,
    /// so — like any working change — it does not yet propagate (ADR 0018: only
    /// signed history travels). The caller must finalize it (attach a
    /// signature) before `push`/`bundle` will ship the re-seal to peers.
    pub change_id: Oid,
}

/// Returned by `migrate`: the new object address plus any targeted grant
/// bundles the caller should forward to newly-granted identities (ADR 0010).
pub struct MigrateResult {
    pub new_oid: Oid,
    pub grants: Vec<(String, SyncBundle)>,
}

/// **Custody face** (R3, #179): key management as verbs — grant, sealed grant,
/// maroon, migrate, escrow flush — plus the manifest/visibility reads that
/// audit it. "Permissioning is key management" (ADR 0003/0007/0008/0010);
/// everything that mints, hands over, or revokes a content key lives here.
impl DagRepo {
    /// Promote embargoed keys whose `reveal_at <= now` from Escrow into the
    /// Keyring. Call this before any content-reading operation (`surface`,
    /// `snapshot`). After this, `sealed::open` finds the key in the Keyring
    /// and decrypts normally — `open` itself is unmodified (ADR 0007).
    pub fn flush_escrow(&mut self, now: u64) {
        self.custody.escrow.flush(&mut self.custody.keyring, now);
    }

    /// Produce a targeted grant bundle that gives `grantee` the key for `oid`
    /// and records the event in the local manifest (ADR 0008). The caller must
    /// hold the key for `oid`; if not, returns `Unauthorized`.
    ///
    /// `expires_at` (`None` = never expires, #20) rides only in the local
    /// manifest record here — a tag-1 grant is a file delivered out of band, so
    /// there is no wire header to carry it; `surface` on this repo's own future
    /// reads is what enforces it (parallel to `grant_sealed`'s wire-carried
    /// `expires_at`, enforced by the recipient's `apply_sealed_grant` too).
    ///
    /// The bundle carries only the objects and key for this single grant — it is
    /// a targeted hand-off, not a full sync. Apply it on the grantee side.
    pub fn grant(
        &mut self,
        oid: &Oid,
        grantee: &str,
        now: u64,
        expires_at: Option<u64>,
    ) -> Result<SyncBundle, RepoError> {
        // Must hold the key ourselves before we can grant it.
        let key = self
            .custody
            .keyring
            .key_for(oid)
            .ok_or_else(|| RepoError::Unauthorized(oid.clone()))?;

        // A grant carries just this object and its key, addressed to grantee.
        let obj = self.object(oid)?.clone();
        let mut keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        keys.insert(oid.clone(), key);
        let mut objs: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        objs.insert(oid.clone(), obj);
        let body = BundleBody {
            changes: Vec::new(),
            objs,
            keys,
            attestations: Vec::new(),
        };

        // Record in the local manifest (file-based grant: no pubkeys known here).
        use crate::manifest::UNKNOWN_PUBKEY;
        self.custody.manifest.record(
            oid.clone(),
            grantee.to_string(),
            UNKNOWN_PUBKEY,
            UNKNOWN_PUBKEY,
            now,
            expires_at,
        );

        Ok(SyncBundle(
            Frame::Grant {
                grantee: grantee.to_string(),
                body,
            }
            .encode(),
        ))
    }

    /// Produce a sealed-key grant bundle (tag 3) where the content key is
    /// ECIES-wrapped to the recipient's x25519 pubkey. Safe to relay — the relay
    /// cannot read the key. The caller supplies `seal_fn` to do the wrapping,
    /// keeping identity crypto outside the engine (ADR 0014).
    ///
    /// `grantee_pubkey` — the recipient's ed25519 pubkey (32 bytes). Used for
    /// mailbox addressing and the manifest audit record (ADR 0015).
    /// `grantor_pubkey` — the issuer's ed25519 pubkey. Recorded in the manifest
    /// so every peer can verify who issued the grant (ADR 0015).
    /// `reveal_at` — `0` for an ordinary grant; nonzero makes it a **timed**
    /// grant the relay withholds until its own clock passes it (hard embargo,
    /// ADR 0027). For embargoed content the originator's key sits in the local
    /// Escrow (pre-reveal staging, ADR 0007), so the lookup falls back there.
    /// `expires_at` — `None` for a grant that never expires (the default, and
    /// the only behavior before #20); `Some(t)` makes the recipient's
    /// `apply_sealed_grant` reject the grant outright once `now >= t`. Rides in
    /// the frame header (v8), inside the grantor-signed envelope, so it cannot
    /// be widened or dropped by a tampered copy.
    ///
    /// Wire format: `[3][grantee_pubkey(32)][wrapped_key(80)][oid(32)][reveal_at(8)][expires_at][payload]`
    pub fn grant_sealed(
        &mut self,
        oid: &Oid,
        grantee_name: &str,
        grantee_pubkey: [u8; 32],
        grantor_pubkey: [u8; 32],
        reveal_at: u64,
        expires_at: Option<u64>,
        now: u64,
        seal: impl FnOnce(&[u8; 32]) -> Result<[u8; 80], RepoError>,
    ) -> Result<SyncBundle, RepoError> {
        let key = self
            .custody
            .keyring
            .key_for(oid)
            .or_else(|| {
                self.custody
                    .escrow
                    .iter()
                    .find(|(o, _)| *o == oid)
                    .map(|(_, e)| e.key)
            })
            .ok_or_else(|| RepoError::Unauthorized(oid.clone()))?;
        let wrapped = seal(&key)?;

        // Object only — the key travels ECIES-wrapped in the frame's wrapped_key
        // field, never in the body.
        let obj = self.object(oid)?.clone();
        let mut objs: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        objs.insert(oid.clone(), obj);
        let body = BundleBody {
            changes: Vec::new(),
            objs,
            keys: BTreeMap::new(),
            attestations: Vec::new(),
        };

        self.custody.manifest.record(
            oid.clone(),
            grantee_name.to_string(),
            grantee_pubkey,
            grantor_pubkey,
            now,
            expires_at,
        );
        Ok(SyncBundle(
            Frame::SealedGrant {
                grantee_pubkey,
                wrapped_key: wrapped,
                oid: oid.clone(),
                reveal_at,
                expires_at,
                body,
            }
            .encode(),
        ))
    }

    /// Apply a sealed-key grant bundle (tag 3). The caller supplies:
    /// - `grantor_pubkey` — verified ed25519 pubkey of the sender (from the
    ///   envelope the caller already verified). Recorded in the manifest (ADR 0015).
    /// - `unseal` — closure that decrypts the 80-byte wrapped key using the
    ///   recipient's private key. If the key was not sealed for us, this fails.
    ///
    /// Authorization is purely cryptographic: if `unseal` succeeds, the grant
    /// was addressed to us. There is no name-compare gate (ADR 0015).
    ///
    /// A grant past its `expires_at` (#20) is rejected outright — `Err`, with
    /// nothing stored or filed — checked before `unseal` so an expired grant is
    /// refused whether or not it was even addressed to us.
    pub fn apply_sealed_grant(
        &mut self,
        bundle: &SyncBundle,
        grantor_pubkey: [u8; 32],
        now: u64,
        unseal: impl FnOnce(&[u8; 80]) -> Result<[u8; 32], RepoError>,
    ) -> Result<(), RepoError> {
        // Decode through the one codec; reject anything that isn't a sealed grant.
        let Frame::SealedGrant {
            grantee_pubkey,
            wrapped_key,
            oid,
            reveal_at,
            expires_at,
            body,
        } = Frame::decode(&bundle.0)?
        else {
            return Err(RepoError::Backend(
                "not a sealed-key grant bundle (tag 3)".into(),
            ));
        };

        if let Some(t) = expires_at {
            if now >= t {
                return Err(RepoError::Expired(t));
            }
        }

        // Cryptographic gate: unseal fails if this grant wasn't addressed to us.
        let key = unseal(&wrapped_key)?;

        // SealedGrant bodies carry objects only (the grant is a key handoff, not
        // a history sync), so `changes` is always empty today. Guard it anyway so
        // a future format extension can't sneak unsigned authored changes in via
        // the grant path (ADR 0018 — verify-always, not a toggle).
        for node in &body.changes {
            verify_authored_change(node)?;
        }

        for (addr, obj) in body.objs {
            self.store(addr, obj, None);
        }
        // A timed grant not yet due stages in the local Escrow, not the Keyring —
        // cooperative defense-in-depth if a relay releases early; the hard
        // guarantee is the relay withholding (ADR 0027).
        if reveal_at > now {
            if !self.custody.escrow.holds(&oid) && !self.custody.keyring.holds(&oid) {
                self.custody.escrow.insert(oid.clone(), key, reveal_at);
            }
        } else if !self.custody.keyring.holds(&oid) {
            self.custody.keyring.insert(oid.clone(), key);
        }

        // Record in manifest: we know both pubkeys, and the grantee is ourselves.
        self.custody.manifest.record(
            oid,
            self.identity.clone(),
            grantee_pubkey,
            grantor_pubkey,
            now,
            expires_at,
        );
        Ok(())
    }

    /// Forward-maroon `marooned` from `path`: re-seal the content under a fresh
    /// key that excludes `marooned`, update the change tree, and produce grant
    /// bundles for every remaining identity in the manifest (ADR 0009).
    ///
    /// Forward maroon does NOT emit a purge event — the marooned identity keeps
    /// their existing key for content they already have; they simply won't receive
    /// the new key. Use `maroon_hard` to also emit a purge event.
    pub fn maroon(
        &mut self,
        path: &Path,
        marooned: &str,
        now: u64,
    ) -> Result<MaroonResult, RepoError> {
        self.maroon_inner(path, marooned, now, false)
    }

    /// Hard-maroon `marooned` from `path`: same as forward maroon, but also emits
    /// a purge event so cooperating peers remove the marooned identity's old key
    /// on next bundle apply (ADR 0009).
    pub fn maroon_hard(
        &mut self,
        path: &Path,
        marooned: &str,
        now: u64,
    ) -> Result<MaroonResult, RepoError> {
        self.maroon_inner(path, marooned, now, true)
    }

    fn maroon_inner(
        &mut self,
        path: &Path,
        marooned: &str,
        now: u64,
        hard: bool,
    ) -> Result<MaroonResult, RepoError> {
        // Find the current oid for this path.
        let tree = self.graph.current_tree();
        let (old_oid, old_vis) = tree
            .get(path)
            .ok_or(RepoError::NotFound(Oid([0; 32])))?
            .clone();

        // Must hold the key to re-seal.
        let plaintext = self
            .get(&old_oid, &self.identity, now)
            .map_err(|_| RepoError::Unauthorized(old_oid.clone()))?;

        // Build the new visibility excluding marooned.
        let new_vis = match &old_vis {
            Visibility::Restricted(ids) => {
                let remaining: Vec<String> = ids
                    .iter()
                    .filter(|id| id.as_str() != marooned)
                    .cloned()
                    .collect();
                Visibility::Restricted(remaining)
            }
            other => other.clone(),
        };

        // Re-seal under new visibility.
        let new_oid = self.put(&plaintext, new_vis.clone())?;

        // Record a purge event if hard maroon.
        if hard {
            self.custody
                .purges
                .push((old_oid.clone(), marooned.to_string()));
        }

        // Update the current working change (or create a new one) to point to new_oid.
        let mut new_tree = tree.clone();
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), new_vis.clone()));
        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: format!("maroon {} from {}", marooned, path.display()),
            tree: new_tree,
        };
        let change_id = self.record(change)?;

        // Produce grant bundles for remaining identities.
        // Carry each remaining grantee's own expires_at (if any) forward onto
        // the re-seal (#20) — a maroon must not accidentally un-expire a grant
        // that was already due to lapse.
        let remaining_grantees: Vec<(String, Option<u64>)> = self
            .custody
            .manifest
            .grants_for(&old_oid)
            .into_iter()
            .filter(|e| e.grantee != marooned && e.grantee != self.identity)
            .map(|e| (e.grantee.clone(), e.expires_at))
            .collect();

        let mut grants = Vec::new();
        for (grantee, expires_at) in remaining_grantees {
            if let Ok(bundle) = self.grant(&new_oid, &grantee, now, expires_at) {
                grants.push((grantee, bundle));
            }
        }

        Ok(MaroonResult {
            new_oid,
            grants,
            change_id,
        })
    }

    /// Migrate `path` to a new visibility policy: re-seal the content under
    /// `new_vis`, update the change tree, and produce grant bundles for any
    /// identities newly granted access (ADR 0010).
    pub fn migrate(
        &mut self,
        path: &Path,
        new_vis: Visibility,
        now: u64,
    ) -> Result<MigrateResult, RepoError> {
        // Find the current oid for this path.
        let tree = self.graph.current_tree();
        let (old_oid, _old_vis) = tree
            .get(path)
            .ok_or(RepoError::NotFound(Oid([0; 32])))?
            .clone();

        // Must hold the key to re-seal.
        let plaintext = self
            .get(&old_oid, &self.identity, now)
            .map_err(|_| RepoError::Unauthorized(old_oid.clone()))?;

        // Re-seal under new visibility.
        let new_oid = self.put(&plaintext, new_vis.clone())?;

        // Update the current working change (or create a new one) to point to new_oid.
        let mut new_tree = tree.clone();
        new_tree.insert(path.to_path_buf(), (new_oid.clone(), new_vis.clone()));
        let change = Change {
            id: Oid([0; 32]),
            parents: self.graph.heads(),
            message: format!("migrate {} to {:?}", path.display(), new_vis),
            tree: new_tree,
        };
        self.record(change)?;

        // Produce grant bundles for any newly-listed identities.
        let grants_needed: Vec<String> = match &new_vis {
            Visibility::Restricted(ids) => ids
                .iter()
                .filter(|id| id.as_str() != self.identity.as_str())
                .cloned()
                .collect(),
            _ => vec![],
        };

        let mut grants = Vec::new();
        for grantee in grants_needed {
            // A migration to Restricted mints a fresh oid with no prior grant
            // to inherit an expiry from — an ordinary, non-expiring grant.
            if let Ok(bundle) = self.grant(&new_oid, &grantee, now, None) {
                grants.push((grantee, bundle));
            }
        }

        Ok(MigrateResult { new_oid, grants })
    }

    /// The grant audit trail.
    pub fn manifest(&self) -> &Manifest {
        &self.custody.manifest
    }

    /// True if `reader`'s own recorded grant for `oid` has expired as of `now`
    /// (#20). A miss — no grant recorded at all for this `(oid, reader)` pair,
    /// e.g. an owner's own content or a tag-1 recipient who never separately
    /// recorded one — is not an expiry (`false`). The one check shared by
    /// `surface`/`surface_with_report` (skip the path) and `visible_paths_at`
    /// (ADR 0022's "matches what surface put there" invariant), so the three
    /// can't drift apart on what counts as expired.
    pub(super) fn grant_expired_for(&self, oid: &Oid, reader: &str, now: u64) -> bool {
        self.custody
            .manifest
            .grant_for(oid, reader)
            .is_some_and(|g| g.is_expired(now))
    }

    /// Every embargoed path in the current tree whose content key this repo
    /// holds — `(path, oid, reveal_at)`. The key may sit in the Keyring
    /// (reveal passed) or still in Escrow (originator staging, ADR 0007);
    /// either way this repo can issue grants for it. The push-time deposit
    /// pass (ADR 0027) grants exactly these — a non-keyholder peer has
    /// nothing to deposit.
    pub fn embargoed_paths(&self) -> Vec<(PathBuf, Oid, u64)> {
        self.graph
            .current_tree()
            .into_iter()
            .filter_map(|(path, (oid, vis))| match vis {
                Visibility::Embargoed { reveal_at }
                    if self.custody.keyring.holds(&oid) || self.custody.escrow.holds(&oid) =>
                {
                    Some((path, oid, reveal_at))
                }
                _ => None,
            })
            .collect()
    }
}

// --- local persistence helpers for the manifest and purge log ---
// Same hand-rolled length-prefixed format as the other engine.rs codecs
// (encode_conflicts/encode_attestations); kept alongside Custody because they
// codec exactly the two fields it owns beyond keyring/escrow.

pub(super) fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    let entries: Vec<_> = manifest.iter().collect();
    put_u32(&mut out, entries.len());
    for e in entries {
        out.extend_from_slice(&e.oid.0);
        put_bytes(&mut out, e.grantee.as_bytes());
        out.extend_from_slice(&e.grantee_pubkey);
        out.extend_from_slice(&e.grantor_pubkey);
        out.extend_from_slice(&e.granted_at.to_le_bytes());
        // v8 (#20): optional grant expiry, presence byte + value.
        match e.expires_at {
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.to_le_bytes());
            }
            None => out.push(0),
        }
    }
    out
}

pub(super) fn decode_manifest(b: &[u8]) -> Result<Manifest, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    let (major, _minor) = crate::format::read_version(&mut c)?;
    let mut m = Manifest::new();
    let n = c.u32()?;
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let grantee = c.string()?;
        let grantee_pubkey = c.arr32()?;
        let grantor_pubkey = c.arr32()?;
        let granted_at = c.u64()?;
        // v8 (#20): pre-v8 manifests predate expiry — never expire.
        let expires_at = if major >= 8 {
            if c.take(1)?[0] != 0 { Some(c.u64()?) } else { None }
        } else {
            None
        };
        m.record(oid, grantee, grantee_pubkey, grantor_pubkey, granted_at, expires_at);
    }
    Ok(m)
}

pub(super) fn encode_purges(purges: &[(Oid, String)]) -> Vec<u8> {
    use crate::bundle_codec::{put_bytes, put_u32};
    let mut out = Vec::new();
    crate::format::put_version(&mut out);
    put_u32(&mut out, purges.len());
    for (oid, identity) in purges {
        out.extend_from_slice(&oid.0);
        put_bytes(&mut out, identity.as_bytes());
    }
    out
}

pub(super) fn decode_purges(b: &[u8]) -> Result<Vec<(Oid, String)>, RepoError> {
    use crate::format::Cursor;
    let mut c = Cursor { b, i: 0 };
    crate::format::read_version(&mut c)?;
    let n = c.u32()?;
    let mut purges = Vec::with_capacity(n);
    for _ in 0..n {
        let oid = Oid(c.arr32()?);
        let identity = c.string()?;
        purges.push((oid, identity));
    }
    Ok(purges)
}

#[cfg(test)]
mod tests {
    //! White-box guards that need engine internals (`custody.keyring`,
    //! `bundle_codec::decode`) — moved from `engine::tests` with the custody
    //! verbs and fields they exercise (#323).
    use super::*;
    use crate::bundle_codec;

    fn tmp() -> PathBuf {
        std::env::temp_dir()
    }

    fn contains_window(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Decode a sync bundle through `Frame::decode` and re-encode just the body
    /// payload for ADR 0003/0004 leak-guard inspection. This approach is immune
    /// to future Frame header changes (S2 compression flags, etc.) — the frame
    /// decoder handles whatever is in front of the body.
    fn extract_sync_payload(bundle: &[u8]) -> Vec<u8> {
        let frame = bundle_codec::Frame::decode(bundle).expect("valid sync bundle");
        let bundle_codec::Frame::Sync { body, .. } = frame else {
            panic!("expected sync bundle (tag 0)");
        };
        let changes: Vec<&ChangeNode> = body.changes.iter().collect();
        bundle_codec::encode(&changes, &body.objs, &body.keys, &body.attestations)
    }

    // --- embargo / escrow (ADR 0007) ---

    /// Core guarantee: the originator's own embargoed key is in Escrow, not
    /// the Keyring, so `get` returns Embargoed before flush.
    #[test]
    fn embargo_key_in_escrow_not_keyring_before_reveal() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice
            .put(b"cve fix", Visibility::Embargoed { reveal_at: 100 })
            .unwrap();

        // Before flush: Keyring has no entry, Escrow does.
        assert!(
            !alice.custody.keyring.holds(&oid),
            "key must be in escrow, not keyring"
        );
        assert!(
            alice.custody.escrow.holds(&oid),
            "key must be in escrow before reveal"
        );
        // get() returns Embargoed (open() finds no key in keyring).
        assert!(matches!(
            alice.get(&oid, "alice", 99),
            Err(RepoError::Embargoed(100))
        ));
    }

    /// After flush_escrow with now >= reveal_at, the key promotes to the Keyring
    /// and get() succeeds.
    #[test]
    fn flush_escrow_promotes_key_and_enables_read() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice
            .put(b"cve fix", Visibility::Embargoed { reveal_at: 100 })
            .unwrap();

        alice.flush_escrow(100);

        assert!(
            alice.custody.keyring.holds(&oid),
            "key must be in keyring after flush"
        );
        assert!(
            !alice.custody.escrow.holds(&oid),
            "escrow must be empty after flush"
        );
        assert_eq!(alice.get(&oid, "alice", 100).unwrap(), b"cve fix");
    }

    /// Hard embargo (ADR 0027, #14): an embargoed key never rides in a sync
    /// bundle at all. The receiver gets ciphertext only — the key bytes are
    /// simply not on their machine, no matter what clock they claim or how
    /// they read their own storage. Keys arrive only as relay-withheld timed
    /// SealedGrants after reveal.
    #[test]
    fn bundle_never_carries_an_embargoed_key() {
        let mut alice = DagRepo::init(std::env::temp_dir(), "alice").unwrap();
        let oid = alice
            .put(b"cve fix", Visibility::Embargoed { reveal_at: 100 })
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("cve.txt"),
            (oid.clone(), Visibility::Embargoed { reveal_at: 100 }),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "cve".into(),
                tree,
            })
            .unwrap();
        // Alice's own key stages in HER escrow (originator staging, ADR 0007) —
        // that never travels.
        assert!(alice.custody.escrow.holds(&oid));

        let bundle = alice.bundle(&[]).unwrap();

        // Wire check: no key for the embargoed object anywhere in the body, and
        // the raw key bytes appear nowhere in the whole bundle.
        let payload = extract_sync_payload(&bundle.0);
        let (_changes, objs, plain_keys, _attestations) =
            bundle_codec::decode(&payload, crate::format::FORMAT_MAJOR).unwrap();
        assert!(
            plain_keys.get(&oid).is_none(),
            "embargoed key must not be in the keys section"
        );
        assert!(
            objs.iter().any(|(a, _)| *a == oid),
            "the ciphertext itself still syncs"
        );
        let alice_key = alice
            .custody
            .escrow
            .iter()
            .find(|(o, _)| *o == &oid)
            .map(|(_, e)| e.key)
            .unwrap();
        assert!(
            !contains_window(&bundle.0, &alice_key),
            "raw embargoed key bytes must not appear anywhere on the wire"
        );

        // Bob applies: ciphertext lands, but no key exists on his machine —
        // neither keyring nor escrow — even long after reveal_at. A lying clock
        // or a modified binary has nothing to find.
        let mut bob = DagRepo::init(std::env::temp_dir(), "bob").unwrap();
        bob.apply(&bundle, 50).unwrap();
        assert!(
            !bob.custody.escrow.holds(&oid),
            "no escrow entry arrives via bundle (v5)"
        );
        assert!(
            !bob.custody.keyring.holds(&oid),
            "no keyring entry arrives via bundle"
        );
        bob.flush_escrow(1_000_000);
        assert!(
            bob.get(&oid, "bob", 1_000_000).is_err(),
            "no key, no read — ever, via this lane"
        );
    }

    /// Escrow persists across save/load so reveal works in a new process.
    #[test]
    fn escrow_survives_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-escrow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo
                .put(b"cve fix", Visibility::Embargoed { reveal_at: 100 })
                .unwrap();
            repo.save(&dir).unwrap();
        }

        let mut loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        // Still embargoed after reload.
        assert!(loaded.custody.escrow.holds(&oid));
        assert!(matches!(
            loaded.get(&oid, "alice", 50),
            Err(RepoError::Embargoed(100))
        ));
        // Flush and read.
        loaded.flush_escrow(100);
        assert_eq!(loaded.get(&oid, "alice", 100).unwrap(), b"cve fix");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Manifest persists across save/load.
    #[test]
    fn manifest_survives_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo
                .put(
                    b"shared data",
                    Visibility::Restricted(vec!["alice".into(), "bob".into()]),
                )
                .unwrap();
            repo.custody
                .manifest
                .record(oid.clone(), "bob".to_string(), [0u8; 32], [0u8; 32], 42, None);
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        let grants = loaded.custody.manifest.grants_for(&oid);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grantee, "bob");
        assert_eq!(grants[0].granted_at, 42);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Purge events persist across save/load.
    #[test]
    fn purge_events_survive_save_load() {
        let dir = std::env::temp_dir().join(format!("loot-purges-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let oid;
        {
            let mut repo = DagRepo::init(dir.join("work"), "alice").unwrap();
            oid = repo
                .put(b"data", Visibility::Restricted(vec!["alice".into()]))
                .unwrap();
            repo.custody.purges.push((oid.clone(), "bob".to_string()));
            repo.save(&dir).unwrap();
        }

        let loaded = DagRepo::load(&dir, dir.join("work")).unwrap();
        assert_eq!(loaded.custody.purges.len(), 1);
        assert_eq!(loaded.custody.purges[0].0, oid);
        assert_eq!(loaded.custody.purges[0].1, "bob");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- grant / manifest (ADR 0008) ---

    #[test]
    fn grant_gives_grantee_the_key_and_records_in_manifest() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret data", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();

        let bundle = alice.grant(&oid, "bob", 100, None).unwrap();

        // Manifest should record the grant.
        let grants = alice.custody.manifest.grants_for(&oid);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].grantee, "bob");
        assert_eq!(grants[0].granted_at, 100);

        // Bob applies the grant bundle.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        // Also give bob the object (normally via regular bundle).
        let obj = alice.objects.get(&oid).unwrap().clone();
        bob.objects.put(oid.clone(), obj);

        bob.apply(&bundle, 0).unwrap();
        assert!(
            bob.custody.keyring.holds(&oid),
            "bob must hold the key after applying grant"
        );
        assert_eq!(bob.get(&oid, "bob", 0).unwrap(), b"secret data");
    }

    #[test]
    fn grant_requires_caller_to_hold_key() {
        let alice = DagRepo::init(tmp(), "alice").unwrap();
        let unknown_oid = Oid([99; 32]);
        let mut repo = alice;
        let result = repo.grant(&unknown_oid, "bob", 0, None);
        assert!(
            matches!(result, Err(RepoError::Unauthorized(_))),
            "must fail without key"
        );
    }

    #[test]
    fn manifest_accumulates_across_bundles() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid1 = alice
            .put(b"data1", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let oid2 = alice
            .put(b"data2", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();

        alice.grant(&oid1, "bob", 10, None).unwrap();
        alice.grant(&oid2, "carol", 20, None).unwrap();

        assert_eq!(alice.custody.manifest.grants_for(&oid1).len(), 1);
        assert_eq!(alice.custody.manifest.grants_for(&oid2).len(), 1);
        assert_eq!(alice.custody.manifest.iter().count(), 2);
    }

    // --- grant expiry (#20) ---
    //
    // A trivial fixed-position seal/unseal pair stands in for real ECIES here
    // (identity crypto is deliberately outside the engine, ADR 0014) — only
    // the wire path and the expiry gate are under test.
    fn fake_seal(key: &[u8; 32]) -> Result<[u8; 80], RepoError> {
        let mut w = [0u8; 80];
        w[..32].copy_from_slice(key);
        Ok(w)
    }
    fn fake_unseal(wrapped: &[u8; 80]) -> Result<[u8; 32], RepoError> {
        let mut k = [0u8; 32];
        k.copy_from_slice(&wrapped[..32]);
        Ok(k)
    }

    #[test]
    fn apply_sealed_grant_rejects_a_grant_past_its_expires_at() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret data", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let bundle = alice
            .grant_sealed(&oid, "bob", [0xbb; 32], [0xaa; 32], 0, Some(100), 50, fake_seal)
            .unwrap();

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        let obj = alice.objects.get(&oid).unwrap().clone();
        bob.objects.put(oid.clone(), obj);

        let result = bob.apply_sealed_grant(&bundle, [0xaa; 32], 100, fake_unseal);
        match &result {
            Err(RepoError::Expired(t)) => assert_eq!(*t, 100),
            other => panic!("expected Err(Expired(100)), got {other:?}"),
        }
        assert!(
            !bob.custody.keyring.holds(&oid),
            "an expired grant must install nothing"
        );
        assert!(
            bob.custody.manifest.grant_for(&oid, "bob").is_none(),
            "an expired grant must not even be recorded"
        );
    }

    #[test]
    fn apply_sealed_grant_accepts_a_grant_before_its_expires_at() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret data", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let bundle = alice
            .grant_sealed(&oid, "bob", [0xbb; 32], [0xaa; 32], 0, Some(100), 50, fake_seal)
            .unwrap();

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        let obj = alice.objects.get(&oid).unwrap().clone();
        bob.objects.put(oid.clone(), obj);

        bob.apply_sealed_grant(&bundle, [0xaa; 32], 99, fake_unseal)
            .unwrap();
        assert!(
            bob.custody.keyring.holds(&oid),
            "a not-yet-expired grant must file the key"
        );
        assert_eq!(bob.get(&oid, "bob", 99).unwrap(), b"secret data");
        assert_eq!(
            bob.custody.manifest.grant_for(&oid, "bob").unwrap().expires_at,
            Some(100)
        );
    }

    #[test]
    fn apply_sealed_grant_with_no_expires_at_behaves_as_before() {
        // The field is optional (#20): a grant that never sets expires_at must
        // behave exactly as it did before this feature existed.
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret data", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let bundle = alice
            .grant_sealed(&oid, "bob", [0xbb; 32], [0xaa; 32], 0, None, 50, fake_seal)
            .unwrap();

        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        let obj = alice.objects.get(&oid).unwrap().clone();
        bob.objects.put(oid.clone(), obj);

        bob.apply_sealed_grant(&bundle, [0xaa; 32], u64::MAX, fake_unseal)
            .unwrap();
        assert!(bob.custody.keyring.holds(&oid), "an unexpiring grant is never rejected");
    }

    fn surface_tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("loot-surface-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn surface_skips_a_path_whose_grant_has_expired() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into()]))
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])),
        );
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree })
            .unwrap();

        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(surface_tmp("expired"), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        // Bob holds the key directly and his own manifest records an already-
        // expired grant for it — the state `apply_sealed_grant` would have left
        // him in before `now` passed `expires_at`.
        let key = alice.custody.keyring.key_for(&oid).unwrap();
        bob.custody.keyring.insert(oid.clone(), key);
        bob.custody
            .manifest
            .record(oid.clone(), "bob".to_string(), [0u8; 32], [0u8; 32], 0, Some(100));

        let (written, skipped) = bob.surface_with_report(&change_id, "bob", 100).unwrap();
        assert!(written.is_empty(), "the expired path must not be materialized: {written:?}");
        assert_eq!(skipped, 1);
    }

    #[test]
    fn surface_keeps_a_path_whose_grant_has_not_yet_expired() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret", Visibility::Restricted(vec!["alice".into(), "bob".into()]))
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (oid.clone(), Visibility::Restricted(vec!["alice".into(), "bob".into()])),
        );
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree })
            .unwrap();

        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(surface_tmp("not-yet-expired"), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();
        let key = alice.custody.keyring.key_for(&oid).unwrap();
        bob.custody.keyring.insert(oid.clone(), key);
        bob.custody
            .manifest
            .record(oid.clone(), "bob".to_string(), [0u8; 32], [0u8; 32], 0, Some(100));

        let (written, skipped) = bob.surface_with_report(&change_id, "bob", 99).unwrap();
        assert_eq!(written.len(), 1, "not yet expired: the path must surface");
        assert_eq!(skipped, 0);
    }

    #[test]
    fn surface_ignores_expiry_check_when_no_grant_is_recorded() {
        // An owner reading their own content: no manifest entry for
        // (oid, "alice") was ever recorded (an owner doesn't grant to
        // themselves), so the miss must not read as an expiry no matter how
        // far `now` runs.
        let mut alice = DagRepo::init(surface_tmp("owner"), "alice").unwrap();
        let oid = alice
            .put(b"mine", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("m.txt"),
            (oid.clone(), Visibility::Restricted(vec!["alice".into()])),
        );
        let change_id = alice
            .record(Change { id: Oid([0; 32]), parents: vec![], message: "add".into(), tree })
            .unwrap();

        let (written, skipped) = alice.surface_with_report(&change_id, "alice", u64::MAX).unwrap();
        assert_eq!(written.len(), 1, "an owner's own content is unaffected by the expiry gate");
        assert_eq!(skipped, 0);
    }

    // --- forward maroon (ADR 0009/0010) ---

    #[test]
    fn forward_maroon_cuts_future_access() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(
                b"secret",
                Visibility::Restricted(vec!["alice".into(), "bob".into()]),
            )
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("secret.txt"),
            (
                oid.clone(),
                Visibility::Restricted(vec!["alice".into(), "bob".into()]),
            ),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add secret".into(),
                tree,
            })
            .unwrap();

        let result = alice.maroon(Path::new("secret.txt"), "bob", 0).unwrap();

        // The new oid is different (re-sealed without bob).
        assert_ne!(result.new_oid, oid, "re-sealed content must have new oid");

        // Alice can still read the new object.
        let plaintext = alice.get(&result.new_oid, "alice", 0).unwrap();
        assert_eq!(plaintext, b"secret");
    }

    #[test]
    fn forward_maroon_re_grants_remaining_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(
                b"secret",
                Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()]),
            )
            .unwrap();
        // Record grant of old oid to bob and carol so maroon can find them.
        // Carol's grant carries an expiry (#20) — the re-grant must preserve it.
        alice
            .custody
            .manifest
            .record(oid.clone(), "bob".to_string(), [0u8; 32], [0u8; 32], 1, None);
        alice.custody.manifest.record(
            oid.clone(),
            "carol".to_string(),
            [0u8; 32],
            [0u8; 32],
            1,
            Some(9_999),
        );
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (
                oid.clone(),
                Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()]),
            ),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        let result = alice.maroon(Path::new("s.txt"), "bob", 0).unwrap();

        // Carol should get a grant bundle (bob was marooned, carol remains).
        assert!(
            result.grants.iter().any(|(g, _)| g == "carol"),
            "carol must receive a re-grant bundle"
        );
        assert!(
            !result.grants.iter().any(|(g, _)| g == "bob"),
            "bob must not receive a re-grant bundle"
        );
        // The re-grant to carol must carry her original expiry forward (#20) —
        // a maroon must not accidentally un-expire a lapsing grant.
        assert_eq!(
            alice.custody.manifest.grant_for(&result.new_oid, "carol").and_then(|e| e.expires_at),
            Some(9_999),
            "carol's re-grant must preserve her original expires_at"
        );
    }

    #[test]
    fn forward_maroon_unknown_path_is_not_found() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.maroon(Path::new("nonexistent.txt"), "bob", 0);
        assert!(matches!(result, Err(RepoError::NotFound(_))));
    }

    #[test]
    fn forward_maroon_requires_keyholder() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"secret", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (oid.clone(), Visibility::Restricted(vec!["alice".into()])),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        let bundle = alice.bundle(&[]).unwrap();
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        bob.apply(&bundle, 0).unwrap();

        // Bob cannot maroon alice (he doesn't hold the key).
        let result = bob.maroon(Path::new("s.txt"), "alice", 0);
        assert!(matches!(result, Err(RepoError::Unauthorized(_))));
    }

    // --- hard maroon (ADR 0009) ---

    #[test]
    fn hard_maroon_purges_old_key_on_apply() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(
                b"secret",
                Visibility::Restricted(vec!["alice".into(), "bob".into()]),
            )
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (
                oid.clone(),
                Visibility::Restricted(vec!["alice".into(), "bob".into()]),
            ),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        // Give bob his own copy with the key.
        let mut bob = DagRepo::init(tmp(), "bob").unwrap();
        let init_bundle = alice.bundle(&[]).unwrap();
        bob.apply(&init_bundle, 0).unwrap();
        // Manually insert bob's key for testing purposes.
        let key = alice.custody.keyring.key_for(&oid).unwrap();
        bob.custody.keyring.insert(oid.clone(), key);
        assert!(
            bob.custody.keyring.holds(&oid),
            "bob should have the key before maroon"
        );

        // Alice hard-marooned bob.
        alice.maroon_hard(Path::new("s.txt"), "bob", 0).unwrap();

        // Alice ships a new bundle to bob (with the purge event).
        let purge_bundle = alice.bundle(&[]).unwrap();
        bob.apply(&purge_bundle, 0).unwrap();

        // Bob's old key should be purged.
        assert!(
            !bob.custody.keyring.holds(&oid),
            "bob's old key must be removed after hard maroon"
        );
    }

    #[test]
    fn hard_maroon_does_not_purge_other_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(
                b"secret",
                Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()]),
            )
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("s.txt"),
            (
                oid.clone(),
                Visibility::Restricted(vec!["alice".into(), "bob".into(), "carol".into()]),
            ),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        alice.maroon_hard(Path::new("s.txt"), "bob", 0).unwrap();
        let purge_bundle = alice.bundle(&[]).unwrap();

        // Carol applies — her key must NOT be removed (purge is only for bob).
        let mut carol = DagRepo::init(tmp(), "carol").unwrap();
        let init_bundle = alice.bundle(&[]).unwrap();
        carol.apply(&init_bundle, 0).unwrap();
        let key = alice.custody.keyring.key_for(&oid).unwrap();
        carol.custody.keyring.insert(oid.clone(), key);

        carol.apply(&purge_bundle, 0).unwrap();
        assert!(
            carol.custody.keyring.holds(&oid),
            "carol's key must NOT be purged"
        );
    }

    #[test]
    fn authored_maroon_reseal_travels_only_after_signing() {
        // The regression behind the section-B grant/maroon demo: in an AUTHORED
        // repo the maroon re-seal change is recorded authored-but-unsigned, so —
        // like any working change — its new object is NOT offered for push
        // (ADR 0018: only signed history travels). The CLI must finalize it via
        // the returned change_id, after which the re-seal propagates. (Keyless
        // repos are unaffected: their unauthored changes always travel, which is
        // why the older maroon tests above never caught this.)
        use ed25519_dalek::Signer;
        let (sk, pk) = test_signer(11);
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        alice.set_author(pk);
        let restricted = Visibility::Restricted(vec!["alice".into(), "bob".into()]);
        let oid = alice.put(b"secret", restricted.clone()).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("s.txt"), (oid, restricted));
        let add_id = alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();
        // Sign the finalize message (`version_id ‖ change_id`, ADR 0029), exactly
        // as the workspace does — an authored change now carries a minted change id.
        let add_cid = alice.change_change_id(&add_id);
        alice
            .attach_signature(
                &add_id,
                sk.sign(&change_signing_message(&add_id, &add_cid, &[]))
                    .to_bytes(),
            )
            .unwrap();

        let res = alice.maroon_hard(Path::new("s.txt"), "bob", 0).unwrap();
        assert!(
            !alice.offered_objects(&[]).contains(&res.new_oid),
            "an unsigned maroon re-seal must not be offered (it would strand on the originator)"
        );

        // Finalize exactly as `cmd_maroon` now does.
        let res_cid = alice.change_change_id(&res.change_id);
        alice
            .attach_signature(
                &res.change_id,
                sk.sign(&change_signing_message(&res.change_id, &res_cid, &[]))
                    .to_bytes(),
            )
            .unwrap();
        assert!(
            alice.offered_objects(&[]).contains(&res.new_oid),
            "after signing, the maroon re-seal must be offered so peers receive it"
        );
    }

    /// A deterministic ed25519 test keypair (seeded, no RNG needed). Duplicated
    /// from `engine::tests` (#323) — small and pure, cheaper to duplicate than
    /// to share across the two test modules.
    fn test_signer(seed: u8) -> (ed25519_dalek::SigningKey, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    // --- migrate (ADR 0010) ---

    #[test]
    fn migrate_restricted_to_public_drops_key_guard() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice
            .put(b"was secret", Visibility::Restricted(vec!["alice".into()]))
            .unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(
            PathBuf::from("f.txt"),
            (oid.clone(), Visibility::Restricted(vec!["alice".into()])),
        );
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        let result = alice
            .migrate(Path::new("f.txt"), Visibility::Public, 0)
            .unwrap();
        let new_oid = result.new_oid;

        // The re-sealed content should be readable by anyone holding the key.
        let plaintext = alice.get(&new_oid, "alice", 0).unwrap();
        assert_eq!(plaintext, b"was secret");
    }

    #[test]
    fn migrate_public_to_restricted_gates_access() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"now secret", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        let result = alice
            .migrate(
                Path::new("f.txt"),
                Visibility::Restricted(vec!["alice".into()]),
                0,
            )
            .unwrap();
        let new_oid = result.new_oid;

        // Alice can read.
        assert_eq!(alice.get(&new_oid, "alice", 0).unwrap(), b"now secret");
    }

    #[test]
    fn migrate_produces_grants_for_restricted_identities() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let oid = alice.put(b"data", Visibility::Public).unwrap();
        let mut tree = BTreeMap::new();
        tree.insert(PathBuf::from("f.txt"), (oid.clone(), Visibility::Public));
        alice
            .record(Change {
                id: Oid([0; 32]),
                parents: vec![],
                message: "add".into(),
                tree,
            })
            .unwrap();

        let result = alice
            .migrate(
                Path::new("f.txt"),
                Visibility::Restricted(vec!["alice".into(), "bob".into()]),
                0,
            )
            .unwrap();

        // bob should receive a grant bundle.
        assert!(
            result.grants.iter().any(|(g, _)| g == "bob"),
            "bob must receive a grant bundle"
        );
    }

    #[test]
    fn migrate_unknown_path_is_not_found() {
        let mut alice = DagRepo::init(tmp(), "alice").unwrap();
        let result = alice.migrate(Path::new("nonexistent.txt"), Visibility::Public, 0);
        assert!(matches!(result, Err(RepoError::NotFound(_))));
    }

    // --- golden-byte fixtures + major-rejection for the manifest/purges codecs
    // (ADR 0019) ---

    // manifest: one entry — oid=[1;32], grantee="bob", grantee_pubkey=[2;32],
    //           grantor_pubkey=[3;32], granted_at=42.
    // Layout: [major=1][minor=0][count=1 u32le][oid 32][put_bytes("bob")=7][grantee_pk 32][grantor_pk 32][granted_at u64le]
    const GOLDEN_MANIFEST_V1: [u8; 117] = [
        1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, // oid=[1;32]
        3, 0, 0, 0, 98, 111, 98, // put_bytes("bob")
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, // grantee_pk=[2;32]
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, // grantor_pk=[3;32]
        42, 0, 0, 0, 0, 0, 0, 0, // granted_at=42
    ];

    // purges: one entry — oid=[6;32], identity="eve".
    // Layout: [major=1][minor=0][count=1 u32le][oid 32][put_bytes("eve")=7]
    const GOLDEN_PURGES_V1: [u8; 45] = [
        1, 0, 1, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, // oid=[6;32]
        3, 0, 0, 0, 101, 118, 101, // put_bytes("eve")
    ];

    // v2 goldens (current format, FORMAT_MAJOR = 2, ADR 0020). These layouts are
    // unchanged from v1; only the marker byte differs.
    const GOLDEN_MANIFEST_V2: [u8; 117] = [
        2, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 3, 0, 0, 0, 98, 111, 98, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V2: [u8; 45] = [
        2, 0, 1, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 3, 0, 0, 0, 101, 118, 101,
    ];

    // v3 goldens (current format, FORMAT_MAJOR = 3, ADR 0018). None of these
    // artifacts contain changes, so their layouts are unchanged from v2 — only
    // the marker byte differs.
    const GOLDEN_MANIFEST_V3: [u8; 117] = [
        3, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 3, 0, 0, 0, 98, 111, 98, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V3: [u8; 45] = [
        3, 0, 1, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 3, 0, 0, 0, 101, 118, 101,
    ];

    // v4 goldens (FORMAT_MAJOR = 4). manifest/purges layouts unchanged in S4 —
    // only the marker.
    const GOLDEN_MANIFEST_V4: [u8; 117] = [
        4, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 3, 0, 0, 0, 98, 111, 98, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 42, 0, 0, 0, 0, 0, 0, 0,
    ];
    const GOLDEN_PURGES_V4: [u8; 45] = [
        4, 0, 1, 0, 0, 0, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
        6, 6, 6, 6, 6, 6, 6, 6, 3, 0, 0, 0, 101, 118, 101,
    ];

    fn sample_manifest() -> Manifest {
        let mut m = Manifest::new();
        m.record(Oid([1; 32]), "bob".to_string(), [2u8; 32], [3u8; 32], 42, None);
        m
    }

    #[test]
    fn v1_manifest_still_decodes() {
        // Layout unchanged since v1; a v2 build still reads a v1 manifest.
        let back = decode_manifest(&GOLDEN_MANIFEST_V1).unwrap();
        let entries = back.grants_for(&Oid([1; 32]));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].grantee, "bob");
        assert_eq!(entries[0].granted_at, 42);
    }

    #[test]
    fn v2_manifest_still_decodes() {
        assert_eq!(
            decode_manifest(&GOLDEN_MANIFEST_V2)
                .unwrap()
                .grants_for(&Oid([1; 32]))
                .len(),
            1
        );
    }

    #[test]
    fn v3_manifest_still_decodes() {
        assert_eq!(
            decode_manifest(&GOLDEN_MANIFEST_V3)
                .unwrap()
                .grants_for(&Oid([1; 32]))
                .len(),
            1
        );
    }

    #[test]
    fn v4_manifest_still_decodes() {
        // v5/v6/v7 durable manifest layouts stayed byte-identical to v4 apart
        // from the marker; v8 (#20) is the first layout change since v1 (an
        // appended optional expires_at) — a v8 reader still reads v4 bytes,
        // filling expires_at = None (never expires, the pre-#20 behavior).
        let back = decode_manifest(&GOLDEN_MANIFEST_V4).unwrap();
        let entries = back.grants_for(&Oid([1; 32]));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].expires_at, None);
    }

    #[test]
    fn golden_v8_manifest_matches_and_round_trips_without_expiry() {
        // v8 (#20) appends an expires_at presence byte (+ 8-byte value when
        // present) per entry — the first manifest layout change since v1. An
        // entry without expires_at costs exactly one extra zero byte over the
        // v4 layout.
        let mut expected = GOLDEN_MANIFEST_V4.to_vec();
        expected[0] = crate::format::FORMAT_MAJOR;
        expected.push(0); // expires_at presence = absent
        assert_eq!(
            encode_manifest(&sample_manifest()),
            expected,
            "v8 manifest layout (no expiry) must not drift"
        );
        let back = decode_manifest(&expected).unwrap();
        assert_eq!(back.grants_for(&Oid([1; 32]))[0].expires_at, None);
    }

    #[test]
    fn golden_v8_manifest_matches_and_round_trips_with_expiry() {
        let mut m = Manifest::new();
        m.record(
            Oid([1; 32]),
            "bob".to_string(),
            [2u8; 32],
            [3u8; 32],
            42,
            Some(0x0102_0304_0506_0708),
        );
        let mut expected = GOLDEN_MANIFEST_V4.to_vec();
        expected[0] = crate::format::FORMAT_MAJOR;
        expected.push(1); // expires_at presence = present
        expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(
            encode_manifest(&m),
            expected,
            "v8 manifest layout (with expiry) must not drift"
        );
        let back = decode_manifest(&expected).unwrap();
        assert_eq!(
            back.grants_for(&Oid([1; 32]))[0].expires_at,
            Some(0x0102_0304_0506_0708)
        );
    }

    #[test]
    fn v1_purges_still_decodes() {
        let back = decode_purges(&GOLDEN_PURGES_V1).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].0, Oid([6; 32]));
        assert_eq!(back[0].1, "eve");
    }

    #[test]
    fn v2_purges_still_decodes() {
        assert_eq!(decode_purges(&GOLDEN_PURGES_V2).unwrap().len(), 1);
    }

    #[test]
    fn v3_purges_still_decodes() {
        assert_eq!(decode_purges(&GOLDEN_PURGES_V3).unwrap().len(), 1);
    }

    #[test]
    fn golden_v4_purges_matches_and_round_trips() {
        let purges = vec![(Oid([6; 32]), "eve".to_string())];
        let mut golden_v5 = GOLDEN_PURGES_V4.to_vec();
        golden_v5[0] = crate::format::FORMAT_MAJOR;
        assert_eq!(
            encode_purges(&purges),
            golden_v5,
            "v5 purges layout must not drift"
        );
        assert_eq!(decode_purges(&GOLDEN_PURGES_V4).unwrap().len(), 1);
    }

    #[test]
    fn decode_manifest_rejects_incompatible_future_major() {
        let mut bytes = encode_manifest(&sample_manifest());
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_manifest(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }

    #[test]
    fn decode_purges_rejects_incompatible_future_major() {
        let mut bytes = encode_purges(&[(Oid([6; 32]), "eve".to_string())]);
        bytes[0] = crate::format::FORMAT_MAJOR + 1;
        assert!(matches!(
            decode_purges(&bytes),
            Err(RepoError::UnsupportedFormat { .. })
        ));
    }
}
