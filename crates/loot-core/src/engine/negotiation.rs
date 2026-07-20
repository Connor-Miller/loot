//! **Sync-negotiation face** (R3, #179; extracted to its own module by the
//! codebase-design review's candidate 4). The wire conversation — what we'd
//! offer, what we lack, and the batched bundles for a want set (S5/S6, ADR
//! 0021/0024). The 9-method [`Repo`](crate::Repo) trait is the narrow generic
//! face loot-net and the bench consume; this is its object-level negotiation
//! twin.
//!
//! These are `DagRepo` methods living in a child module of `engine`, so they
//! reach the engine's private object store, change graph, and custody exactly
//! as they did inline — a pure relocation (no interface or behaviour change),
//! the same shape as the Custody extraction (#323). `super::*` brings the
//! engine's types and helpers into scope.

use super::*;

impl DagRepo {
    /// [`Repo::apply`] with the caller's local abandoned set (#216): ingest
    /// classification consults the [`Liveness`](crate::Liveness) view, so an
    /// incoming co-version of a locally-abandoned version is not
    /// divergence-forming and classifies normally. This is the keyholder
    /// CLI's apply — the Workspace passes `.loot/abandoned` through; the
    /// bake-off trait's `apply` delegates here with the empty set.
    pub fn apply_with(
        &mut self,
        bundle: &SyncBundle,
        now: u64,
        abandoned: &std::collections::BTreeSet<Oid>,
    ) -> Result<BTreeMap<PathBuf, MergeOutcome>, RepoError> {
        // One decode, then dispatch on the typed frame. A relay would call `stow`
        // instead and skip the merge. Sealed-key grants (tag 3) need the caller's
        // unseal closure, so they go through `apply_sealed_grant`, not here.
        match Frame::decode(&bundle.0)? {
            Frame::Sync { purges, body } => self.apply_sync(purges, body, now, abandoned),
            Frame::Grant { grantee, body } => {
                let BundleBody { objs, keys, .. } = body;
                // Install objects and, if the grant is addressed to us, its keys.
                for (addr, obj) in objs {
                    let key = keys.get(&addr).copied();
                    // Store the object (may dedup). For grant bundles targeted to us,
                    // file the key directly into the keyring — dedup does not block key
                    // custody since the key is the grant payload, not derived from storage.
                    self.store(addr.clone(), obj, None);
                    if grantee == self.identity {
                        if let Some(k) = key {
                            if !self.custody.keyring.holds(&addr) {
                                self.custody.keyring.insert(addr, k);
                            }
                        }
                    }
                }
                Ok(BTreeMap::new())
            }
            Frame::SealedGrant { .. } => Err(RepoError::Backend(
                "sealed-key grant bundle (tag 3) must be applied via apply_sealed_grant".into(),
            )),
        }
    }

    /// Returns `true` if the repo has any authored-but-unsigned change (a working
    /// change the author has not yet signed). Such changes are excluded from
    /// bundles (ADR 0018), so a push while one exists silently transfers nothing.
    pub fn has_unsigned_tip(&self) -> bool {
        self.graph
            .in_order()
            .into_iter()
            .any(is_working_change)
    }

    /// Object addresses in the closure of the changes this repo would send for
    /// `have` — the objects a recipient may be missing (S5). Only addresses of
    /// objects we actually hold are offered. Zero-knowledge: addresses only,
    /// never keys or plaintext (the relay already sees content addresses).
    pub fn offered_objects(&self, have: &[Oid]) -> Vec<Oid> {
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let mut addrs: std::collections::BTreeSet<Oid> = std::collections::BTreeSet::new();
        for c in self.graph.in_order() {
            if have_set.contains(&c.id) || is_working_change(c) {
                continue;
            }
            for (oid, _vis) in c.tree.values() {
                if self.object(oid).is_ok() {
                    addrs.insert(oid.clone());
                }
            }
        }
        addrs.into_iter().collect()
    }

    /// The heads a pull should NEGOTIATE with (#217): heads whose own full
    /// tree's objects are all present locally. An interrupted batched pull
    /// (S6, ADR 0024) ingests change nodes before all their object bytes
    /// arrive; claiming such a head as `have` makes the relay skip the very
    /// changes whose objects we still lack — the pull could then never
    /// complete (offer returns nothing). Excluding incomplete heads makes the
    /// relay re-offer their closure, so re-pulling fetches exactly the
    /// remainder (change re-insertion is idempotent).
    pub fn negotiation_have(&self) -> Vec<Oid> {
        self.graph
            .heads()
            .into_iter()
            .filter(|h| self.closure_complete(h))
            .collect()
    }

    /// Whether this repo holds every object in `id`'s whole reachable CLOSURE,
    /// not just its own tree: batch order is address order, so a historical
    /// object of an ancestor can be the one still missing while the tip's tree
    /// happens to be whole. `false` means a transfer is still mid-flight (an
    /// interrupted pull ingested the change node before all its object bytes,
    /// S6/ADR 0024) — the working tree is not yet a materialization of `id`.
    pub fn closure_complete(&self, id: &Oid) -> bool {
        self.ancestors_of(id).iter().all(|a| {
            self.graph
                .tree_at(a)
                .values()
                .all(|(oid, _vis)| self.object(oid).is_ok())
        })
    }

    /// The subset of `offered` addresses this repo does NOT already hold — the
    /// "wants" a receiver replies with (S5).
    pub fn missing_objects(&self, offered: &[Oid]) -> Vec<Oid> {
        offered
            .iter()
            // A burned oid we lack is *deliberately* absent (ADR 0038): never
            // request it back, or a pull from a relay that still holds the bytes
            // would resurrect what we burned. `store` would refuse it anyway;
            // filtering here means we never even ask.
            .filter(|oid| self.object(oid).is_err() && !self.burn_log.contains(oid))
            .cloned()
            .collect()
    }

    /// A sync bundle for `have` whose object *bytes* are limited to `wants` (S5).
    /// Changes, keys, escrow, and attestations ride as in a normal bundle (they
    /// are tiny); only the negotiated object ciphertext is filtered, so a peer
    /// never re-downloads objects it already holds.
    pub fn bundle_wanted(&self, have: &[Oid], wants: &[Oid]) -> Result<SyncBundle, RepoError> {
        let wants_set: std::collections::BTreeSet<Oid> = wants.iter().cloned().collect();
        self.bundle_impl(have, Some(&wants_set))
    }

    /// Split `wants` into batches and produce one `SyncBundle` per batch (S6).
    ///
    /// The change delta, keys, escrow, and attestations are computed once via
    /// `bundle_impl`; only the object subset differs per batch. When `wants` is
    /// empty one bundle is returned (carrying the change delta and attestations
    /// with no object bytes) so the caller always makes at least one round-trip
    /// to propagate metadata.
    ///
    /// A batch closes at `batch_size` objects (resume granularity, ADR 0024) or
    /// when its object ciphertext would exceed `batch_bytes` (#309: a relay
    /// buffers the whole request body, so a batch must stay under its body
    /// limit). Byte accounting is ciphertext-only — the per-bundle change
    /// delta and framing ride on top, so callers pick `batch_bytes` with
    /// headroom below the transport limit. An object larger than the whole
    /// budget still ships, alone in its own bundle: the cap bounds packing,
    /// it never wedges a transfer.
    pub fn bundle_wanted_batched(
        &self,
        have: &[Oid],
        wants: &[Oid],
        batch_size: usize,
        batch_bytes: usize,
    ) -> Result<Vec<SyncBundle>, RepoError> {
        if wants.is_empty() {
            // One metadata-only bundle: change delta + attestations, no objects.
            return Ok(vec![self.bundle_impl(have, Some(&Default::default()))?]);
        }
        // Pre-partition objects across all batches in one pass over the wants list,
        // then build each bundle independently. This avoids iterating all_objects
        // once per batch (which would be O(total_objects × num_batches)).
        let mut batches: Vec<std::collections::BTreeSet<Oid>> = Vec::new();
        let mut cur: std::collections::BTreeSet<Oid> = Default::default();
        let mut cur_bytes = 0usize;
        for oid in wants {
            // An address we do not hold contributes no bytes; bundle_impl skips
            // it anyway, so it costs nothing to carry in a batch set.
            let size = self.object(oid).map(|o| o.ciphertext.len()).unwrap_or(0);
            if !cur.is_empty() && (cur.len() >= batch_size || cur_bytes + size > batch_bytes) {
                batches.push(std::mem::take(&mut cur));
                cur_bytes = 0;
            }
            cur.insert(oid.clone());
            cur_bytes += size;
        }
        if !cur.is_empty() {
            batches.push(cur);
        }
        batches
            .iter()
            .map(|batch_set| self.bundle_impl(have, Some(batch_set)))
            .collect()
    }

    /// Shared bundle builder. `wants = None` ships every referenced object;
    /// `wants = Some(set)` ships only those object *bytes* (S5 negotiation).
    /// `pub(crate)` because `bundle_full` in the engine proper (the parent
    /// module) still delegates here.
    pub(crate) fn bundle_impl(
        &self,
        have: &[Oid],
        wants: Option<&std::collections::BTreeSet<Oid>>,
    ) -> Result<SyncBundle, RepoError> {
        // Changes reachable here but not already known to the recipient. For
        // now, "reachable-not-have" = every change id not in `have`.
        let have_set: std::collections::BTreeSet<&Oid> = have.iter().collect();
        let send: Vec<&ChangeNode> = self
            .graph
            .in_order()
            .into_iter()
            // Skip changes the recipient has, and any authored-but-unsigned
            // working change: only finalized, signed history travels (ADR 0018).
            // Legacy unauthored changes still travel, so keyless repos are unaffected.
            .filter(|c| !have_set.contains(&c.id) && !is_working_change(c))
            .collect();

        // Ship SealedObjects (ciphertext, no keys) plus:
        //   - Public content keys -> plain keyring section (ANYONE-granted, not embargoed)
        //   - Embargoed content keys NEVER ride in a bundle (ADR 0027, v5): they
        //     reach peers only as relay-withheld timed SealedGrants after
        //     reveal_at. Ciphertext still syncs; the key lane is the relay.
        //   - Restricted keys NEVER travel (ADR 0003)
        let mut needed: BTreeMap<Oid, SealedObject> = BTreeMap::new();
        let mut public_keys: BTreeMap<Oid, ContentKey> = BTreeMap::new();
        for c in &send {
            for (oid, vis) in c.tree.values() {
                if let Ok(obj) = self.object(oid) {
                    // Object bytes: when negotiating (S5), ship only wanted addrs;
                    // keys below always ride (tiny, and a peer may hold the
                    // ciphertext but not the key).
                    if wants.map_or(true, |w| w.contains(oid)) {
                        needed.entry(oid.clone()).or_insert_with(|| obj.clone());
                    }
                    if obj.grant_ids.iter().any(|g| g == ANYONE)
                        && !matches!(vis, Visibility::Embargoed { .. })
                    {
                        if let Some(k) = self.custody.keyring.key_for(oid) {
                            public_keys.insert(oid.clone(), k);
                        }
                    }
                }
            }
        }

        // Only ship attestations for changes actually in this bundle's send set
        // (#42/#48). An attestation for a change the recipient is not receiving
        // would leak that change's existence and its reviewers, so attestations
        // ride strictly with their change.
        let sent_ids: std::collections::BTreeSet<&Oid> = send.iter().map(|c| &c.id).collect();
        let attestations: Vec<Attestation> = self
            .attestations
            .iter()
            .filter(|a| sent_ids.contains(&a.change_id))
            .cloned()
            .collect();

        let body = BundleBody {
            changes: send.into_iter().cloned().collect(),
            objs: needed,
            keys: public_keys,
            attestations,
        };
        Ok(SyncBundle(Frame::Sync { purges: self.custody.purges.clone(), body }.encode()))
    }
}
