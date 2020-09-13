//! loot-codec: the no-fs, wasm-buildable core.
//!
//! The byte format ([`format`]), sync-bundle wire codec ([`bundle_codec`]),
//! sealed content ([`sealed`], AES-GCM + blake3 addressing), detachable
//! attestations ([`attestation`]), and the leaf value types they share
//! ([`Oid`], [`Visibility`], [`RepoError`], [`ChangeNode`]).
//!
//! Extracted from `loot-core` so this core compiles to `wasm32-unknown-unknown`
//! for the in-memory TypeScript SDK (the crypto/codec that must stay
//! bit-identical to the binary — ADR: TS SDK bridging). `loot-core` re-exports
//! every item here at its original path, so nothing downstream moved.
//!
//! zstd (a C library that will not build for `wasm32`) lives behind the default
//! `zstd` feature: the native host enables it; the wasm wrapper builds with
//! `default-features = false` and does public-content decompression host-side.

use std::collections::BTreeMap;
use std::path::PathBuf;

pub mod attestation;
pub mod bundle_codec;
pub mod change_id;
pub mod format;
pub mod key_seal;
pub mod sealed;

pub use attestation::{Attestation, AttestationLog};

/// Content identity. A stable handle to a unit of content, independent of
/// where (or whether) it is currently materialized on disk.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub [u8; 32]);

/// Who may read a unit of content. The whole product thesis lives here:
/// visibility is a property of the *content*, not the repo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    /// Readable by anyone with repo access — plaintext, but not the anonymous
    /// world. Renamed from `Public` (ADR 0041): the forge reserves "Published"
    /// for the world-readable tier, so this identity-plaintext tier is `Internal`.
    Internal,
    /// Readable only by the listed identities (by key id).
    Restricted(Vec<String>),
    /// Encrypted to all, but the decryption key is withheld until `reveal_at`
    /// (unix seconds). Models embargoed security fixes / delayed-reveal merges.
    Embargoed { reveal_at: u64 },
}

/// A node in the change DAG: change identity, parent/child shape, and the full
/// path→address manifest. Pure data — the graph algorithms that operate on it
/// (head tracking, tree derivation, the change-id fold) stay in `loot-core`'s
/// engine; only the shape the wire codec reads/writes lives here.
#[derive(Clone)]
pub struct ChangeNode {
    /// The **version id** (ADR 0029/0032): `compute_change_id(author ‖ message
    /// ‖ parents ‖ tree ‖ predecessors)`. Content-and-author-derived, so it
    /// rewrites on every snapshot; carries dedup, DAG parent edges, and sync
    /// addressing.
    pub id: Oid,
    pub parents: Vec<Oid>,
    pub message: String,
    pub tree: BTreeMap<PathBuf, (Oid, Visibility)>,
    /// The author's ed25519 public key (S3, ADR 0018). `Some` for authored
    /// changes — the pubkey is folded into `id`, so authorship is intrinsic.
    /// `None` for legacy/unauthored changes read under an older format version.
    pub author: Option<[u8; 32]>,
    /// The author's signature over the finalize message (`version_id ‖
    /// change_id`, ADR 0029; just `version_id` for a legacy change whose
    /// `change_id` is `None`), attached at finalization (`loot new`). `None` for
    /// an in-progress working change, or a legacy/unauthored change.
    pub signature: Option<[u8; 64]>,
    /// The **change id** (v6, ADR 0029): a random 16-byte durable handle minted
    /// when the change begins and carried unchanged across every re-snapshot, so
    /// a working change has a stable name *while you edit it*. Never folded into
    /// `id` — it is a label, not a graph edge. `None` for a legacy (pre-v6) or
    /// unauthored change.
    pub change_id: Option<[u8; 16]>,
    /// The version ids this version **supersedes** (v7, ADR 0032). Empty for an
    /// ordinary change and for legacy/unauthored/bridge nodes. Canonically
    /// sorted (see `canonical_predecessors` in the engine).
    pub predecessors: Vec<Oid>,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("object not found: {0:?}")]
    NotFound(Oid),
    #[error("not authorized to read {0:?}")]
    Unauthorized(Oid),
    #[error("content still embargoed until {0}")]
    Embargoed(u64),
    /// A grant whose `expires_at` has already passed as of the applying
    /// clock (#20). Parallel to `Embargoed`, but the other direction in time
    /// and a harder stop: an embargoed key merely isn't visible *yet* (it
    /// still stages), whereas an expired grant is rejected outright —
    /// `apply_sealed_grant` installs nothing for it.
    #[error("grant expired at {0}")]
    Expired(u64),
    #[error("unsupported format version v{found} — upgrade loot (this build reads up to v{supported})")]
    UnsupportedFormat { found: u8, supported: u8 },
    #[error("change {0:?} has a missing or invalid author signature")]
    BadChangeSignature(Oid),
    /// A snapshot would re-seal one or more paths *more readably* than the tree
    /// already records (#62, ADR 0030). A typed, matchable outcome carrying the
    /// offending paths so a driver can classify the abort (rather than scrape a
    /// prose string) and re-run with `--allow-demote` for the ones it intends.
    #[error("refusing to demote visibility of {}: an attributes change would re-seal private content more readably; restore the .lootattributes rule, or re-run with `--allow-demote <path>` to demote deliberately", .paths.join(", "))]
    Demotion { paths: Vec<String> },
    /// The mis-seal gate (#63, ADR 0038 §1): a secret-shaped path is being
    /// sealed public for the first time, but resolves Public only by
    /// *fallthrough* — no `.lootattributes` rule names it, so the default (or a
    /// catch-all glob) is what makes it readable. The sibling of `Demotion`: a
    /// typed, matchable refusal carrying the offending paths so a driver can
    /// classify the abort rather than scrape prose, overridable per-path with
    /// `--allow-reveal`. Content is never inspected — only the name and the
    /// resolution provenance.
    #[error("refusing to seal {} publicly: it matches a built-in secret-shaped name and resolves Public only by fallthrough (no .lootattributes rule names it). Name it in .lootattributes — `<path> restricted=<id>` to seal it, or `<path> public` to consent — or re-run with `--allow-reveal <path>` to seal it public deliberately", .paths.join(", "))]
    MisSeal { paths: Vec<String> },
    /// The seal-WIP guard (#418, map #354; ADR 0039). A **bare sync verb** —
    /// plain `loot ferry` (not `--with-wip`, which is a pure review projection)
    /// or no-arg `loot adopt` (the catch-up merge arm) — is about to fold the
    /// ambient position's live **described** working change into signed
    /// history, stranding it as a PR-less line no review ever saw. The sibling
    /// of `MisSeal`/`Demotion`: a typed, matchable refusal mirroring the ADR
    /// 0030/0038 guard+override pattern, overridable with `--seal-wip`. Unlike
    /// the mis-seal gate this is not per-path — the whole described line is
    /// what would become PR-less — so it carries the change's subject, not a
    /// path list. `verb` names the bare sync verb that tripped it.
    #[error("refusing to finalize your described working change \"{subject}\": a bare `{verb}` would fold it onto `main` with no review — no PR would ever carry it, and it lands PR-less. Land it through review instead (`loot-first review` then `loot-first land`), or re-run with `--seal-wip` to seal it here deliberately", subject = .subject, verb = .verb)]
    SealWip { subject: String, verb: String },
    #[error("backend error: {0}")]
    Backend(String),
}

impl RepoError {
    /// A stable, machine-readable slug per variant — the source of truth for the
    /// CLI's `--json` error channel (#430). The binary emits this as
    /// `{"error":{"code":…}}` on stderr so a subprocess consumer (the physical
    /// SDK adapter) reads the taxonomy as **data** instead of regex-matching the
    /// prose. Versioned with `FORMAT_MAJOR` like the other ADR-0023 machine
    /// contracts: these slugs are part of the wire and must not drift silently.
    /// Each arm is spelled out (no `_` catch-all) so a new variant fails to
    /// compile until it is given a slug.
    pub fn code(&self) -> &'static str {
        match self {
            RepoError::NotFound(_) => "not_found",
            RepoError::Unauthorized(_) => "unauthorized",
            RepoError::Embargoed(_) => "embargoed",
            RepoError::Expired(_) => "expired",
            RepoError::UnsupportedFormat { .. } => "unsupported_format",
            RepoError::BadChangeSignature(_) => "bad_signature",
            RepoError::Demotion { .. } => "demotion",
            RepoError::MisSeal { .. } => "mis_seal",
            RepoError::SealWip { .. } => "seal_wip",
            RepoError::Backend(_) => "backend",
        }
    }
}

#[cfg(test)]
mod repo_error_code_tests {
    use super::*;

    /// Every variant maps to its stable slug (#430). This is the source of truth
    /// for the CLI's machine error channel; a slug change here is a wire change.
    #[test]
    fn code_is_a_stable_slug_per_variant() {
        let oid = Oid([0u8; 32]);
        assert_eq!(RepoError::NotFound(oid.clone()).code(), "not_found");
        assert_eq!(RepoError::Unauthorized(oid.clone()).code(), "unauthorized");
        assert_eq!(RepoError::Embargoed(42).code(), "embargoed");
        assert_eq!(RepoError::Expired(42).code(), "expired");
        assert_eq!(
            RepoError::UnsupportedFormat { found: 9, supported: 8 }.code(),
            "unsupported_format"
        );
        assert_eq!(RepoError::BadChangeSignature(oid).code(), "bad_signature");
        assert_eq!(RepoError::Demotion { paths: vec![".env".into()] }.code(), "demotion");
        assert_eq!(RepoError::MisSeal { paths: vec![".env".into()] }.code(), "mis_seal");
        assert_eq!(
            RepoError::SealWip { subject: "x".into(), verb: "ferry".into() }.code(),
            "seal_wip"
        );
        assert_eq!(RepoError::Backend("io".into()).code(), "backend");
    }
}
