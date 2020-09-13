//! Pure helpers for the git interop bridge (`loot ferry`, GB1, ADR 0028).
//!
//! Everything here is plumbing-free: commit-message trailers, deterministic
//! commit dates, and the line-oriented mark-map / sync-state codecs that live
//! under `.loot/git-mirror/`. The git2-driving sync pass lives in the CLI;
//! this module owns the formats so they have one testable home.

use crate::hex;
use crate::Oid;
use std::collections::BTreeMap;

/// Trailer key carrying the loot change id on a mirrored commit. A commit with
/// this trailer maps straight back to its change (lossless round-trip).
pub const TRAILER_CHANGE_ID: &str = "Loot-Change-Id";
/// Trailer key carrying the author pubkey (hex) of an authored change.
pub const TRAILER_AUTHOR: &str = "Loot-Author";
/// Trailer key carrying the author's signature (hex) over the change id.
pub const TRAILER_SIGNATURE: &str = "Loot-Signature";
/// Trailer key preserving the original git author on an ingested git-native
/// commit that did not resolve to the syncing identity (ADR 0028).
pub const TRAILER_GIT_AUTHOR: &str = "Git-Author";
/// Trailer marking a projected *unfinalized* working change on a `review/*`
/// branch (map #148). A provisional commit carries no `Loot-Signature` — the
/// missing signature is the machine-checkable "not finalized" marker — and it
/// never enters the round-trip: ingest refuses it, mark rebuilds skip it.
pub const TRAILER_PROVISIONAL: &str = "Loot-Provisional";
/// Trailer key carrying the version ids a change supersedes (ADR 0032/0033),
/// space-separated hex. Present only on an amend's projected commit — a
/// faithful echo of loot's `predecessors` for lossless round-trip. Projection
/// and the mark-map rebuild both read supersession from loot's graph, never
/// this trailer (`Loot-Change-Id` still carries the version id the rebuild
/// keys on); it is faithfulness, not mechanism.
pub const TRAILER_PREDECESSORS: &str = "Loot-Predecessors";

/// Base of the deterministic commit-date scheme (loot changes carry no
/// timestamp, ADR 0028): committer = author date = `BASE_EPOCH + generation`,
/// where generation is the change's ancestor depth. Reproducible and
/// ancestry-respecting for `git log --date-order`; siblings may share a date.
pub const BASE_EPOCH: i64 = 1_600_000_000;

/// The deterministic unix timestamp for a change at ancestor depth `generation`.
pub fn commit_timestamp(generation: u64) -> i64 {
    BASE_EPOCH + generation as i64
}

/// Append `trailers` to `message` as a git trailer block (a final paragraph of
/// `Key: value` lines). A message that already ends in a trailer block gets the
/// new lines appended to it.
pub fn append_trailers(message: &str, trailers: &[(&str, String)]) -> String {
    let mut out = message.trim_end().to_string();
    if trailers.is_empty() {
        return out;
    }
    out.push_str(if ends_in_trailer_block(&out) { "\n" } else { "\n\n" });
    for (i, (key, value)) in trailers.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(key);
        out.push_str(": ");
        out.push_str(value);
    }
    out
}

/// The value of trailer `key` in `message`'s final trailer block, if present.
pub fn parse_trailer(message: &str, key: &str) -> Option<String> {
    for line in trailer_block(message) {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// `message` with its final trailer block (and the blank line before it)
/// removed — the original change message of a mirrored commit.
pub fn strip_trailers(message: &str) -> String {
    let trimmed = message.trim_end();
    let block_len: usize = trailer_block(trimmed).len();
    if block_len == 0 {
        return trimmed.to_string();
    }
    let mut lines: Vec<&str> = trimmed.lines().collect();
    lines.truncate(lines.len() - block_len);
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// The lines of `message`'s final trailer block: the last paragraph, if every
/// line in it looks like `Key: value`. Empty when the message has no trailers.
fn trailer_block(message: &str) -> Vec<&str> {
    let trimmed = message.trim_end();
    let last_paragraph: Vec<&str> = trimmed
        .lines()
        .rev()
        .take_while(|l| !l.trim().is_empty())
        .collect();
    // There must be a paragraph break (or nothing) above the block, and a
    // single-paragraph message is all body, not all trailers, unless every
    // line is a trailer AND it's not the only content... git treats a
    // lone-paragraph message as having no trailers only when it's the subject;
    // we require at least one trailer-shaped line and all lines trailer-shaped.
    if last_paragraph.is_empty() || !last_paragraph.iter().all(|l| is_trailer_line(l)) {
        return Vec::new();
    }
    // The subject line alone is never a trailer block, even if it contains ':'.
    if trimmed.lines().count() == last_paragraph.len() {
        return Vec::new();
    }
    last_paragraph.into_iter().rev().collect()
}

fn ends_in_trailer_block(message: &str) -> bool {
    !trailer_block(message).is_empty()
}

fn is_trailer_line(line: &str) -> bool {
    match line.split_once(':') {
        Some((key, _)) => {
            !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-')
        }
        None => false,
    }
}

/// Where a mark's object originated (ADR 0028): a `Loot` mark is a change the
/// bridge projected into git; a `Git` mark is a git-native commit the bridge
/// ingested into loot. A git-native change is never re-emitted to git.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkOrigin {
    Loot,
    Git,
}

/// The sha ↔ change-id ↔ origin map — the bridge's spine. Line-oriented
/// (`<sha> <change-id-hex> <loot|git>`), local-only under `.loot/git-mirror/`,
/// rebuildable from `Loot-Change-Id` trailers if lost.
#[derive(Default)]
pub struct MarkMap {
    by_sha: BTreeMap<String, (Oid, MarkOrigin)>,
    by_change: BTreeMap<Oid, String>,
}

impl MarkMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse the on-disk encoding. Malformed lines are an error, not a skip —
    /// a half-read mark map would silently re-project or re-ingest.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut map = Self::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (sha, id_hex, origin) = match (parts.next(), parts.next(), parts.next()) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => return Err(format!("marks line {}: expected `<sha> <change-id> <origin>`", n + 1)),
            };
            let origin = match origin {
                "loot" => MarkOrigin::Loot,
                "git" => MarkOrigin::Git,
                other => return Err(format!("marks line {}: unknown origin '{other}'", n + 1)),
            };
            let id = parse_oid_hex(id_hex)
                .ok_or_else(|| format!("marks line {}: bad change id", n + 1))?;
            map.insert(sha.to_string(), id, origin);
        }
        Ok(map)
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        for (sha, (id, origin)) in &self.by_sha {
            out.push_str(sha);
            out.push(' ');
            out.push_str(&hex::encode(&id.0));
            out.push(' ');
            out.push_str(match origin {
                MarkOrigin::Loot => "loot",
                MarkOrigin::Git => "git",
            });
            out.push('\n');
        }
        out
    }

    pub fn insert(&mut self, sha: String, id: Oid, origin: MarkOrigin) {
        self.by_change.insert(id.clone(), sha.clone());
        self.by_sha.insert(sha, (id, origin));
    }

    pub fn change_for(&self, sha: &str) -> Option<&(Oid, MarkOrigin)> {
        self.by_sha.get(sha)
    }

    pub fn sha_for(&self, id: &Oid) -> Option<&str> {
        self.by_change.get(id).map(String::as_str)
    }

    pub fn contains_sha(&self, sha: &str) -> bool {
        self.by_sha.contains_key(sha)
    }

    pub fn len(&self) -> usize {
        self.by_sha.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_sha.is_empty()
    }

    pub fn shas(&self) -> impl Iterator<Item = &str> {
        self.by_sha.keys().map(String::as_str)
    }

    pub fn change_ids(&self) -> impl Iterator<Item = &Oid> {
        self.by_change.keys()
    }
}

/// The last-synced pointers (ADR 0028): where the two sides last agreed.
/// Divergence = both sides advanced past these. Line-oriented beside the marks.
#[derive(Default, Clone)]
pub struct FerryState {
    /// The mirrored git branch's tip sha at last agreement.
    pub git_main: Option<String>,
    /// The loot heads at last agreement.
    pub loot_heads: Vec<Oid>,
}

impl FerryState {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut state = Self::default();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match line.split_once(' ') {
                Some(("git-main", sha)) => state.git_main = Some(sha.trim().to_string()),
                Some(("loot-head", id_hex)) => {
                    let id = parse_oid_hex(id_hex.trim())
                        .ok_or_else(|| format!("state line {}: bad change id", n + 1))?;
                    state.loot_heads.push(id);
                }
                _ => return Err(format!("state line {}: unknown entry", n + 1)),
            }
        }
        Ok(state)
    }

    pub fn encode(&self) -> String {
        let mut out = String::new();
        if let Some(sha) = &self.git_main {
            out.push_str("git-main ");
            out.push_str(sha);
            out.push('\n');
        }
        for id in &self.loot_heads {
            out.push_str("loot-head ");
            out.push_str(&hex::encode(&id.0));
            out.push('\n');
        }
        out
    }
}

/// Parse a 64-char hex change id. `None` on any malformation.
pub fn parse_oid_hex(s: &str) -> Option<Oid> {
    hex::decode_array::<32>(s).map(Oid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailers_round_trip() {
        let msg = "fix the flux capacitor\n\nlonger body text";
        let id_hex = "ab".repeat(32);
        let out = append_trailers(msg, &[
            (TRAILER_CHANGE_ID, id_hex.clone()),
            (TRAILER_AUTHOR, "cd".repeat(32)),
        ]);
        assert_eq!(parse_trailer(&out, TRAILER_CHANGE_ID), Some(id_hex));
        assert_eq!(parse_trailer(&out, TRAILER_AUTHOR), Some("cd".repeat(32)));
        assert_eq!(parse_trailer(&out, TRAILER_SIGNATURE), None);
        assert_eq!(strip_trailers(&out), msg);
    }

    #[test]
    fn predecessors_trailer_round_trips_space_separated() {
        let msg = "amend the flux capacitor\n\nbody";
        let preds = format!("{} {}", "12".repeat(32), "34".repeat(32));
        let out = append_trailers(msg, &[
            (TRAILER_CHANGE_ID, "ab".repeat(32)),
            (TRAILER_SIGNATURE, "cd".repeat(64)),
            (TRAILER_PREDECESSORS, preds.clone()),
        ]);
        assert_eq!(parse_trailer(&out, TRAILER_PREDECESSORS), Some(preds));
        // A space-separated value does not disturb the neighbouring trailers.
        assert_eq!(parse_trailer(&out, TRAILER_CHANGE_ID), Some("ab".repeat(32)));
        assert_eq!(strip_trailers(&out), msg);
    }

    #[test]
    fn subject_only_message_gains_and_sheds_trailers() {
        let out = append_trailers("subject", &[(TRAILER_CHANGE_ID, "ef".repeat(32))]);
        assert_eq!(out, format!("subject\n\n{}: {}", TRAILER_CHANGE_ID, "ef".repeat(32)));
        assert_eq!(strip_trailers(&out), "subject");
    }

    #[test]
    fn subject_with_colon_is_not_a_trailer() {
        // A lone-paragraph message never parses as a trailer block.
        let msg = "fix: the thing";
        assert_eq!(parse_trailer(msg, "fix"), None);
        assert_eq!(strip_trailers(msg), msg);
    }

    #[test]
    fn appending_to_an_existing_block_extends_it() {
        let one = append_trailers("subject", &[(TRAILER_CHANGE_ID, "11".repeat(32))]);
        let two = append_trailers(&one, &[(TRAILER_GIT_AUTHOR, "Ada <ada@x>".into())]);
        assert_eq!(parse_trailer(&two, TRAILER_CHANGE_ID), Some("11".repeat(32)));
        assert_eq!(parse_trailer(&two, TRAILER_GIT_AUTHOR), Some("Ada <ada@x>".into()));
        assert_eq!(strip_trailers(&two), "subject");
    }

    #[test]
    fn commit_dates_are_deterministic_and_ancestry_respecting() {
        assert_eq!(commit_timestamp(0), BASE_EPOCH);
        assert!(commit_timestamp(3) > commit_timestamp(2));
    }

    #[test]
    fn mark_map_round_trips() {
        let mut map = MarkMap::new();
        map.insert("a".repeat(40), Oid([1; 32]), MarkOrigin::Loot);
        map.insert("b".repeat(40), Oid([2; 32]), MarkOrigin::Git);
        let parsed = MarkMap::parse(&map.encode()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.change_for(&"a".repeat(40)), Some(&(Oid([1; 32]), MarkOrigin::Loot)));
        assert_eq!(parsed.change_for(&"b".repeat(40)), Some(&(Oid([2; 32]), MarkOrigin::Git)));
        assert_eq!(parsed.sha_for(&Oid([1; 32])), Some("a".repeat(40).as_str()));
    }

    #[test]
    fn mark_map_rejects_malformed_lines() {
        assert!(MarkMap::parse("justonesha\n").is_err());
        assert!(MarkMap::parse(&format!("{} {} elsewhere\n", "a".repeat(40), "11".repeat(32))).is_err());
        assert!(MarkMap::parse(&format!("{} nothex loot\n", "a".repeat(40))).is_err());
    }

    #[test]
    fn ferry_state_round_trips() {
        let state = FerryState {
            git_main: Some("c".repeat(40)),
            loot_heads: vec![Oid([3; 32]), Oid([4; 32])],
        };
        let parsed = FerryState::parse(&state.encode()).unwrap();
        assert_eq!(parsed.git_main, Some("c".repeat(40)));
        assert_eq!(parsed.loot_heads, vec![Oid([3; 32]), Oid([4; 32])]);
        let empty = FerryState::parse("").unwrap();
        assert_eq!(empty.git_main, None);
        assert!(empty.loot_heads.is_empty());
    }
}
