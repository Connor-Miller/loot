//! Visibility policy — the user-facing surface of loot's thesis (CONTEXT.md).
//!
//! One home for the `.lootattributes` / `.lootignore` machinery that decides,
//! per path, the visibility a snapshot seals it under and whether it is
//! snapshotted at all: the shared glob dialect (`*` stops at `/`, `**` crosses
//! it), the ordered attribute rules, the ignore globs, and the ADR 0038 §1
//! mis-seal gate's secret-shaped name set + fallthrough-consent test. Lifted
//! out of `workspace.rs` (candidate 3, the codebase-design review) so the
//! thesis surface has locality and its dialect edge-cases are testable through
//! one interface. `Workspace` reads `.lootattributes`/`.lootignore` and
//! consults these at snapshot and at the signing seams; the engine only ever
//! receives already-resolved visibilities.

use loot_core::Visibility;
use std::path::Path;

/// The policy filenames (#62): versioned like any other path so the rules
/// travel to peers and clones, and never themselves ignorable.
pub(crate) const ATTRS: &str = ".lootattributes";
pub(crate) const IGNORE: &str = ".lootignore";

/// Parsed `.lootignore` (#64): ordered globs excluding paths from snapshot,
/// in the same dialect as `.lootattributes` (full relative path, `*` stops at
/// `/`, `**` crosses it — see `Glob`). A trailing `/` ignores the whole
/// subtree (`target/` ≡ `target/**`). One pattern per line; `#` comments.
///
/// Semantics: an ignored path simply isn't part of the tree the engine
/// reconciles — if it was previously snapshotted and is readable, the next
/// snapshot records its deletion (which is the remedy for a mis-sealed
/// `target/`: add the ignore line, run `loot status`, the working change
/// drops it). The policy files themselves (`.lootattributes`, `.lootignore`)
/// are never ignorable — like #62, policy must stay versioned and travel.
pub(crate) struct Ignore {
    globs: Vec<Glob>,
}

impl Ignore {
    pub(crate) fn load(path: &Path) -> Self {
        Self::parse(&std::fs::read_to_string(path).unwrap_or_default())
    }

    pub(crate) fn parse(text: &str) -> Self {
        let mut globs = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(subtree) = line.strip_suffix('/') {
                globs.push(Glob::new(&format!("{subtree}/**")));
            } else {
                globs.push(Glob::new(line));
            }
        }
        Ignore { globs }
    }

    pub(crate) fn ignores_file(&self, rel: &str) -> bool {
        let unix = rel.replace('\\', "/");
        if unix == ATTRS || unix == IGNORE {
            return false;
        }
        self.globs.iter().any(|g| g.matches(&unix))
    }

    /// A directory is pruned when every possible descendant is ignored. That
    /// is provable only for subtree globs (`…/**`): strip the suffix and match
    /// the prefix against the dir. File globs (`target/*.o`) never prune —
    /// deeper non-matching descendants may exist — their files are still
    /// excluded one-by-one in `ignores_file`.
    pub(crate) fn ignores_dir(&self, rel: &str) -> bool {
        let unix = rel.replace('\\', "/");
        self.globs
            .iter()
            .any(|g| g.pattern.strip_suffix("/**").is_some_and(|prefix| glob_match(prefix, &unix)))
    }
}

/// Parsed `.lootattributes`: ordered (glob, visibility) rules. First match wins;
/// unmatched paths default to Public.
pub(crate) struct Attributes {
    rules: Vec<(Glob, Visibility)>,
}

impl Attributes {
    pub(crate) fn load(path: &Path) -> Self {
        Self::parse(&std::fs::read_to_string(path).unwrap_or_default())
    }

    pub(crate) fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(pat), Some(spec)) = (parts.next(), parts.next()) else {
                continue;
            };
            if let Some(vis) = parse_visibility(spec) {
                rules.push((Glob::new(pat), vis));
            }
        }
        Attributes { rules }
    }

    pub(crate) fn visibility_for(&self, path: &str) -> Visibility {
        for (glob, vis) in &self.rules {
            if glob.matches(path) {
                return vis.clone();
            }
        }
        Visibility::Public
    }

    /// Does `path` resolve **Public via fallthrough** — the default (no rule
    /// matched) or a catch-all glob — rather than an explicit rule naming it?
    /// This is the mis-seal gate's consent test (#63, ADR 0038 §1): an explicit
    /// rule that names the path public is deliberate consent; falling through a
    /// dropped/typo'd rule to the public default (or through a `* public`
    /// catch-all every real repo wants) is the accident the gate catches. A
    /// non-Public resolution is never a fallthrough-public (it is not public at
    /// all), so the gate leaves restricted/embargoed paths alone.
    pub(crate) fn public_by_fallthrough(&self, path: &str) -> bool {
        for (glob, vis) in &self.rules {
            if glob.matches(path) {
                // First matching rule wins. It is a fallthrough only when it is
                // a catch-all *and* resolves Public; an explicit (named) rule is
                // consent, and any non-Public rule is not a public seal at all.
                return is_catchall(&glob.pattern) && matches!(vis, Visibility::Public);
            }
        }
        // No rule matched: the default Public — the plainest fallthrough.
        true
    }
}

/// Is a glob a **catch-all** — a pattern made only of wildcards and separators
/// (`*`, `**`, `**/*`, `*/**`), with no literal segment that ties it to a name?
/// The mis-seal gate treats a catch-all `* public` like the bare default: it
/// waves every path through, so a secret riding it is a fallthrough, not
/// consent (ADR 0038 §1 — "a catch-all rule, which every real repo wants,
/// waves the typo'd-rule case straight through"). Any literal character
/// (`*.pem`, `id_*`, `.env*`) makes the rule an explicit naming.
pub(crate) fn is_catchall(pattern: &str) -> bool {
    !pattern.is_empty() && pattern.chars().all(|c| c == '*' || c == '/')
}

/// The built-in **secret-shaped name set** (#63, ADR 0038 §1): file *basenames*
/// that look like credentials — matched anywhere in the tree, case-insensitively
/// (secrets do not care about case, and the gate fails closed). The gate refuses
/// a first-time *public-by-fallthrough* seal of any path whose basename matches;
/// it never inspects content. The exact set lives here, as the ADR defers it to
/// the implementation. We pick precise SSH key names over the ADR's illustrative
/// broad `id_*` to avoid false-positives on ordinary source files (`id_map.rs`),
/// while keeping the `.env*` / `*.pem` / `*.key` / `*credentials*` families it
/// names.
const SECRET_NAMES: &[&str] = &[
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "*.jks",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*credentials*",
    ".npmrc",
    ".pgpass",
    ".htpasswd",
];

/// True when `rel`'s **basename** matches a [`SECRET_NAMES`] pattern — a
/// secret-shaped file anywhere in the tree (#63, ADR 0038 §1). Basename, not
/// full path, so a nested `config/.env` is caught while a root-anchored glob
/// would miss it. Case-insensitive.
pub(crate) fn is_secret_name(rel: &Path) -> bool {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    SECRET_NAMES.iter().any(|pat| glob_match(pat, &lower))
}

fn parse_visibility(spec: &str) -> Option<Visibility> {
    if spec == "public" {
        Some(Visibility::Public)
    } else if let Some(ids) = spec.strip_prefix("restricted=") {
        let ids: Vec<String> = ids.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        if ids.is_empty() {
            None
        } else {
            Some(Visibility::Restricted(ids))
        }
    } else if let Some(reveal) = spec.strip_prefix("embargoed=") {
        reveal.parse().ok().map(|reveal_at| Visibility::Embargoed { reveal_at })
    } else {
        None
    }
}

/// Minimal glob: `*` matches a run of non-`/`; `**` matches across separators.
/// Patterns and paths are both normalized to `/` before matching — snapshot
/// hands over OS-native paths (`docs\private\x` on Windows), and a portable
/// rule like `docs/private/*` that silently fails to match seals content
/// **Public**: fail-open, the worst failure mode for a privacy-first VCS (#61).
pub(crate) struct Glob {
    pattern: String,
}

impl Glob {
    pub(crate) fn new(pattern: &str) -> Self {
        Glob { pattern: pattern.replace('\\', "/") }
    }
    pub(crate) fn matches(&self, path: &str) -> bool {
        glob_match(&self.pattern, &path.replace('\\', "/"))
    }
}

pub(crate) fn glob_match(pat: &str, text: &str) -> bool {
    let p: Vec<char> = pat.chars().collect();
    let t: Vec<char> = text.chars().collect();
    fn go(p: &[char], t: &[char]) -> bool {
        if p.is_empty() {
            return t.is_empty();
        }
        if p[0] == '*' {
            let double = p.len() >= 2 && p[1] == '*';
            let rest = if double { &p[2..] } else { &p[1..] };
            if go(rest, t) {
                return true;
            }
            let mut i = 0;
            while i < t.len() {
                if !double && t[i] == '/' {
                    break;
                }
                i += 1;
                if go(rest, &t[i..]) {
                    return true;
                }
            }
            false
        } else if !t.is_empty() && p[0] == t[0] {
            go(&p[1..], &t[1..])
        } else {
            false
        }
    }
    go(&p, &t)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- glob dialect (`*` stops at `/`, `**` crosses it) ---

    #[test]
    fn glob_star_stops_at_slash_double_star_crosses() {
        assert!(glob_match(".env", ".env"));
        assert!(!glob_match(".env", ".envx"));
        assert!(glob_match("*.md", "README.md"));
        assert!(!glob_match("*.md", "docs/x.md")); // single star does not cross /
        assert!(glob_match("**/*.md", "docs/x.md"));
        assert!(glob_match("secrets/**", "secrets/a/b.txt"));
        assert!(glob_match("*", "anything"));
        assert!(!glob_match("*", "a/b")); // one segment only
    }

    #[test]
    fn glob_normalizes_backslashes_both_ways() {
        assert!(Glob::new("docs/private/*").matches(r"docs\private\secrets.md"));
        assert!(Glob::new(r"docs\private\*").matches("docs/private/secrets.md"));
        assert!(!Glob::new("*.md").matches(r"docs\x.md"));
    }

    // --- Attributes: first-match-wins visibility + fallthrough consent ---

    #[test]
    fn attributes_first_matching_rule_wins() {
        let a = Attributes::parse(".env restricted=alice\n*.md public\n");
        assert!(matches!(a.visibility_for(".env"), Visibility::Restricted(_)));
        assert!(matches!(a.visibility_for("README.md"), Visibility::Public));
        assert!(matches!(a.visibility_for("unmatched.txt"), Visibility::Public)); // default
    }

    #[test]
    fn public_by_fallthrough_is_the_mis_seal_consent_test() {
        // No rule → default Public → fallthrough.
        assert!(Attributes::parse("").public_by_fallthrough("secret.env"));
        // A catch-all `* public` also waves it through → fallthrough.
        assert!(Attributes::parse("* public\n").public_by_fallthrough("secret.env"));
        // An explicit rule naming the path public is consent, NOT fallthrough.
        assert!(!Attributes::parse("secret.env public\n").public_by_fallthrough("secret.env"));
        // A non-Public resolution is never a fallthrough-public.
        assert!(!Attributes::parse("secret.env restricted=me\n").public_by_fallthrough("secret.env"));
    }

    // --- catch-all classification + secret-shaped names (ADR 0038 §1) ---

    #[test]
    fn is_catchall_distinguishes_wildcards_from_named_rules() {
        assert!(is_catchall("*"));
        assert!(is_catchall("**"));
        assert!(is_catchall("**/*"));
        assert!(is_catchall("*/**"));
        assert!(!is_catchall(""));
        assert!(!is_catchall("*.pem")); // a literal segment names it
        assert!(!is_catchall(".env*"));
        assert!(!is_catchall("docs/private/*"));
    }

    #[test]
    fn is_secret_name_matches_basenames_anywhere_case_insensitively() {
        for p in [".env", "config/.env", "id_rsa", "server.pem", "AWS_credentials.txt", "keys/.env.LOCAL"] {
            assert!(is_secret_name(std::path::Path::new(p)), "should be secret-shaped: {p}");
        }
        for p in ["main.rs", "id_map.rs", "README.md", "environment.txt"] {
            assert!(!is_secret_name(std::path::Path::new(p)), "should NOT be secret-shaped: {p}");
        }
        // NB the `.env*` pattern is anchored at the basename start, so the
        // suffix style `prod.env` is NOT caught (only `.env`, `.env.local`, …).
        assert!(!is_secret_name(std::path::Path::new("deploy/prod.env")));
    }

    // --- Ignore: file exclusion, subtree pruning, policy-file protection ---

    #[test]
    fn ignore_excludes_files_prunes_subtrees_and_never_ignores_policy() {
        let ig = Ignore::parse("target/\n*.tmp\n");
        assert!(ig.ignores_file("target/debug/x.o"));
        assert!(ig.ignores_dir("target")); // trailing-slash subtree prunes the dir
        assert!(ig.ignores_file("scratch.tmp"));
        assert!(!ig.ignores_dir("src")); // a file glob never prunes a dir
        // The policy files themselves are never ignorable (#62).
        assert!(!Ignore::parse("**\n").ignores_file(ATTRS));
        assert!(!Ignore::parse("**\n").ignores_file(IGNORE));
    }

    #[test]
    fn parse_visibility_reads_the_three_specs() {
        assert!(matches!(parse_visibility("public"), Some(Visibility::Public)));
        assert!(matches!(parse_visibility("restricted=a,b"), Some(Visibility::Restricted(ids)) if ids.len() == 2));
        assert!(matches!(parse_visibility("embargoed=1800000000"), Some(Visibility::Embargoed { reveal_at: 1800000000 })));
        assert!(parse_visibility("restricted=").is_none()); // empty id set
        assert!(parse_visibility("bogus").is_none());
    }
}
