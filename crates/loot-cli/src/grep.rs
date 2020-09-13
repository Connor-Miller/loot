//! `loot grep` — content search across a change's tree (#391).
//!
//! `git grep` searches file contents across commits; loot's twist is that
//! content is encrypted, so the search must route through the key oracle.
//! [`cmd_grep`] resolves the target change (the current working change by
//! default, or a `#305` selector), asks the [`Workspace`] for the plaintext of
//! every path the current identity may open ([`Workspace::readable_tree_at`],
//! which decrypts through [`loot_core::DagRepo::readable_tree`]), and matches
//! each line. A path this identity cannot open is never searched and never
//! seen — it is invisible, not an error (#391) — and the count of such skipped
//! paths is reported at the end.
//!
//! Match semantics are **fixed-string** (literal substring), case-sensitive —
//! `git grep -F`, not a regex. Regex was deliberately not pulled in: loot has
//! no `regex` dependency, and a literal search is the honest common case; the
//! seam ([`search_file`]) is where a regex matcher would slot in later.
//! Output is `<path>:<line>:<matching line>`, the `git grep` shape, so existing
//! tooling can parse it. Binary content (any NUL byte) is skipped, matching
//! `git grep`'s default of not searching binary files.

use crate::emit::{self, Emit};
use crate::error::CliError;
use crate::workspace::Workspace;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// One `git grep`-shaped hit: the path, the 1-based line number, and the full
/// text of the matching line (rendered lossily from UTF-8, trailing `\r`
/// stripped so a CRLF file reads the same as an LF one).
#[derive(Debug, PartialEq, Eq)]
pub struct Match {
    pub path: PathBuf,
    pub line: usize,
    pub text: String,
}

/// Every line of `content` that contains the literal `pattern`. Fixed-string,
/// case-sensitive matching on raw bytes, so it never panics on non-UTF-8 input.
/// A binary file (any embedded NUL) and an empty pattern both yield no hits —
/// the former mirrors `git grep`'s "don't search binaries" default, the latter
/// avoids matching every line of every file.
pub fn search_file(path: &Path, content: &[u8], pattern: &[u8]) -> Vec<Match> {
    if pattern.is_empty() || content.contains(&0) {
        return Vec::new();
    }
    let mut hits = Vec::new();
    for (i, line) in content.split(|&b| b == b'\n').enumerate() {
        if contains_sub(line, pattern) {
            hits.push(Match {
                path: path.to_path_buf(),
                line: i + 1,
                text: String::from_utf8_lossy(line).trim_end_matches('\r').to_string(),
            });
        }
    }
    hits
}

/// Byte-level substring test — `haystack.contains(needle)` for `&[u8]`.
fn contains_sub(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// `loot grep <pattern> [<selector>]` — search the readable content of the
/// current change (or the change named by `<selector>`) for the literal
/// `<pattern>`. Prints one `<path>:<line>:<match>` row per hit and, when the
/// current identity could not open some paths, a trailing count of those
/// skipped sealed paths.
pub fn cmd_grep(args: &[String]) -> Result<Box<dyn Emit>, CliError> {
    let positionals: Vec<&str> =
        args.iter().map(String::as_str).filter(|a| !a.starts_with('-')).collect();
    let pattern = *positionals.first().ok_or("usage: loot grep <pattern> [<selector>]")?;
    let selector = positionals.get(1).copied();

    let mut ws = Workspace::open().map_err(CliError::no_repo)?;
    let (_head, readable, skipped) = ws.readable_tree_at(selector)?;

    let needle = pattern.as_bytes();
    let mut out = String::new();
    for (path, bytes) in &readable {
        for m in search_file(path, bytes, needle) {
            let _ = writeln!(out, "{}:{}:{}", m.path.display(), m.line, m.text);
        }
    }
    if skipped > 0 {
        let _ = writeln!(
            out,
            "({skipped} sealed path(s) skipped — not readable by {})",
            ws.identity()
        );
    }
    Ok(Box::new(emit::Message::new(out)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn reports_path_line_and_full_matching_line() {
        let content = b"first line\nhas needle here\nthird\n";
        let hits = search_file(&p("a.txt"), content, b"needle");
        assert_eq!(
            hits,
            vec![Match { path: p("a.txt"), line: 2, text: "has needle here".into() }]
        );
    }

    #[test]
    fn finds_every_matching_line_with_1_based_numbers() {
        let content = b"needle\nno\nneedle again\n";
        let hits = search_file(&p("a"), content, b"needle");
        assert_eq!(hits.iter().map(|m| m.line).collect::<Vec<_>>(), vec![1, 3]);
    }

    #[test]
    fn no_match_yields_nothing() {
        assert!(search_file(&p("a"), b"nothing to see\n", b"needle").is_empty());
    }

    #[test]
    fn matching_is_case_sensitive_and_literal() {
        // Uppercase does not match a lowercase pattern (case-sensitive)...
        assert!(search_file(&p("a"), b"NEEDLE\n", b"needle").is_empty());
        // ...and the pattern is a literal substring, not a regex.
        let hits = search_file(&p("a"), b"a.b matches\naxb does not\n", b"a.b");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn strips_trailing_carriage_return_from_crlf_lines() {
        let hits = search_file(&p("a"), b"has needle here\r\nnext\r\n", b"needle");
        assert_eq!(hits[0].text, "has needle here");
    }

    #[test]
    fn binary_content_is_skipped() {
        // A NUL byte marks the file as binary; git grep skips it by default.
        assert!(search_file(&p("a"), b"needle\0needle\n", b"needle").is_empty());
    }

    #[test]
    fn empty_pattern_matches_nothing() {
        assert!(search_file(&p("a"), b"anything\n", b"").is_empty());
    }
}
