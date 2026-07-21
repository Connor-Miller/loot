//! The `key = value` config dialect (candidate 5). One home for the
//! trim-skip-`split_once('=')` idiom that `ferry` (git_config / git_identity_map
//! spine files), the per-repo `.loot/config`, and the global config were each
//! re-authoring byte-for-byte. Blank lines and `#` comments are skipped; keys
//! and values are trimmed; entries sort by key (BTreeMap), so `encode` is the
//! stable inverse of `parse` for a normalized map.

use std::collections::BTreeMap;

/// Parse `key = value` lines into a sorted map. Blank lines and `#` comments
/// are ignored; a line without `=` is skipped. Whitespace around key and value
/// is trimmed.
pub fn parse(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Serialize a map back to the dialect: one `key = value` line per entry, in
/// key order.
pub fn encode(entries: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for (k, v) in entries {
        out.push_str(&format!("{k} = {v}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_normalized_map() {
        let text = "a = 1\nb = two\n";
        let map = parse(text);
        assert_eq!(map.get("a").map(String::as_str), Some("1"));
        assert_eq!(map.get("b").map(String::as_str), Some("two"));
        assert_eq!(encode(&map), text);
    }

    #[test]
    fn skips_comments_blanks_and_bad_lines_and_trims() {
        let map = parse("# a comment\n\n  key   =   value  \nno-equals-here\n");
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("key").map(String::as_str), Some("value"));
    }

    #[test]
    fn encode_orders_by_key() {
        let mut m = BTreeMap::new();
        m.insert("zed".to_string(), "z".to_string());
        m.insert("apex".to_string(), "a".to_string());
        assert_eq!(encode(&m), "apex = a\nzed = z\n");
    }

    #[test]
    fn value_may_contain_equals() {
        // split_once keeps everything after the first `=` as the value.
        let map = parse("url = https://h/p?x=1\n");
        assert_eq!(map.get("url").map(String::as_str), Some("https://h/p?x=1"));
    }
}
