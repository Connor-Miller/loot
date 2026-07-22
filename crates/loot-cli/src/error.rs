//! The CLI's machine error channel (#430).
//!
//! Before this, a verb failed with a bare `String` and `main` printed
//! `loot: <prose>`; a subprocess consumer (the physical SDK adapter) could only
//! recover the error *taxonomy* by regex-matching that prose, because the
//! binary's typed [`RepoError`](loot_core::RepoError) variants never crossed the
//! subprocess seam. [`CliError`] carries the taxonomy as **data**: a stable
//! `code` slug alongside the unchanged human `message`. The dispatcher prints
//! the same `loot: <message>` as before, and — only under `--json` — emits
//! `{"contract":N,"error":{"code","message"}}` to stderr (see [`CliError::to_json`]).
//!
//! `code` is a `&'static str` because every slug is a compile-time constant:
//! [`RepoError::code`](loot_core::RepoError::code) is the source of truth for the
//! engine taxonomy, and the CLI adds its own two (`no_repo`, `unknown_flag`).
//! A plain `String` error (anything the engine already stringified before it
//! reached the verb) converts to the generic `"error"` code — honest about the
//! fact that its variant was lost upstream, message preserved verbatim.

use loot_core::RepoError;

/// A coded CLI failure: a stable machine `code` plus the exact human `message`
/// the CLI has always printed. The verb return type (`Emitted`) carries this so
/// the code survives to the dispatcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    /// Stable machine slug — a [`RepoError::code`](loot_core::RepoError::code)
    /// value, a CLI-level slug (`no_repo`, `unknown_flag`), or `"error"` for a
    /// pre-stringified failure whose variant was already lost.
    pub code: &'static str,
    /// The human message — byte-for-byte what `loot: <message>` prints, so the
    /// non-`--json` output is unchanged for humans and existing scripts.
    pub message: String,
}

impl CliError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    /// A `Workspace::open` failure: there is no loot repo here (or its store
    /// would not load). The CLI-level `no_repo` slug the SDK maps to a setup
    /// error.
    pub fn no_repo(message: impl Into<String>) -> Self {
        Self::new("no_repo", message)
    }

    /// The flag gate refused an undeclared flag (#67). The CLI-level
    /// `unknown_flag` slug.
    pub fn unknown_flag(message: impl Into<String>) -> Self {
        Self::new("unknown_flag", message)
    }

    /// The machine rendering (#430): `{"contract":N,"error":{"code","message"}}`.
    /// Versioned with `FORMAT_MAJOR` exactly like the other ADR-0023 machine
    /// contracts (`verdict::json`, `status_json`, …) so a consumer can gate on
    /// the wire version; emitted to stderr under `--json`.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"contract\":");
        out.push_str(&loot_core::format::FORMAT_MAJOR.to_string());
        out.push_str(",\"error\":{\"code\":");
        json_string(self.code, &mut out);
        out.push_str(",\"message\":");
        json_string(&self.message, &mut out);
        out.push_str("}}");
        out
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// The engine taxonomy travels as its own slug (the whole point of #430).
impl From<RepoError> for CliError {
    fn from(e: RepoError) -> Self {
        Self { code: e.code(), message: e.to_string() }
    }
}

/// A pre-stringified failure — the engine already collapsed its variant to prose
/// upstream, so all the code channel can honestly say is the generic `"error"`.
impl From<String> for CliError {
    fn from(message: String) -> Self {
        Self { code: "error", message }
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        Self { code: "error", message: message.to_string() }
    }
}

/// Append `s` as a quoted, escaped JSON string — the same RFC 8259 handling
/// `loot_core::verdict` uses for the other machine contracts (that module's
/// `json_string` is private, so this is its twin). Control chars below 0x20
/// become `\u00XX` so a message with a newline or tab round-trips.
fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use loot_core::Oid;

    #[test]
    fn repo_error_carries_its_variant_slug() {
        let e: CliError = RepoError::Unauthorized(Oid([0; 32])).into();
        assert_eq!(e.code, "unauthorized");
        assert_eq!(e.message, RepoError::Unauthorized(Oid([0; 32])).to_string());
    }

    #[test]
    fn a_bare_string_is_the_generic_error_code() {
        let e: CliError = "something went wrong".to_string().into();
        assert_eq!(e.code, "error");
        assert_eq!(e.message, "something went wrong");
    }

    #[test]
    fn cli_level_slugs() {
        assert_eq!(CliError::no_repo("nope").code, "no_repo");
        assert_eq!(CliError::unknown_flag("bad").code, "unknown_flag");
    }

    #[test]
    fn json_shape_is_contract_versioned_and_escaped() {
        let e = CliError::new("unauthorized", "not authorized to read \"x\"\n");
        let j = e.to_json();
        assert_eq!(
            j,
            format!(
                "{{\"contract\":{},\"error\":{{\"code\":\"unauthorized\",\"message\":\"not authorized to read \\\"x\\\"\\n\"}}}}",
                loot_core::format::FORMAT_MAJOR
            )
        );
    }
}
