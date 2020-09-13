//! Typed parse/lex errors. Every failure a caller can hit is a distinct,
//! matchable variant with a legible `Display` — no stringly-typed prose to
//! scrape.

use thiserror::Error;

/// What went wrong turning a revset string into a set of changes. Lex and parse
/// failures are the only cases: evaluation itself is total (an unmatched
/// selector yields the empty set, never an error).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RevsetError {
    /// The input was empty or all whitespace.
    #[error("empty revset expression")]
    Empty,

    /// A character that cannot begin any token, at byte-offset `pos`.
    #[error("unexpected character {ch:?} at position {pos}")]
    UnexpectedChar { ch: char, pos: usize },

    /// A quoted string was opened but never closed.
    #[error("unterminated string literal")]
    UnterminatedString,

    /// The parser expected more input (e.g. a right operand or a closing paren)
    /// but the token stream ended.
    #[error("unexpected end of expression")]
    UnexpectedEnd,

    /// A `(` with no matching `)`.
    #[error("unbalanced parentheses")]
    UnbalancedParens,

    /// A `name(` call where `name` is not one of the known functions
    /// (`ancestors`, `descendants`, `author`, `description`, `all`, `visible`).
    #[error("unknown function `{0}()`")]
    UnknownFunction(String),

    /// `author(...)` / `description(...)` needs exactly one string argument.
    #[error("`{0}()` expects a single argument")]
    BadArgument(&'static str),

    /// A bare word that is neither a known keyword, nor a function call, nor a
    /// valid hex id-prefix — most often a mistyped builtin (`all` for `all()`).
    #[error("`{0}` is not a valid revset: expected `@`, `HEAD`, a hex id-prefix, or a function like `ancestors(...)`")]
    InvalidIdPrefix(String),

    /// Tokens remained after a complete expression was parsed.
    #[error("unexpected trailing input in revset")]
    TrailingInput,
}
