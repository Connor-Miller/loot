//! Tokenizer: source string -> a flat `Vec<Token>`.
//!
//! The lexer is deliberately tiny. The only non-obvious rule is the glued
//! `HEAD~<n>` point selector (loot's existing n-th-ancestor form): a `~`
//! immediately followed by digits, immediately after `HEAD`, is ONE token, so
//! it never collides with the binary `~` difference operator. `HEAD ~ x` (with
//! surrounding space) still tokenizes as three tokens.

use crate::error::RevsetError;

/// One lexical token. Function names, the `all`/`visible` keywords, and bare
/// id-prefixes all arrive as [`Token::Ident`]; the parser tells them apart by
/// whether a `(` follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// `@` — the working change.
    At,
    /// `HEAD` — the tip.
    Head,
    /// `HEAD~<n>` — the n-th first-parent ancestor of the tip.
    HeadAncestor(u32),
    /// A bare word: a function name (`ancestors`, `author`, …), a keyword
    /// (`all`, `visible`), an id-prefix, or an `author`/`description` argument.
    Ident(String),
    /// A quoted string literal (`"…"` or `'…'`) — for patterns with spaces.
    Str(String),
    /// `..` — the range operator.
    DotDot,
    /// `&` — intersection.
    Amp,
    /// `|` — union.
    Pipe,
    /// `~` — complement (unary) / difference (binary).
    Tilde,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `,`
    Comma,
}

/// True for the characters allowed in a bare word (function names, keywords,
/// id-prefixes, unquoted `author`/`description` arguments). `.` is excluded so
/// it can never eat into a `..` range; use a quoted string for a pattern that
/// needs dots or spaces.
fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '/')
}

/// Tokenize `src`. Whitespace separates tokens and is otherwise ignored.
pub fn tokenize(src: &str) -> Result<Vec<Token>, RevsetError> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < chars.len() {
        let c = chars[i];
        match c {
            c if c.is_whitespace() => {
                i += 1;
            }
            '(' => {
                out.push(Token::LParen);
                i += 1;
            }
            ')' => {
                out.push(Token::RParen);
                i += 1;
            }
            '&' => {
                out.push(Token::Amp);
                i += 1;
            }
            '|' => {
                out.push(Token::Pipe);
                i += 1;
            }
            '~' => {
                out.push(Token::Tilde);
                i += 1;
            }
            ',' => {
                out.push(Token::Comma);
                i += 1;
            }
            '@' => {
                out.push(Token::At);
                i += 1;
            }
            '.' => {
                if chars.get(i + 1) == Some(&'.') {
                    out.push(Token::DotDot);
                    i += 2;
                } else {
                    return Err(RevsetError::UnexpectedChar { ch: '.', pos: i });
                }
            }
            '"' | '\'' => {
                let quote = c;
                let mut s = String::new();
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == quote {
                        closed = true;
                        i += 1;
                        break;
                    }
                    s.push(chars[i]);
                    i += 1;
                }
                if !closed {
                    return Err(RevsetError::UnterminatedString);
                }
                out.push(Token::Str(s));
            }
            c if is_word_char(c) => {
                let start = i;
                while i < chars.len() && is_word_char(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                if word == "HEAD" {
                    // Glued `HEAD~<n>`: only when a `~` is *immediately* followed
                    // by at least one digit. Otherwise leave `~` for the parser.
                    if chars.get(i) == Some(&'~')
                        && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit())
                    {
                        i += 1; // consume '~'
                        let dstart = i;
                        while i < chars.len() && chars[i].is_ascii_digit() {
                            i += 1;
                        }
                        let digits: String = chars[dstart..i].iter().collect();
                        let n: u32 = digits
                            .parse()
                            .map_err(|_| RevsetError::InvalidIdPrefix(digits.clone()))?;
                        out.push(Token::HeadAncestor(n));
                    } else {
                        out.push(Token::Head);
                    }
                } else {
                    out.push(Token::Ident(word));
                }
            }
            other => {
                return Err(RevsetError::UnexpectedChar { ch: other, pos: i });
            }
        }
    }

    Ok(out)
}
