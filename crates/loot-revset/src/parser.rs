//! AST + recursive-descent parser.
//!
//! Precedence, loosest binding to tightest:
//!
//! 1. `|`  union            (left-associative)
//! 2. `&`  intersection     (left-associative)
//! 3. `~`  difference        binary `x ~ y` == `x & ~y` (left-associative)
//! 4. `~`  complement        unary prefix `~x` == `all() ~ x` (tightest operator)
//! 5. `..` range             `x..y` == ancestors(y) minus ancestors(x)
//! 6. primaries              `@`, `HEAD`, `HEAD~n`, id-prefix, `f(...)`, `(e)`
//!
//! So `~a & b` is `(~a) & b`, `a & b ~ c` is `a & (b ~ c)`, and a range's
//! endpoints are always primaries (`ancestors(x)..HEAD` parses, `~x..y` is
//! `~(x..y)`).

use crate::error::RevsetError;
use crate::lexer::{tokenize, Token};

/// A parsed revset expression. Each variant denotes a set of changes; see the
/// evaluator for the exact semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// `@` — the working change(s) (authored-but-unsigned tip).
    At,
    /// `HEAD` — the current tip(s) / heads.
    Head,
    /// `HEAD~<n>` — the n-th first-parent ancestor of each head.
    HeadAncestor(u32),
    /// A bare hex id-prefix resolving to the change(s) it matches.
    IdPrefix(String),
    /// `all()` — every change in the view.
    All,
    /// `visible()` — changes fully readable under the current key oracle.
    Visible,
    /// `ancestors(x)` — `x` and everything reachable from it via parents.
    Ancestors(Box<Expr>),
    /// `descendants(x)` — `x` and everything that reaches it via parents.
    Descendants(Box<Expr>),
    /// `author(name)` — changes whose author pubkey hex starts with `name`.
    Author(String),
    /// `description(pattern)` — changes whose message contains `pattern`.
    Description(String),
    /// `x..y` — changes reachable from `y` but not from `x`.
    Range(Box<Expr>, Box<Expr>),
    /// `x | y` — set union.
    Union(Box<Expr>, Box<Expr>),
    /// `x & y` — set intersection.
    Intersect(Box<Expr>, Box<Expr>),
    /// `x ~ y` — set difference (`x` without `y`).
    Difference(Box<Expr>, Box<Expr>),
    /// `~x` — complement (`all()` without `x`).
    Complement(Box<Expr>),
}

/// Parse a revset string into an [`Expr`], or fail with a typed error.
pub fn parse(src: &str) -> Result<Expr, RevsetError> {
    let tokens = tokenize(src)?;
    if tokens.is_empty() {
        return Err(RevsetError::Empty);
    }
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_union()?;
    if p.pos != p.tokens.len() {
        return Err(RevsetError::TrailingInput);
    }
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn bump(&mut self) -> Option<Token> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn expect(&mut self, want: &Token) -> Result<(), RevsetError> {
        match self.peek() {
            Some(t) if t == want => {
                self.pos += 1;
                Ok(())
            }
            Some(_) => Err(if *want == Token::RParen {
                RevsetError::UnbalancedParens
            } else {
                RevsetError::UnexpectedEnd
            }),
            None => Err(if *want == Token::RParen {
                RevsetError::UnbalancedParens
            } else {
                RevsetError::UnexpectedEnd
            }),
        }
    }

    fn parse_union(&mut self) -> Result<Expr, RevsetError> {
        let mut left = self.parse_intersection()?;
        while matches!(self.peek(), Some(Token::Pipe)) {
            self.bump();
            let right = self.parse_intersection()?;
            left = Expr::Union(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_intersection(&mut self) -> Result<Expr, RevsetError> {
        let mut left = self.parse_difference()?;
        while matches!(self.peek(), Some(Token::Amp)) {
            self.bump();
            let right = self.parse_difference()?;
            left = Expr::Intersect(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_difference(&mut self) -> Result<Expr, RevsetError> {
        let mut left = self.parse_complement()?;
        // A `~` here is binary difference. Its right operand is a complement,
        // so `a ~ ~b` reads as `a ~ (~b)` and `~a ~ b` as `(~a) ~ b`.
        while matches!(self.peek(), Some(Token::Tilde)) {
            self.bump();
            let right = self.parse_complement()?;
            left = Expr::Difference(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_complement(&mut self) -> Result<Expr, RevsetError> {
        if matches!(self.peek(), Some(Token::Tilde)) {
            self.bump();
            let inner = self.parse_complement()?;
            Ok(Expr::Complement(Box::new(inner)))
        } else {
            self.parse_range()
        }
    }

    fn parse_range(&mut self) -> Result<Expr, RevsetError> {
        let left = self.parse_primary()?;
        if matches!(self.peek(), Some(Token::DotDot)) {
            self.bump();
            let right = self.parse_primary()?;
            Ok(Expr::Range(Box::new(left), Box::new(right)))
        } else {
            Ok(left)
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, RevsetError> {
        match self.bump() {
            Some(Token::At) => Ok(Expr::At),
            Some(Token::Head) => Ok(Expr::Head),
            Some(Token::HeadAncestor(n)) => Ok(Expr::HeadAncestor(n)),
            Some(Token::LParen) => {
                let inner = self.parse_union()?;
                self.expect(&Token::RParen)?;
                Ok(inner)
            }
            Some(Token::Ident(name)) => self.parse_ident(name),
            Some(_) => Err(RevsetError::UnexpectedEnd),
            None => Err(RevsetError::UnexpectedEnd),
        }
    }

    /// An identifier is a function call when a `(` follows, otherwise a bare
    /// id-prefix (which must be valid lowercase/uppercase hex).
    fn parse_ident(&mut self, name: String) -> Result<Expr, RevsetError> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.bump();
            let expr = match name.as_str() {
                "all" => {
                    self.expect(&Token::RParen)?;
                    Expr::All
                }
                "visible" => {
                    self.expect(&Token::RParen)?;
                    Expr::Visible
                }
                "ancestors" => {
                    let arg = self.parse_union()?;
                    self.expect(&Token::RParen)?;
                    Expr::Ancestors(Box::new(arg))
                }
                "descendants" => {
                    let arg = self.parse_union()?;
                    self.expect(&Token::RParen)?;
                    Expr::Descendants(Box::new(arg))
                }
                "author" => {
                    let s = self.parse_string_arg("author")?;
                    self.expect(&Token::RParen)?;
                    Expr::Author(s)
                }
                "description" => {
                    let s = self.parse_string_arg("description")?;
                    self.expect(&Token::RParen)?;
                    Expr::Description(s)
                }
                _ => return Err(RevsetError::UnknownFunction(name)),
            };
            Ok(expr)
        } else if is_hex(&name) {
            Ok(Expr::IdPrefix(name))
        } else {
            Err(RevsetError::InvalidIdPrefix(name))
        }
    }

    /// The single textual argument to `author`/`description`: a quoted string or
    /// a bare word.
    fn parse_string_arg(&mut self, func: &'static str) -> Result<String, RevsetError> {
        match self.bump() {
            Some(Token::Str(s)) => Ok(s),
            Some(Token::Ident(s)) => Ok(s),
            _ => Err(RevsetError::BadArgument(func)),
        }
    }
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}
