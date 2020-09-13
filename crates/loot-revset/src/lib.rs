//! # loot-revset
//!
//! A small **query algebra for selecting sets of changes** from a [`DagRepo`]
//! view — loot's answer to jj's revset language (#394). loot's historic
//! selector grammar (`@`, `HEAD`, `HEAD~n`, an id-prefix) is a single-point
//! stand-in; a revset is a strict *superset* of it that also names *sets*:
//! ranges, ancestry, author/description predicates, and boolean combinations.
//!
//! This crate is a pure **library** — a [`parse`] step (string → [`Expr`]) and
//! an [`evaluate`] step ([`Expr`] × [`DagRepo`] → change ids). It wires into no
//! CLI verb; the downstream consumers (split targets, filtered log, …) are
//! separate tickets.
//!
//! ## Grammar (MVP)
//!
//! ```text
//! Builtins    @              working change (authored-but-unsigned tip)
//!             HEAD           the tip / heads
//!             HEAD~<n>       n-th first-parent ancestor of the tip
//!             all()          every change in the view
//!             visible()      changes fully readable under the current key oracle
//!             <hexprefix>    the change(s) whose version-id hex starts with it
//! Range       x..y           reachable from y but not from x
//! Ancestry    ancestors(x)   x and everything reachable via parents
//!             descendants(x) x and everything that reaches it via parents
//! Predicates  author(name)   author pubkey hex starts with `name`
//!             description(p) message contains substring `p`
//! Booleans    x & y          intersection
//!             x | y          union
//!             ~x             complement  (== all() ~ x)
//!             x ~ y          difference   (== x & ~y)
//! ```
//!
//! ### Precedence (loosest → tightest)
//!
//! `|`  <  `&`  <  binary `~`  <  unary `~`  <  `..`  <  primaries.
//!
//! So `~a & b` is `(~a) & b`, and `a & b ~ c` is `a & (b ~ c)`. Parenthesize to
//! override. A range's endpoints are always primaries.
//!
//! ### `~` — complement, defined precisely
//!
//! Unary `~x` is the complement **relative to the current view**: exactly
//! `all() ~ x` (every change the view holds, minus `x`). It is never a
//! universe-of-all-possible-ids. Binary `x ~ y` is set difference, `x & ~y`.
//!
//! ### `visible()` and the key oracle
//!
//! `visible()` asks the repo's own key oracle (the same one `surface`/`get`
//! use). A change counts as visible when this identity can open **every**
//! content object in its tree as of `now`; a change carrying any object we lack
//! the key for — or one still embargoed at `now` — is excluded. An empty-tree
//! change is trivially visible.
//!
//! ### `description` matching
//!
//! Case-sensitive **substring** match. The workspace carries no `regex`
//! dependency, so a substring is the dependency-free, evidence-driven default
//! (upgrade to regex only if the workspace later adopts it).
//!
//! ### `author` matching
//!
//! Case-insensitive hex-prefix of the author's ed25519 pubkey. The
//! peer-nickname registry (name ↔ key) lives above loot-core in the CLI, so
//! this library matches the *intrinsic* author key that every change carries,
//! not a human alias.
//!
//! ## Example
//!
//! ```no_run
//! # use loot_core::DagRepo;
//! # fn demo(repo: &DagRepo) -> Result<(), loot_revset::RevsetError> {
//! // Everything on the tip's line that Bob authored, minus the working change:
//! let ids = loot_revset::evaluate("ancestors(HEAD) & author(bb) ~ @", repo, 0)?;
//! # let _ = ids;
//! # Ok(())
//! # }
//! ```

mod error;
mod eval;
mod lexer;
mod parser;

pub use error::RevsetError;
pub use parser::{parse, Expr};

// Re-export the id type callers get back, so a consumer needs only this crate.
pub use loot_core::Oid;

use loot_core::DagRepo;

/// Parse and evaluate `expr` against `repo` as of clock `now`, returning the
/// selected change (version) ids in the view's topological order (parents
/// before children), de-duplicated.
///
/// `now` (unix seconds) is consulted only by `visible()`; pass `0` for
/// expressions that don't use it.
pub fn evaluate(expr: &str, repo: &DagRepo, now: u64) -> Result<Vec<Oid>, RevsetError> {
    let ast = parse(expr)?;
    Ok(eval::eval(&ast, repo, now))
}

/// Evaluate an already-parsed [`Expr`] — the entry a caller that parsed once
/// (e.g. to inspect or cache the AST) uses to avoid re-lexing.
pub fn evaluate_ast(ast: &Expr, repo: &DagRepo, now: u64) -> Vec<Oid> {
    eval::eval(ast, repo, now)
}
