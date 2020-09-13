//! End-to-end tests over a real, multi-change `DagRepo` built in memory.
//!
//! Fixture graph (parents point up; `w` is the unsigned working change):
//!
//! ```text
//!   c0  root            (alice, public)
//!   |
//!   c1  feature login   (alice, public)
//!   |\
//!   | c4  side docs      (alice, RESTRICTED to bob -> invisible to alice)
//!   |
//!   c2  fix parser bug  (bob, public)
//!   |
//!   c3  feature logout  (bob, public)   <- finalized tip
//!   |
//!   w   wip refactor    (alice, public, UNSIGNED == working change `@`)
//! ```
//!
//! heads = {c4, w}.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use loot_core::{Change, DagRepo, Oid, Repo, Visibility};
use loot_revset::{evaluate, parse, Expr, RevsetError};

const ALICE: [u8; 32] = [0xAA; 32];
const BOB: [u8; 32] = [0xBB; 32];

struct Fixture {
    repo: DagRepo,
    c0: Oid,
    c1: Oid,
    c2: Oid,
    c3: Oid,
    c4: Oid,
    w: Oid,
}

/// Record one change and (optionally) finalize it with a stub signature. An
/// authored-but-unsigned change is a *working change*; signing finalizes it.
fn add(
    repo: &mut DagRepo,
    author: [u8; 32],
    parents: Vec<Oid>,
    msg: &str,
    path: &str,
    bytes: &[u8],
    vis: Visibility,
    sign: bool,
) -> Oid {
    repo.set_author(author);
    let oid = repo.put(bytes, vis.clone()).unwrap();
    let mut tree: BTreeMap<PathBuf, (Oid, Visibility)> = BTreeMap::new();
    tree.insert(PathBuf::from(path), (oid, vis));
    let id = repo
        .record(Change { id: Oid([0; 32]), parents, message: msg.to_string(), tree })
        .unwrap();
    if sign {
        repo.attach_signature(&id, [0u8; 64]).unwrap();
    }
    id
}

fn fixture() -> Fixture {
    // The repo identity is "alice": she is the key oracle `visible()` consults.
    let mut repo = DagRepo::init(PathBuf::from("mem://revset-test"), "alice").unwrap();

    let c0 = add(&mut repo, ALICE, vec![], "root: init", "root.txt", b"root\n", Visibility::Internal, true);
    let c1 = add(&mut repo, ALICE, vec![c0.clone()], "feature login", "login.rs", b"login\n", Visibility::Internal, true);
    let c2 = add(&mut repo, BOB, vec![c1.clone()], "fix parser bug", "parser.rs", b"parser\n", Visibility::Internal, true);
    let c3 = add(&mut repo, BOB, vec![c2.clone()], "feature logout", "logout.rs", b"logout\n", Visibility::Internal, true);
    // Restricted to bob only: alice holds no key, so this change is invisible.
    let c4 = add(
        &mut repo,
        ALICE,
        vec![c1.clone()],
        "side docs",
        "docs.md",
        b"secret docs\n",
        Visibility::Restricted(vec!["bob".to_string()]),
        true,
    );
    // The working change: authored by alice, left UNSIGNED.
    let w = add(&mut repo, ALICE, vec![c3.clone()], "wip refactor", "refactor.rs", b"wip\n", Visibility::Internal, false);

    Fixture { repo, c0, c1, c2, c3, c4, w }
}

fn set(v: Vec<Oid>) -> BTreeSet<Oid> {
    v.into_iter().collect()
}

fn expect(ids: &[&Oid]) -> BTreeSet<Oid> {
    ids.iter().map(|o| (*o).clone()).collect()
}

/// A comfortably-unique hex prefix for an id.
fn prefix(o: &Oid) -> String {
    loot_core::hex::encode(&o.0)[..12].to_string()
}

fn eval(f: &Fixture, expr: &str) -> BTreeSet<Oid> {
    set(evaluate(expr, &f.repo, 0).unwrap())
}

// --- builtins -------------------------------------------------------------

#[test]
fn all_enumerates_every_change() {
    let f = fixture();
    assert_eq!(
        eval(&f, "all()"),
        expect(&[&f.c0, &f.c1, &f.c2, &f.c3, &f.c4, &f.w])
    );
}

#[test]
fn at_is_the_working_change() {
    let f = fixture();
    assert_eq!(eval(&f, "@"), expect(&[&f.w]));
}

#[test]
fn head_is_the_heads() {
    let f = fixture();
    assert_eq!(eval(&f, "HEAD"), expect(&[&f.c4, &f.w]));
}

#[test]
fn head_ancestor_walks_first_parents() {
    let f = fixture();
    // c4~1 = c1 ; w~1 = c3
    assert_eq!(eval(&f, "HEAD~1"), expect(&[&f.c1, &f.c3]));
    // c4~2 = c0 ; w~2 = c2
    assert_eq!(eval(&f, "HEAD~2"), expect(&[&f.c0, &f.c2]));
}

#[test]
fn visible_excludes_unreadable_changes() {
    let f = fixture();
    // c4 is restricted to bob; alice cannot open it, so it drops out.
    assert_eq!(
        eval(&f, "visible()"),
        expect(&[&f.c0, &f.c1, &f.c2, &f.c3, &f.w])
    );
}

// --- point selectors (superset of the old grammar) ------------------------

#[test]
fn id_prefix_resolves_a_singleton() {
    let f = fixture();
    assert_eq!(eval(&f, &prefix(&f.c2)), expect(&[&f.c2]));
}

#[test]
fn id_prefix_is_case_insensitive() {
    let f = fixture();
    assert_eq!(eval(&f, &prefix(&f.c2).to_uppercase()), expect(&[&f.c2]));
}

// --- ancestry -------------------------------------------------------------

#[test]
fn ancestors_walks_parents_inclusive() {
    let f = fixture();
    assert_eq!(
        eval(&f, &format!("ancestors({})", prefix(&f.c3))),
        expect(&[&f.c0, &f.c1, &f.c2, &f.c3])
    );
}

#[test]
fn descendants_walks_children_inclusive() {
    let f = fixture();
    assert_eq!(
        eval(&f, &format!("descendants({})", prefix(&f.c1))),
        expect(&[&f.c1, &f.c2, &f.c3, &f.c4, &f.w])
    );
}

#[test]
fn range_is_reachable_from_y_but_not_x() {
    let f = fixture();
    // c1..c3 = ancestors(c3) \ ancestors(c1) = {c2, c3}
    assert_eq!(
        eval(&f, &format!("{}..{}", prefix(&f.c1), prefix(&f.c3))),
        expect(&[&f.c2, &f.c3])
    );
}

// --- predicates -----------------------------------------------------------

#[test]
fn author_matches_pubkey_prefix() {
    let f = fixture();
    assert_eq!(eval(&f, "author(aa)"), expect(&[&f.c0, &f.c1, &f.c4, &f.w]));
    assert_eq!(eval(&f, "author(bb)"), expect(&[&f.c2, &f.c3]));
}

#[test]
fn description_substring_match_case_sensitive() {
    let f = fixture();
    assert_eq!(eval(&f, "description(feature)"), expect(&[&f.c1, &f.c3]));
    // Case-sensitive: "Feature" matches nothing.
    assert!(eval(&f, "description(Feature)").is_empty());
    // Quoted pattern with a space.
    assert_eq!(eval(&f, "description(\"parser bug\")"), expect(&[&f.c2]));
}

// --- boolean algebra ------------------------------------------------------

#[test]
fn union_intersection_difference_complement() {
    let f = fixture();
    assert_eq!(eval(&f, "author(bb) | @"), expect(&[&f.c2, &f.c3, &f.w]));
    assert_eq!(eval(&f, "author(aa) & description(feature)"), expect(&[&f.c1]));
    assert_eq!(
        eval(&f, "all() ~ @"),
        expect(&[&f.c0, &f.c1, &f.c2, &f.c3, &f.c4])
    );
    // Unary complement is relative to the view: ~author(bb) == all() ~ author(bb).
    assert_eq!(
        eval(&f, "~author(bb)"),
        expect(&[&f.c0, &f.c1, &f.c4, &f.w])
    );
}

#[test]
fn precedence_and_binds_tighter_than_or() {
    let f = fixture();
    // author(bb) | author(aa) & @  ==  author(bb) | (author(aa) & @)
    assert_eq!(
        eval(&f, "author(bb) | author(aa) & @"),
        expect(&[&f.c2, &f.c3, &f.w])
    );
    // Parenthesized differently:
    assert_eq!(
        eval(&f, "(author(bb) | author(aa)) & @"),
        expect(&[&f.w])
    );
}

#[test]
fn combined_ancestry_and_predicate() {
    let f = fixture();
    // Bob's work on the tip's line: ancestors(HEAD) & author(bb) == {c2, c3}
    assert_eq!(
        eval(&f, "ancestors(HEAD) & author(bb)"),
        expect(&[&f.c2, &f.c3])
    );
}

#[test]
fn results_are_deduplicated_and_topo_ordered() {
    let f = fixture();
    // Overlapping union must not repeat, and comes back parents-before-children.
    let v = evaluate("ancestors(HEAD) | all()", &f.repo, 0).unwrap();
    let deduped: BTreeSet<Oid> = v.iter().cloned().collect();
    assert_eq!(v.len(), deduped.len(), "no duplicates");
    // c0 (a root) must precede c3 (its descendant).
    let pos = |o: &Oid| v.iter().position(|x| x == o).unwrap();
    assert!(pos(&f.c0) < pos(&f.c3));
    assert!(pos(&f.c1) < pos(&f.c2));
}

// --- parser ---------------------------------------------------------------

#[test]
fn parses_grammar_shapes() {
    assert_eq!(parse("@").unwrap(), Expr::At);
    assert_eq!(parse("HEAD").unwrap(), Expr::Head);
    assert_eq!(parse("HEAD~3").unwrap(), Expr::HeadAncestor(3));
    assert_eq!(parse("all()").unwrap(), Expr::All);
    assert_eq!(parse("visible()").unwrap(), Expr::Visible);
    assert!(matches!(parse("ancestors(@)").unwrap(), Expr::Ancestors(_)));
    assert!(matches!(parse("author(alice)").unwrap(), Expr::Author(_)));
    // Glued HEAD~n vs spaced difference.
    assert!(matches!(parse("HEAD ~ @").unwrap(), Expr::Difference(_, _)));
}

#[test]
fn parse_errors_are_typed() {
    assert_eq!(parse(""), Err(RevsetError::Empty));
    assert_eq!(parse("   "), Err(RevsetError::Empty));
    assert_eq!(
        parse("bogus()"),
        Err(RevsetError::UnknownFunction("bogus".to_string()))
    );
    assert_eq!(parse("(@"), Err(RevsetError::UnbalancedParens));
    assert!(matches!(parse("@ @"), Err(RevsetError::TrailingInput)));
    assert!(matches!(parse("@ &"), Err(RevsetError::UnexpectedEnd)));
    assert!(matches!(parse("!"), Err(RevsetError::UnexpectedChar { .. })));
    assert!(matches!(
        parse("\"unclosed"),
        Err(RevsetError::UnterminatedString)
    ));
    // A bare non-hex word is not a valid revset.
    assert!(matches!(
        parse("nothex"),
        Err(RevsetError::InvalidIdPrefix(_))
    ));
}

#[test]
fn evaluate_surfaces_parse_errors() {
    let f = fixture();
    assert!(evaluate("bogus()", &f.repo, 0).is_err());
}
