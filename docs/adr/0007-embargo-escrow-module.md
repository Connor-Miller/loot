# Embargo is enforced by an Escrow module, not by open()

## Status

accepted

## Context

ADR 0003 introduced spike-honest embargo: `open()` checks `now < reveal_at` and
refuses early. This keeps the authorization chokepoint clean but does not close
the D-threat: a keyholder who holds the plaintext content key in their Keyring
can bypass embargo by calling the engine with a manipulated `now`. The key
simply shouldn't be in the Keyring until the embargo lifts.

The threat model, grilled before this decision:

| Threat | Prior mechanism | Gap |
|--------|-----------------|-----|
| External attacker / relay | No key in bundle/object (ADR 0003) | Closed |
| Honest premature read | `open()` time gate | Closed |
| Malicious keyholder bypass | `open()` time gate | Open — key already in Keyring |

The D-threat is real for the CVE scenario ("automated tooling must not render
this fix before the release ships") and applies equally to the originator and to
peers who receive the bundle. A symmetric guarantee requires that *no* identity
holds a usable Keyring entry for embargoed content before `reveal_at`.

## Decision

Introduce an **Escrow** module in `loot-core` as a new lifecycle stage between
`seal` and `Keyring`:

### Module interface

```rust
pub struct Escrow { entries: BTreeMap<Oid, EscrowEntry> }
pub struct EscrowEntry { pub key: ContentKey, pub reveal_at: u64 }

impl Escrow {
    pub fn insert(&mut self, oid: Oid, key: ContentKey, reveal_at: u64)
    pub fn flush(&mut self, keyring: &mut Keyring, now: u64)
    pub fn iter(&self) -> impl Iterator<Item = (&Oid, &EscrowEntry)>
}
```

`flush` promotes all entries where `now >= reveal_at` into the Keyring and
removes them from the Escrow. After flush, `sealed::open` finds the key in the
Keyring and proceeds as before — `open()` itself is unmodified.

### Key routing at seal time

```
Visibility::Embargoed { reveal_at }  →  escrow.insert(oid, key, reveal_at)
Visibility::Public | Restricted      →  keyring.insert(oid, key)   (unchanged)
```

This is symmetric: the originator's key goes to Escrow, not the Keyring.
Nobody reads embargoed content before `flush` promotes the key.

### flush call sites (Workspace)

`Workspace::checkout()` and `Workspace::snapshot()` call
`repo.flush_escrow(self.now)` before any content-reading operation. The engine
exposes:

```rust
pub fn flush_escrow(&mut self, now: u64)
```

`sealed::open` has no new parameters. The Keyring is always current by the time
`open` runs.

### Bundle wire format

Bundles gain an `escrow_entries: Vec<(Oid, [u8;32], u64)>` section alongside the
existing keyring section. The sender ships embargoed keys as escrow entries (with
their `reveal_at`) rather than as plain keyring entries. `apply` files them into
the receiver's `Escrow`. Restricted keys continue to never travel.

Key routing in bundle send/receive:

```
Send:    ANYONE-granted, not embargoed  →  keyring section
         ANYONE-granted, embargoed      →  escrow_entries section
         Restricted                     →  never bundled

Receive: keyring section   →  receiver Keyring
         escrow_entries    →  receiver Escrow
```

### Persistence

`.loot/escrow` — local-only, same discipline as `.loot/keyring`. Never bundled
(the bundle already carries escrow entries for receivers; the sender's own
escrow is their local state).

## Considered alternatives

- **Time-locked Keyring entries (`KeyEntry { key, available_after }`).** The
  Keyring itself refuses to serve the key early. Rejected: this moves the
  clock-check to a different module but doesn't close D — a caller can still
  read `key` directly from the Keyring struct or pass a manipulated `now` to
  `key_for`. The structural gap is the same.

- **Key escrow via external service.** A real server holds the key and releases
  it at `reveal_at`. Closes D completely, including against a modified binary.
  Rejected for now: requires a network dependency, a trust anchor, and a key
  release protocol. The Escrow module is the right local analogue and the seam
  is designed so an external service can replace it later.

- **Originator keeps Keyring access (asymmetric).** Originator's key goes to
  Keyring; peers get Escrow entries. Rejected: the CVE scenario is about
  accidental disclosure by tooling, which can happen to the originator too.
  Symmetric treatment requires no special-casing and gives a uniform guarantee.

## Consequences

- Embargo is now a structural guarantee for all identities: no Keyring entry
  exists for embargoed content before `flush` runs. `open()` is unchanged.
- The Workspace is the single flush call site; commands that don't read content
  (`log`, `bundle`) do not flush.
- `sealed::open` remains a pure authorization check — "given a Keyring, can
  this reader open this content now?" — with no new parameters.
- External-service escrow is a future drop-in: replace `Escrow::flush` with a
  network call and the rest of the system is unaffected.
- CONTEXT.md gains: **Escrow** (the new module), and the D-threat is removed
  from "Open / undecided".
