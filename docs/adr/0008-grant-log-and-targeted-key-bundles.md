# Grant is a targeted bundle; the grant log is append-only and travels with bundles

## Status

accepted

## Context

Candidates 1 (revocation), 2 (visibility migration), and 5 (grant) from the
innovation backlog all require the same primitive: getting an existing content
key from one identity's Keyring into another identity's Keyring. That primitive
— grant — did not exist.

Two design questions had to be resolved:

**Where does auditability live?** A grant needs to be auditable, but the change
graph records *what content exists and who can see it*, not *who holds which
key*. Putting key handoffs in the DAG would conflate content history with key
management history and expose grant entries to relays who can't act on them.

**Does the grant log need to be secret?** A grant log entry `{ oid, grantee,
granted_at }` leaks the social graph of who granted whom access. This is beyond
what a SealedObject already reveals (its `grant_ids` field). The question is
whether relays should see this.

## Decision

**Identities are strings; secure channel is the security boundary.** There are
no keypairs or PKI. The grantor controls delivery by choosing who receives the
bundle. Security is only as strong as the bundle delivery channel — the same
model as sending a key over Signal. PKI is deferred.

**Grant is an out-of-band targeted bundle.** A grant bundle carries:
- The content key in the keyring section (reaching the grantee's Keyring on apply)
- A Grant log entry (`oid`, `grantee`, `granted_at`) in a new grant log section

The key travels to the grantee via a targeted send; the grant log entry travels
to all peers via normal bundle propagation.

**The grant log is append-only, fact-only, and travels in bundles.** It records
the *fact* of a grant (who, what OID, when), never the key itself. It is a
separate structure from the change graph and from the Keyring. Leaking the
social graph to relays is acceptable: a relay already knows from `grant_ids`
which identities are authorized; the grant log adds only the timing and
provenance of those grants.

## Considered alternatives

- **Grant as a Change in the DAG.** Rejected: conflates content history with
  key management history; relays see grant entries they can't act on; replay
  semantics become complex (do you re-grant on rebase?).

- **Grant log is local-only (like Keyring).** Rejected: no cross-peer audit
  trail without explicit sharing; undermines the "who had access when" story
  for compliance use cases.

- **Keypair identities + encrypt-to-pubkey.** Deferred: avoids the secure-
  channel requirement, but introduces PKI surface that would dominate the next
  several ADRs. The string + secure-channel model is sufficient for the current
  scope.

## Consequences

- `loot grant <path> <identity>` produces a targeted bundle carrying the key
  and a grant log entry. The grantor sends this bundle directly to the grantee.
- Every peer accumulates a grant log they can query: "who has been granted
  access to this path?"
- Revocation and visibility migration are built on top of this primitive.
- The grant log section is added to the bundle wire format alongside the
  existing keyring and escrow sections.
