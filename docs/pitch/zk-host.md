# The host that cannot read your code

Working notes for the zero-knowledge-host pitch. Sealed `restricted=connor`
(ADR 0026) — this file is the milestone's genuinely-private content: it rides
the relay as ciphertext, agents clone around it, and git never sees it.

## The one-liner

Every code host you can buy reads your code. Not "may read" — *reads*: search
indexing, dedup, abuse scanning, model training. loot's relay physically
cannot: it stores ciphertext addressed by ciphertext, holds no keys, and
learned nothing when it was breached.

## Why now (raw)

- AI coding agents make third-party code custody radioactive: the host that
  can read your repo can train on it, and every enterprise knows it.
- "Private repo" is a permission bit on the host's database. This is a key
  that never leaves your machines. Different claim entirely.
- Services that DO need plaintext (CI, code search) become explicit, audited
  grants to service identities — a feature, not a hole: you can enumerate
  every party that can read a path, cryptographically.

## Honest limits (keep these in the pitch)

- Metadata is visible: object counts, sizes, push cadence, peer pubkeys.
- Embargo reveal trusts the relay operator's clock (holder-adversary-proof,
  not operator-proof) until drand timelock hardening lands.
- The milestone proof is one dev + agents on one machine; multi-human trust
  texture is unproven.

## Proof artifact

This repo. The milestone evidence (docs/evidence/loot-hosts-loot.md) is the
demo: if you're reading this file, you're a keyholder — the relay hosting it
is not.
