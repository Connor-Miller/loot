/**
 * Typed errors (#382). The read path (slice 1) surfaces `transport`,
 * `not_found`, and `unauthorized`; the write path adds `conflict` (slice 3).
 * Every error carries a string-literal `code` so callers branch programmatically
 * instead of matching messages.
 */
export type LootErrorCode =
  | "transport"
  | "not_found"
  | "unauthorized"
  | "conflict"
  | "unsupported";

export class LootError extends Error {
  readonly code: LootErrorCode;
  constructor(code: LootErrorCode, message: string) {
    super(message);
    this.name = "LootError";
    this.code = code;
  }
}

/** The relay was unreachable or the HTTP call failed (distinct from a loot-level rejection). */
export class TransportError extends LootError {
  constructor(message: string) {
    super("transport", message);
    this.name = "TransportError";
  }
}

/** A path or object address is absent from the repo. */
export class NotFoundError extends LootError {
  constructor(message: string) {
    super("not_found", message);
    this.name = "NotFoundError";
  }
}

/**
 * The session isn't authorized for the operation. Two shapes:
 *  - read: the content is readable in principle but this session lacks the key
 *    (e.g. private content whose key travels only via a grant — out of slice 1);
 *  - push: the relay's allow-list rejected the signing key (slice 3). In that
 *    case `pubkey` carries the offending key (hex) so an operator knows which to
 *    enroll — the SDK never pre-checks, auto-enrolls, or downgrades (#383).
 */
export class AuthError extends LootError {
  /** The offending signing key (hex), when the failure is an allow-list rejection. */
  readonly pubkey?: string;
  constructor(message: string, pubkey?: string) {
    super("unauthorized", message);
    this.name = "AuthError";
    this.pubkey = pubkey;
  }
}

/**
 * The pending change's parent has moved; the caller should re-pull and rebuild
 * (referenced by #382).
 *
 * NOTE — deferred in slice 3. The relay's `/stow` is append-only and *never*
 * rejects a moved parent: concurrent forks off a shared base both succeed and
 * accumulate as uncollapsed tips (loot-core `stow_accumulates_concurrent_forks_
 * without_conflict` — "convergence is the keyholders' job on pull, not the
 * relay's"). And the capture-first `push` re-snapshots the heads immediately
 * before composing, so it always builds on the *current* parent — there is no
 * pinned earlier parent to have moved. Cleanly detecting a moved parent would
 * need an optimistic-concurrency model (pin the head at edit-start, compare at
 * push) that slice 2's overlay doesn't carry. This type is exported so callers
 * can branch on `code: "conflict"` once that model lands; slice 3 does not throw
 * it (faking it against a relay that accepts forks would be wrong).
 */
export class ConflictError extends LootError {
  constructor(message: string) {
    super("conflict", message);
    this.name = "ConflictError";
  }
}
