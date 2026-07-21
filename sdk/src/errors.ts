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
 * The content is readable in principle but this session lacks the key — e.g.
 * private content whose key travels only via a grant (the grant flow is out of
 * slice 1; a v1 in-memory agent reads public content).
 */
export class AuthError extends LootError {
  constructor(message: string) {
    super("unauthorized", message);
    this.name = "AuthError";
  }
}
