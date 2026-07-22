/**
 * @millerbyte/loot-sdk — in-memory loot for JS/TS agents.
 *
 * Slice 1 (#423): connect to a relay and read public content, entirely in RAM,
 * over the WASM crypto/codec core. `LootRepo` is the backend-agnostic interface
 * (#382); mutation, private content, and the physical backend arrive in later
 * slices.
 */
export { connectRelay } from "./repo.js";
export type { ConnectRelayOptions } from "./repo.js";
export { HttpRelayTransport } from "./relay-transport.js";
export type { RelayTransport, RelayResponse } from "./relay-transport.js";
export { openRepo } from "./physical.js";
export type { OpenRepoOptions } from "./physical.js";
export { SubprocessRunner } from "./loot-runner.js";
export type { LootRunner, RunResult, StreamHandle } from "./loot-runner.js";
export type {
  LootRepo,
  PathEntry,
  Visibility,
  EditOptions,
  VisibilityGuard,
  ReadStream,
  Status,
  ChangeSummary,
  ChangeKind,
} from "./repo.js";
export {
  LootError,
  TransportError,
  NotFoundError,
  AuthError,
  ConflictError,
  GuardError,
  SetupError,
} from "./errors.js";
export type { LootErrorCode } from "./errors.js";

// The diskless identity (generate / fromSeed / publicKey), straight from the
// WASM core (#383).
export { Identity } from "../wasm/loot_wasm.js";
