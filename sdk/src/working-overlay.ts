/**
 * WorkingOverlay<P> (#429) — the capture-first pending-change behaviour both
 * `LootRepo` backends compose, extracted from the two adapters that used to copy
 * it. Pure and synchronous: it never `fetch`es or spawns. `classify` takes the
 * committed-tree baseline as a *parameter*, so the same core serves the relay
 * (baseline from a `/fetch` snapshot) and the physical backend (baseline from
 * `surface`). Generic over the put payload `P` — relay stows the `Uint8Array`
 * bytes to seal, physical the absolute path written.
 *
 * The SDK-tier analogue of loot's Working change: the in-RAM overlay that *is*
 * the pending change until `push` folds it into a signed change. Deliberately
 * OUT of scope (stays in the adapters): the transport, the committed-baseline
 * *source*, relay's client-side visibility resolution + `GuardError`
 * enforcement, the private keyring, and `have`-tracking.
 */
import type { ChangeSummary, Visibility, VisibilityGuard } from "./repo.js";

/** One overlay slot: a path replaced with a new payload (with an optionally
 * explicit `visibility` — `undefined` means "inherit"), or removed. A
 * discriminated union so the fold site narrows on `kind` and reads `payload`
 * without a non-null assertion. */
export type OverlayEntry<P> =
  | { kind: "put"; payload: P; visibility?: Visibility }
  | { kind: "remove" };

/** Union two guards: paths named by either may demote; either enabling reveal
 * enables it. Lets `describe`-time and `push`-time guards combine. */
function mergeGuards(a: VisibilityGuard, b: VisibilityGuard): VisibilityGuard {
  return {
    allowDemote: [...new Set([...(a.allowDemote ?? []), ...(b.allowDemote ?? [])])],
    allowReveal: Boolean(a.allowReveal || b.allowReveal),
  };
}

export class WorkingOverlay<P> {
  private readonly overlay = new Map<string, OverlayEntry<P>>();
  private msg: string | null = null;
  private guard: VisibilityGuard = {};

  /** Stage `payload` at `path`; `visibility` undefined means "inherit". */
  put(path: string, payload: P, visibility?: Visibility): void {
    this.overlay.set(path, { kind: "put", payload, visibility });
  }

  remove(path: string): void {
    this.overlay.set(path, { kind: "remove" });
  }

  /** Name the pending change; any `guard` accumulates (describe-time and
   * push-time guards union — loot never seals or reveals silently). */
  describe(message: string, guard?: VisibilityGuard): void {
    this.msg = message;
    if (guard) this.guard = mergeGuards(this.guard, guard);
  }

  /** The message set by `describe`, or `null` while the change is unnamed. */
  get message(): string | null {
    return this.msg;
  }

  /** How many paths are staged. */
  get size(): number {
    return this.overlay.size;
  }

  /** Pure kind derivation against a committed-tree baseline: a removed slot is
   * `removed`, a put is `modified` if the path is already committed else
   * `added`. Takes the baseline as a parameter — it never fetches it. */
  classify(committed: Set<string>): ChangeSummary[] {
    return [...this.overlay.entries()].map(([path, p]) => ({
      path,
      kind: p.kind === "remove" ? "removed" : committed.has(path) ? "modified" : "added",
    }));
  }

  /** The guard authorizing this push: the accumulated describe-time guard
   * unioned with an optional push-time guard. */
  effectiveGuard(pushGuard?: VisibilityGuard): VisibilityGuard {
    return mergeGuards(this.guard, pushGuard ?? {});
  }

  /** Throw the two push preconditions. These are caller usage bugs (no message
   * / nothing staged), so a plain `Error`, not a typed `LootError`. */
  requirePushable(): void {
    if (this.msg === null) {
      throw new Error("describe the change before pushing (no message set)");
    }
    if (this.overlay.size === 0) {
      throw new Error("nothing to push (no pending edits)");
    }
  }

  /** The composition seam: each staged slot, for the adapter to fold into its
   * own change (relay carries/seals/puts in the WASM core; physical delegates to
   * the binary). */
  entries(): Iterable<[string, OverlayEntry<P>]> {
    return this.overlay.entries();
  }

  /** Reset after a push: drop the overlay, message, and accumulated guard. */
  clear(): void {
    this.overlay.clear();
    this.msg = null;
    this.guard = {};
  }
}
