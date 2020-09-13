import {
  WasmBundle,
  ChangeBuilder,
  decrypt,
  encodeFetchRequest,
  encodeNegotiateRequest,
} from "../wasm/loot_wasm.js";
import type { Identity } from "../wasm/loot_wasm.js";
import { decompress as zstdInflate } from "fzstd";
import { AuthError, GuardError, NotFoundError, TransportError } from "./errors.js";
import { HttpRelayTransport, type RelayResponse, type RelayTransport } from "./relay-transport.js";
import { type OverlayEntry, WorkingOverlay } from "./working-overlay.js";

export type Visibility = "public" | "private";

/** Options for authoring a path (`edit`). Omitting `visibility` inherits the
 * path's current visibility, or defaults a brand-new path to `public`. */
export interface EditOptions {
  visibility?: Visibility;
}

/** Guards that authorize a visibility change on an existing path. Without the
 * matching guard, a change of visibility is refused (loot never seals or reveals
 * content silently). `allowDemote` names paths that may go public→private;
 * `allowReveal` permits private→public. */
export interface VisibilityGuard {
  allowDemote?: string[];
  allowReveal?: boolean;
}

export interface PathEntry {
  path: string;
  visibility: Visibility;
}

/** How a path differs from the parent tree in the pending change. */
export type ChangeKind = "added" | "modified" | "removed";
export interface ChangeSummary {
  path: string;
  kind: ChangeKind;
}
export interface Status {
  /** The message set by `describe`, or `null` if the change is unnamed. */
  message: string | null;
  changes: ChangeSummary[];
}

/** The result of `read`: an `AsyncIterable<Uint8Array>` with a `.bytes()`
 * collector. A sealed object is one AES-GCM unit — it can't be authenticated
 * until fully in hand — so slice 1 yields it as a **single chunk** rather than
 * true chunked streaming; the iterable shape is the interface later slices grow
 * into (e.g. `pull` over many changes). */
export interface ReadStream extends AsyncIterable<Uint8Array> {
  bytes(): Promise<Uint8Array>;
  /** The visibility of the path being read (`public` or `private`). */
  visibility(): Promise<Visibility>;
}

/**
 * One `LootRepo` interface, backend-agnostic (#382). Slice 1 shipped the read
 * half; slice 2 (#424) adds capture-first authoring: `edit`/`remove` mutate an
 * in-RAM overlay that *is* the pending change, `describe` names it, and `push`
 * folds it into a signed change stowed on the relay.
 */
export interface LootRepo {
  list(): Promise<PathEntry[]>;
  read(path: string): ReadStream;
  /** Stage `bytes` at `path`. `opts.visibility` sets visibility explicitly;
   * omitted, it inherits the path's current visibility (new path → `public`). */
  edit(path: string, bytes: Uint8Array, opts?: EditOptions): Promise<void>;
  remove(path: string): Promise<void>;
  /** Name the pending change; `guard` may be supplied here or at `push`. */
  describe(message: string, guard?: VisibilityGuard): Promise<void>;
  status(): Promise<Status>;
  diff(): Promise<ChangeSummary[]>;
  /** Sign + stow the pending change; returns its durable change-id (hex).
   * `guard` authorizes any visibility changes (unioned with `describe`'s). */
  push(guard?: VisibilityGuard): Promise<string>;
  /**
   * Stream changes authored elsewhere, advancing the session's view so later
   * `read`/`list` reflect them. Yields one chunk per new change; a pull with
   * nothing new completes cleanly (no chunks, no error).
   */
  pull(): AsyncIterable<Uint8Array>;
}

interface TreeEntry {
  path: string;
  oid: string;
  visibility: string;
}
interface ChangeView {
  id: string;
  message: string;
  parents: string[];
  tree: TreeEntry[];
}

const EMPTY = new Uint8Array(0);

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function toVisibility(raw: string): Visibility {
  // The core's identity-plaintext tier is `internal` (ADR 0041); `public` is a
  // back-compat alias. Either maps to the SDK's binary `public`.
  return raw === "internal" || raw === "public" ? "public" : "private";
}

/** A 2xx relay response. */
function isOk(status: number): boolean {
  return status >= 200 && status < 300;
}

/**
 * Assert a `/stow` response is an acceptance, else throw — the relay's write-path
 * verdict, kept adapter-side so it is unit-testable against a fake transport
 * (#432). A 2xx is a clean stow. A 401 is the allow-list rejecting this signing
 * key: the SDK always signs in the WASM core, so it means the key is not enrolled
 * — throw an `AuthError` carrying the offending pubkey so an operator knows which
 * to enroll (#383: attempt & report, no pre-check / auto-enroll / downgrade).
 * Anything else is transport.
 */
function assertStowAccepted(resp: RelayResponse, identity: Identity, url: string): void {
  if (isOk(resp.status)) return;
  if (resp.status === 401) {
    const pubkey = bytesToHex(identity.publicKey());
    const detail = new TextDecoder().decode(resp.body).trim();
    throw new AuthError(
      `relay rejected push: signing key ${pubkey} is not on the allow-list` + (detail ? ` (${detail})` : ""),
      pubkey,
    );
  }
  throw new TransportError(`relay ${url}/stow returned ${resp.status}`);
}

/**
 * Resolve each edited path's target visibility and enforce the guard model —
 * BEFORE composing, so a refused change stows nothing. Pure and relay-specific
 * (physical delegates visibility to the binary): a new path picks its visibility
 * freely; changing an *established* path's visibility needs the matching guard
 * (`allowDemote` names public→private; `allowReveal` permits private→public).
 * Extracted from `push` so it is unit-testable with hand-built trees (#432).
 */
function resolvePushVisibilities<P>(
  overlay: Map<string, OverlayEntry<P>>,
  existing: Map<string, Visibility>,
  guard: VisibilityGuard,
): Map<string, Visibility> {
  const resolved = new Map<string, Visibility>();
  for (const [path, pending] of overlay) {
    if (pending.kind !== "put") continue;
    const prior = existing.get(path);
    const target: Visibility = pending.visibility ?? prior ?? "public";
    if (prior !== undefined && target !== prior) {
      if (prior === "public" && !(guard.allowDemote ?? []).includes(path)) {
        throw new GuardError(
          `refusing to make ${path} private without allowDemote (public→private is a demotion)`,
        );
      }
      if (prior === "private" && !guard.allowReveal) {
        throw new GuardError(
          `refusing to make ${path} public without allowReveal (private→public reveals sealed content)`,
        );
      }
    }
    resolved.set(path, target);
  }
  return resolved;
}

class RelayRepo implements LootRepo {
  /** Capture-first pending change (#429). Relay's payload is the `Uint8Array`
   * bytes to seal; the overlay owns the message + guard union + status kinds. */
  private readonly working = new WorkingOverlay<Uint8Array>();
  /**
   * Change-ids (hex, the 32-byte change-graph node id) this session already
   * holds. `pull` sends this as its `/negotiate` `have` so the relay ships only
   * newer changes, and folds each returned id back in so a repeat pull with
   * nothing new returns empty. `push` records its own change so the session
   * never re-pulls what it just authored.
   */
  private readonly have = new Set<string>();
  /** In-RAM keyring for content this identity authored privately: object-id
   * (hex) → the content key ECIES-wrapped to this identity. Lets the author read
   * their own just-sealed content back this session by unwrapping the key. The
   * cross-session delivery of these grants to OTHER parties is deferred (#383). */
  private readonly privateKeyring = new Map<string, Uint8Array>();

  constructor(
    private readonly url: string,
    private readonly identity: Identity,
    private readonly transport: RelayTransport,
  ) {}

  /** POST through the transport, mapping a connection failure to `TransportError`.
   * Response *classification* stays with each caller (fetch/stow/negotiate map
   * status differently), so this only owns the unreachable-relay case. */
  private async post(endpoint: string, body: Uint8Array): Promise<RelayResponse> {
    try {
      return await this.transport.post(endpoint, body);
    } catch (e) {
      throw new TransportError(`relay unreachable at ${this.url}: ${String(e)}`);
    }
  }

  private async fetchBundle(have: Uint8Array, wants: Uint8Array): Promise<WasmBundle> {
    const resp = await this.post("/fetch", encodeFetchRequest(have, wants));
    if (!isOk(resp.status)) {
      throw new TransportError(`relay ${this.url}/fetch returned ${resp.status}`);
    }
    return WasmBundle.fromBytes(resp.body);
  }

  /**
   * The current head(s) and merged tree — the parent state a new change builds
   * on. Path scoping (#380) is a content-bytes optimization only; the whole tree
   * always travels, so this metadata fetch is `wants = []`.
   */
  private async snapshot(): Promise<{ parents: string[]; tree: TreeEntry[] }> {
    const meta = await this.fetchBundle(EMPTY, EMPTY);
    const changes: ChangeView[] = JSON.parse(meta.changesJson());
    if (changes.length === 0) return { parents: [], tree: [] };
    const parented = new Set(changes.flatMap((c) => c.parents));
    const byId = new Map(changes.map((c) => [c.id, c]));
    // Heads are changes nobody names as a parent; a later head's write wins a
    // shared path (mirrors the engine's current_tree union).
    const parents = changes.filter((c) => !parented.has(c.id)).map((c) => c.id);
    const tree = new Map<string, TreeEntry>();
    for (const id of parents) {
      for (const entry of byId.get(id)!.tree) tree.set(entry.path, entry);
    }
    return { parents, tree: [...tree.values()] };
  }

  async list(): Promise<PathEntry[]> {
    const { tree } = await this.snapshot();
    return tree.map((e) => ({ path: e.path, visibility: toVisibility(e.visibility) }));
  }

  read(path: string): ReadStream {
    const resolve = async (): Promise<TreeEntry> => {
      const { tree } = await this.snapshot();
      const entry = tree.find((e) => e.path === path);
      if (!entry) throw new NotFoundError(`path not found: ${path}`);
      return entry;
    };

    const load = async (): Promise<Uint8Array> => {
      const entry = await resolve();

      // Scoped fetch: only this object's bytes. `have = []` is required — the
      // relay gathers object bytes + public keys by walking the changes NOT in
      // `have`, so scoping the metadata out would drop the object itself.
      const oid = hexToBytes(entry.oid);
      const bundle = await this.fetchBundle(EMPTY, oid);
      const ciphertext = bundle.object(oid);
      const nonce = bundle.nonce(oid);
      if (!ciphertext || !nonce) {
        throw new NotFoundError(`object bytes for ${path} did not travel`);
      }

      // Public content ships its key in the bundle; private content's key never
      // does (the relay stores only ciphertext). For a path THIS session sealed,
      // unwrap the author-held key from the RAM keyring; otherwise it is private
      // content we cannot read (cross-session grant delivery is deferred, #383).
      const publicKey = bundle.publicKey(oid);
      if (publicKey) {
        const plain = decrypt(nonce, ciphertext, publicKey);
        return bundle.compressed(oid) ? zstdInflate(plain) : plain;
      }
      const wrapped = this.privateKeyring.get(entry.oid);
      if (!wrapped) {
        throw new AuthError(
          `no content key for ${path}: private content's key is held only by its author (cross-session grant delivery is deferred)`,
        );
      }
      const contentKey = this.identity.unsealKey(wrapped);
      // Private content is never compressed (S2, ADR 0020), so no zstd inflate.
      return decrypt(nonce, ciphertext, contentKey);
    };

    let cached: Promise<Uint8Array> | undefined;
    const bytes = () => (cached ??= load());
    return {
      bytes,
      async visibility() {
        return toVisibility((await resolve()).visibility);
      },
      async *[Symbol.asyncIterator]() {
        yield await bytes();
      },
    };
  }

  // --- capture-first authoring (#424) --------------------------------------

  async edit(path: string, bytes: Uint8Array, opts?: EditOptions): Promise<void> {
    this.working.put(path, bytes, opts?.visibility);
  }

  async remove(path: string): Promise<void> {
    this.working.remove(path);
  }

  async describe(message: string, guard?: VisibilityGuard): Promise<void> {
    this.working.describe(message, guard);
  }

  async status(): Promise<Status> {
    const { tree } = await this.snapshot();
    return {
      message: this.working.message,
      changes: this.working.classify(new Set(tree.map((e) => e.path))),
    };
  }

  async diff(): Promise<ChangeSummary[]> {
    return (await this.status()).changes;
  }

  async push(guard?: VisibilityGuard): Promise<string> {
    // The two push preconditions (usage bugs, plain Error) live in the overlay.
    this.working.requirePushable();
    const message = this.working.message!; // requirePushable guarantees non-null
    const effectiveGuard = this.working.effectiveGuard(guard);
    const { parents, tree } = await this.snapshot();
    const existing = new Map(tree.map((e) => [e.path, toVisibility(e.visibility)]));
    const overlay = new Map(this.working.entries());

    // Resolve each edited path's visibility (inherit / new-path default) and
    // enforce the guard model BEFORE composing — a refused change stows nothing.
    // This client-side visibility resolution + GuardError enforcement is
    // genuinely relay behaviour (physical delegates to the binary), so it lives
    // in this file — extracted to a pure helper so it is unit-testable (#432).
    const resolved = resolvePushVisibilities(overlay, existing, effectiveGuard);

    // Compose the full-tree change in the WASM core: carry unchanged paths,
    // seal + put edited ones, skip removed. Composition (id fold, signing,
    // sealing, bundle encode, envelope) never leaves Rust.
    const builder = new ChangeBuilder(this.identity, message);
    for (const id of parents) builder.addParent(hexToBytes(id));
    for (const entry of tree) {
      if (overlay.has(entry.path)) continue; // removed (skip) or replaced (put below)
      builder.carry(entry.path, hexToBytes(entry.oid), toVisibility(entry.visibility));
    }
    for (const [path, pending] of overlay) {
      if (pending.kind === "put") builder.put(path, pending.payload, resolved.get(path)!);
    }
    const authored = builder.finish();

    // File the author's private grants (content keys ECIES-wrapped to self) into
    // the RAM keyring so read-back works; they do NOT travel in the envelope.
    const grants: { oid: string; wrapped: string }[] = JSON.parse(authored.privateGrantsJson);
    for (const g of grants) this.privateKeyring.set(g.oid, hexToBytes(g.wrapped));

    await this.stow(authored.envelope);
    // Record the authored change (by its graph node id, the `/negotiate` unit)
    // so a later `pull` does not stream our own change back as "new".
    this.have.add(bytesToHex(authored.versionId));
    this.working.clear();
    return bytesToHex(authored.changeId);
  }

  private async stow(envelope: Uint8Array): Promise<void> {
    const resp = await this.post("/stow", envelope);
    // 2xx → clean; 401 → this signing key is not allow-listed (AuthError + the
    // offending pubkey); anything else → transport. Kept in a pure helper so the
    // write-path verdict is unit-testable against a fake transport (#432).
    assertStowAccepted(resp, this.identity, this.url);
  }

  // --- streaming pull (#427) -----------------------------------------------

  /**
   * Bring down changes authored elsewhere. Sends the session's `have`
   * change-ids to the relay's `/negotiate`, which returns a bundle of every
   * change not in that set, then yields each one the session did not already
   * hold — folding its id into `have` as it goes, so a later pull fetches only
   * what is newer still and a pull with nothing new completes with no chunks.
   *
   * Streaming is per-change: a sync bundle is one codec unit (it decodes whole,
   * like a sealed object in `read`), but the v1 commitment is that `pull`
   * surfaces changes one at a time rather than as a buffered batch — the caller
   * observes each as `have` advances, and stopping early stops the work.
   *
   * The session's read view is live (each `read`/`list` re-resolves the head
   * from the relay), so those already reflect a pulled change; `pull`'s durable
   * effect is advancing `have`. Each yielded chunk is the new change's metadata
   * as UTF-8 JSON (`{ id, message, parents, tree }`).
   */
  async *pull(): AsyncGenerator<Uint8Array> {
    const known = [...this.have];
    const haveBytes = new Uint8Array(known.length * 32);
    known.forEach((id, i) => haveBytes.set(hexToBytes(id), i * 32));

    const resp = await this.post("/negotiate", encodeNegotiateRequest(haveBytes));
    if (!isOk(resp.status)) {
      throw new TransportError(`relay ${this.url}/negotiate returned ${resp.status}`);
    }

    const bundle = WasmBundle.fromBytes(resp.body);
    const changes: ChangeView[] = JSON.parse(bundle.changesJson());
    const encoder = new TextEncoder();
    for (const change of changes) {
      if (this.have.has(change.id)) continue; // already held — not new
      this.have.add(change.id);
      yield encoder.encode(JSON.stringify(change));
    }
  }
}

/** Options for {@link connectRelay}. `transport` injects the network seam
 * (default: an {@link HttpRelayTransport} over `url`), so tests drive the relay
 * branches without a live `loot serve`. */
export interface ConnectRelayOptions {
  transport?: RelayTransport;
}

/**
 * Connect to a relay and drive a loot repo entirely in memory — no `.loot/` on
 * disk (#382/#383). `identity` is a WASM `Identity` (generate / fromSeed); a
 * pre-registered key (`fromSeed`) is what the relay allow-list gates `push` on.
 */
export function connectRelay(
  url: string,
  identity: Identity,
  opts?: ConnectRelayOptions,
): Promise<LootRepo> {
  const base = url.replace(/\/+$/, "");
  const transport = opts?.transport ?? new HttpRelayTransport(base);
  return Promise.resolve(new RelayRepo(base, identity, transport));
}
