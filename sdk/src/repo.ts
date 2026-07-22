import {
  WasmBundle,
  ChangeBuilder,
  decrypt,
  encodeFetchRequest,
  encodeNegotiateRequest,
} from "../wasm/loot_wasm.js";
import type { Identity } from "../wasm/loot_wasm.js";
import { decompress as zstdInflate } from "fzstd";
import { AuthError, NotFoundError, TransportError } from "./errors.js";

export type Visibility = "public" | "private";

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
  edit(path: string, bytes: Uint8Array): Promise<void>;
  remove(path: string): Promise<void>;
  describe(message: string): Promise<void>;
  status(): Promise<Status>;
  diff(): Promise<ChangeSummary[]>;
  /** Sign + stow the pending change; returns its durable change-id (hex). */
  push(): Promise<string>;
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

/** The overlay: a path is either replaced with new bytes, or removed. */
type Pending = { kind: "put"; bytes: Uint8Array } | { kind: "remove" };

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
  return raw === "public" ? "public" : "private";
}

class RelayRepo implements LootRepo {
  private readonly overlay = new Map<string, Pending>();
  private message: string | null = null;
  /**
   * Change-ids (hex, the 32-byte change-graph node id) this session already
   * holds. `pull` sends this as its `/negotiate` `have` so the relay ships only
   * newer changes, and folds each returned id back in so a repeat pull with
   * nothing new returns empty. `push` records its own change so the session
   * never re-pulls what it just authored.
   */
  private readonly have = new Set<string>();

  constructor(
    private readonly url: string,
    private readonly identity: Identity,
  ) {}

  private async fetchBundle(have: Uint8Array, wants: Uint8Array): Promise<WasmBundle> {
    const body = encodeFetchRequest(have, wants);
    let resp: Response;
    try {
      resp = await fetch(`${this.url}/fetch`, {
        method: "POST",
        body,
        headers: { "content-type": "application/octet-stream" },
      });
    } catch (e) {
      throw new TransportError(`relay unreachable at ${this.url}: ${String(e)}`);
    }
    if (!resp.ok) {
      throw new TransportError(`relay /fetch returned ${resp.status} ${resp.statusText}`);
    }
    const bytes = new Uint8Array(await resp.arrayBuffer());
    return WasmBundle.fromBytes(bytes);
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
    const load = async (): Promise<Uint8Array> => {
      const { tree } = await this.snapshot();
      const entry = tree.find((e) => e.path === path);
      if (!entry) throw new NotFoundError(`path not found: ${path}`);

      // Scoped fetch: only this object's bytes. `have = []` is required — the
      // relay gathers object bytes + public keys by walking the changes NOT in
      // `have`, so scoping the metadata out would drop the object itself.
      const oid = hexToBytes(entry.oid);
      const bundle = await this.fetchBundle(EMPTY, oid);
      const ciphertext = bundle.object(oid);
      const nonce = bundle.nonce(oid);
      const key = bundle.publicKey(oid);
      if (!ciphertext || !nonce) {
        throw new NotFoundError(`object bytes for ${path} did not travel`);
      }
      if (!key) {
        throw new AuthError(
          `no content key for ${path}: private content's key travels only via a grant (out of slice 1)`,
        );
      }
      const plain = decrypt(nonce, ciphertext, key);
      return bundle.compressed(oid) ? zstdInflate(plain) : plain;
    };

    let cached: Promise<Uint8Array> | undefined;
    const bytes = () => (cached ??= load());
    return {
      bytes,
      async *[Symbol.asyncIterator]() {
        yield await bytes();
      },
    };
  }

  // --- capture-first authoring (#424) --------------------------------------

  async edit(path: string, bytes: Uint8Array): Promise<void> {
    this.overlay.set(path, { kind: "put", bytes });
  }

  async remove(path: string): Promise<void> {
    this.overlay.set(path, { kind: "remove" });
  }

  async describe(message: string): Promise<void> {
    this.message = message;
  }

  async status(): Promise<Status> {
    const { tree } = await this.snapshot();
    const existing = new Set(tree.map((e) => e.path));
    const changes: ChangeSummary[] = [...this.overlay.entries()].map(([path, p]) => ({
      path,
      kind: p.kind === "remove" ? "removed" : existing.has(path) ? "modified" : "added",
    }));
    return { message: this.message, changes };
  }

  async diff(): Promise<ChangeSummary[]> {
    return (await this.status()).changes;
  }

  async push(): Promise<string> {
    // Caller preconditions (usage bugs), not loot-domain errors — a plain Error,
    // not a typed LootError, since "conflict" means a real same-path bounce.
    if (this.message === null) {
      throw new Error("describe the change before pushing (no message set)");
    }
    if (this.overlay.size === 0) {
      throw new Error("nothing to push (no pending edits)");
    }
    const { parents, tree } = await this.snapshot();

    // Compose the full-tree change in the WASM core: carry unchanged paths,
    // seal + put edited ones, skip removed. Composition (id fold, signing,
    // bundle encode, envelope) never leaves Rust.
    const builder = new ChangeBuilder(this.identity, this.message);
    for (const id of parents) builder.addParent(hexToBytes(id));
    for (const entry of tree) {
      const pending = this.overlay.get(entry.path);
      if (pending) continue; // removed (skip) or replaced (put below)
      builder.carry(entry.path, hexToBytes(entry.oid), toVisibility(entry.visibility));
    }
    for (const [path, pending] of this.overlay) {
      if (pending.kind === "put") builder.put(path, pending.bytes, "public");
    }
    const authored = builder.finish();

    await this.stow(authored.envelope);
    // Record the authored change (by its graph node id, the `/negotiate` unit)
    // so a later `pull` does not stream our own change back as "new".
    this.have.add(bytesToHex(authored.versionId));
    this.overlay.clear();
    this.message = null;
    return bytesToHex(authored.changeId);
  }

  private async stow(envelope: Uint8Array): Promise<void> {
    let resp: Response;
    try {
      resp = await fetch(`${this.url}/stow`, {
        method: "POST",
        body: envelope,
        headers: { "content-type": "application/octet-stream" },
      });
    } catch (e) {
      throw new TransportError(`relay unreachable at ${this.url}: ${String(e)}`);
    }
    if (resp.ok) return;
    // The relay rejects an unverifiable push with 401 (loot-net `handle_stow` →
    // `identity::unwrap_envelope`, which maps both a bad signature and a
    // non-allow-listed key to `BadSignature`/UNAUTHORIZED). The SDK always signs
    // its envelope in the WASM core, so a 401 here means this key is not on the
    // relay's allow-list — surface it as `unauthorized`, carrying the offending
    // pubkey so an operator knows which key to enroll (#383: attempt & report,
    // no pre-check / auto-enroll / downgrade). Any other non-2xx is a genuine
    // transport/relay failure.
    if (resp.status === 401) {
      const pubkey = bytesToHex(this.identity.publicKey());
      const detail = (await resp.text().catch(() => "")).trim();
      throw new AuthError(
        `relay rejected push: signing key ${pubkey} is not on the allow-list` +
          (detail ? ` (${detail})` : ""),
        pubkey,
      );
    }
    throw new TransportError(`relay /stow returned ${resp.status} ${resp.statusText}`);
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

    let resp: Response;
    try {
      resp = await fetch(`${this.url}/negotiate`, {
        method: "POST",
        body: encodeNegotiateRequest(haveBytes),
        headers: { "content-type": "application/octet-stream" },
      });
    } catch (e) {
      throw new TransportError(`relay unreachable at ${this.url}: ${String(e)}`);
    }
    if (!resp.ok) {
      throw new TransportError(`relay /negotiate returned ${resp.status} ${resp.statusText}`);
    }

    const bundle = WasmBundle.fromBytes(new Uint8Array(await resp.arrayBuffer()));
    const changes: ChangeView[] = JSON.parse(bundle.changesJson());
    const encoder = new TextEncoder();
    for (const change of changes) {
      if (this.have.has(change.id)) continue; // already held — not new
      this.have.add(change.id);
      yield encoder.encode(JSON.stringify(change));
    }
  }
}

/**
 * Connect to a relay and drive a loot repo entirely in memory — no `.loot/` on
 * disk (#382/#383). `identity` is a WASM `Identity` (generate / fromSeed); a
 * pre-registered key (`fromSeed`) is what the relay allow-list gates `push` on.
 */
export function connectRelay(url: string, identity: Identity): Promise<LootRepo> {
  return Promise.resolve(new RelayRepo(url.replace(/\/+$/, ""), identity));
}
