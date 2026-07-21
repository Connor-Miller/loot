import { WasmBundle, decrypt, encodeFetchRequest } from "../wasm/loot_wasm.js";
import type { Identity } from "../wasm/loot_wasm.js";
import { decompress as zstdInflate } from "fzstd";
import { AuthError, NotFoundError, TransportError } from "./errors.js";

export type Visibility = "public" | "private";

export interface PathEntry {
  path: string;
  visibility: Visibility;
}

/**
 * The result of `read`: an `AsyncIterable<Uint8Array>` with a `.bytes()`
 * collector. A sealed object is one AES-GCM unit — it can't be authenticated
 * until fully in hand — so slice 1 yields it as a **single chunk** rather than
 * true chunked streaming; the iterable shape is the interface later slices grow
 * into (e.g. `pull` over many changes).
 */
export interface ReadStream extends AsyncIterable<Uint8Array> {
  bytes(): Promise<Uint8Array>;
}

/**
 * One `LootRepo` interface, backend-agnostic (#382). Slice 1 ships the
 * in-memory backend (`connectRelay`) and the read half (`list`/`read`);
 * mutation and the physical backend arrive in later slices.
 */
export interface LootRepo {
  list(): Promise<PathEntry[]>;
  read(path: string): ReadStream;
}

// The relay wire uses the same visibility strings the WASM codec emits, but a
// tree entry can be embargoed/restricted too; the SDK surface collapses anything
// non-public to "private" for v1.
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
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toVisibility(raw: string): Visibility {
  return raw === "public" ? "public" : "private";
}

class RelayRepo implements LootRepo {
  // `identity` is unused on the ungated read path but is the handle the write
  // path (slice 2) signs with; held so the constructor contract matches #382/#383.
  constructor(
    private readonly url: string,
    private readonly identity: Identity,
  ) {}

  /**
   * One relay `/fetch` round trip. `have` = change-ids already held, `wants` =
   * object addresses whose bytes are needed (both flat 32-byte concatenations).
   * The request framing is produced by the WASM core so the wire format can
   * never drift from the binary's; the response is decoded by the WASM codec.
   */
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
   * The current tree (path → oid/visibility), resolved by pulling the change
   * graph metadata (no object bytes) and merging the head manifests. Path
   * scoping (#380) is a *content-bytes* optimization only — the whole tree
   * always travels — so this metadata fetch is `wants = []`.
   */
  private async currentTree(): Promise<TreeEntry[]> {
    const meta = await this.fetchBundle(EMPTY, EMPTY);
    const changes: ChangeView[] = JSON.parse(meta.changesJson());
    if (changes.length === 0) return [];
    const parents = new Set(changes.flatMap((c) => c.parents));
    const byId = new Map(changes.map((c) => [c.id, c]));
    // Heads are changes nobody names as a parent; a later head's write wins a
    // shared path (mirrors the engine's current_tree union).
    const heads = changes.filter((c) => !parents.has(c.id));
    const tree = new Map<string, TreeEntry>();
    for (const head of heads) {
      for (const entry of byId.get(head.id)!.tree) {
        tree.set(entry.path, entry);
      }
    }
    return [...tree.values()];
  }

  async list(): Promise<PathEntry[]> {
    const tree = await this.currentTree();
    return tree.map((e) => ({ path: e.path, visibility: toVisibility(e.visibility) }));
  }

  read(path: string): ReadStream {
    const load = async (): Promise<Uint8Array> => {
      const tree = await this.currentTree();
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

      // WASM decrypt yields the (possibly zstd-compressed) plaintext; public
      // content is inflated host-side, since zstd is not in the wasm core.
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
}

/**
 * Connect to a relay and drive a loot repo entirely in memory — no `.loot/` on
 * disk (#382/#383). `identity` is a WASM `Identity` (generate / fromSeed).
 */
export function connectRelay(url: string, identity: Identity): Promise<LootRepo> {
  return Promise.resolve(new RelayRepo(url.replace(/\/+$/, ""), identity));
}
