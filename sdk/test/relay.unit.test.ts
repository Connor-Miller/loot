/**
 * #432: the relay adapter's *branches* — transport-response classification
 * (401 → AuthError, non-2xx / connection-fail → TransportError), client-side
 * path-scoping, decode, and the compose/guard decision — proven against a FAKE
 * `RelayTransport`, no live `loot serve`. The seam (`connectRelay`'s
 * `opts.transport`) is what makes this possible.
 *
 * Decode/path-scoping need decodable bundle bytes, and the WASM core exposes no
 * bundle *encoder*, so those tests replay GOLDEN `/fetch` bytes captured from a
 * real relay (test/fixtures/relay-bundles.json — regenerate with
 * gen-relay-fixtures.mjs after a bundle format bump) against the fake. The real
 * round-trip stays a smoke in read.behavior / write.behavior.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  AuthError,
  GuardError,
  Identity,
  NotFoundError,
  TransportError,
  connectRelay,
  type RelayResponse,
  type RelayTransport,
} from "../src/index.js";
import { encodeFetchRequest } from "../wasm/loot_wasm.js";

const FX = JSON.parse(
  readFileSync(new URL("./fixtures/relay-bundles.json", import.meta.url), "utf8"),
) as {
  readme: string;
  other: string;
  readmeText: string;
  readmeOid: string;
  emptyBundle: string;
  metaBundle: string;
  scopedBundle: string;
};
const b64 = (s: string): Uint8Array => Uint8Array.from(Buffer.from(s, "base64"));
const hexToBytes = (hex: string): Uint8Array => {
  const o = new Uint8Array(hex.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return o;
};
const EMPTY = new Uint8Array(0);
const bytesEqual = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const ok = (body: Uint8Array): RelayResponse => ({ status: 200, body });

/** A programmable {@link RelayTransport}: `handler(endpoint, body, callIndex)`
 * returns a canned response or throws (connection failure); every post is
 * recorded so path-scoping request shapes can be asserted. */
class FakeTransport implements RelayTransport {
  readonly posts: { endpoint: string; body: Uint8Array }[] = [];
  constructor(private readonly handler: (endpoint: string, body: Uint8Array, call: number) => RelayResponse) {}
  post(endpoint: string, body: Uint8Array): Promise<RelayResponse> {
    const call = this.posts.length;
    this.posts.push({ endpoint, body });
    return Promise.resolve(this.handler(endpoint, body, call)); // handler may throw → connection failure
  }
}

describe("relay transport-response classification (fake transport)", () => {
  it("a 401 on /stow throws AuthError(unauthorized) carrying the offending pubkey", async () => {
    const identity = Identity.generate();
    const transport = new FakeTransport((endpoint) =>
      endpoint === "/stow" ? { status: 401, body: new TextEncoder().encode("not allow-listed") } : ok(b64(FX.emptyBundle)),
    );
    const repo = await connectRelay("http://relay.test", identity, { transport });
    await repo.edit("x.md", new TextEncoder().encode("hi"));
    await repo.describe("push it");

    const err = await repo.push().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthError);
    const pubkey = Array.from(identity.publicKey(), (x) => x.toString(16).padStart(2, "0")).join("");
    expect((err as AuthError).pubkey).toBe(pubkey);
    expect((err as AuthError).message).toContain(pubkey);
  });

  it("a connection failure (transport throws) surfaces as TransportError", async () => {
    const transport = new FakeTransport(() => {
      throw new Error("ECONNREFUSED");
    });
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    await expect(repo.list()).rejects.toBeInstanceOf(TransportError);
  });

  it("a non-2xx /fetch surfaces as TransportError", async () => {
    const transport = new FakeTransport(() => ({ status: 503, body: EMPTY }));
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    await expect(repo.list()).rejects.toBeInstanceOf(TransportError);
  });

  it("a non-2xx /negotiate (pull) surfaces as TransportError", async () => {
    const transport = new FakeTransport((endpoint) =>
      endpoint === "/negotiate" ? { status: 500, body: EMPTY } : ok(b64(FX.emptyBundle)),
    );
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    const drain = async () => {
      for await (const _ of repo.pull()) void _;
    };
    await expect(drain()).rejects.toBeInstanceOf(TransportError);
  });
});

describe("relay path-scoping + decode (fake transport, golden bundles)", () => {
  it("list decodes the meta bundle to both paths (snapshot fetch is unscoped)", async () => {
    const transport = new FakeTransport(() => ok(b64(FX.metaBundle)));
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    const entries = await repo.list();
    expect(entries).toContainEqual({ path: FX.readme, visibility: "public" });
    expect(entries).toContainEqual({ path: FX.other, visibility: "public" });
    // Snapshot is metadata-only: wants is empty (path-scoping is content, not names).
    expect(bytesEqual(transport.posts[0]!.body, encodeFetchRequest(EMPTY, EMPTY))).toBe(true);
  });

  it("read scopes the object fetch to the path's oid and decodes the public bytes", async () => {
    // First /fetch resolves the tree (meta); the scoped /fetch returns the object.
    const transport = new FakeTransport((_e, _b, call) => ok(b64(call === 0 ? FX.metaBundle : FX.scopedBundle)));
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });

    const bytes = await repo.read(FX.readme).bytes();
    expect(new TextDecoder().decode(bytes)).toBe(FX.readmeText);

    // The scoped fetch wants EXACTLY the readme oid, with have empty (#380).
    const scopedReq = encodeFetchRequest(EMPTY, hexToBytes(FX.readmeOid));
    expect(transport.posts.some((p) => bytesEqual(p.body, scopedReq))).toBe(true);
  });

  it("read of an absent path throws NotFoundError (from the decoded tree)", async () => {
    const transport = new FakeTransport(() => ok(b64(FX.metaBundle)));
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    await expect(repo.read("does-not-exist.md").bytes()).rejects.toBeInstanceOf(NotFoundError);
  });
});

describe("relay compose/guard decision (fake transport, golden meta bundle)", () => {
  it("demoting an established public path without allowDemote throws GuardError before stow", async () => {
    // The meta bundle holds readme.md as public; a private re-put is a demotion.
    const transport = new FakeTransport(() => ok(b64(FX.metaBundle)));
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    await repo.edit(FX.readme, new TextEncoder().encode("now secret"), { visibility: "private" });
    await repo.describe("demote readme");

    await expect(repo.push()).rejects.toBeInstanceOf(GuardError);
    // No /stow was ever attempted — a refused change stows nothing.
    expect(transport.posts.some((p) => p.endpoint === "/stow")).toBe(false);
  });

  it("a new path picks its visibility freely (no guard needed)", async () => {
    // Snapshot from meta, then accept the stow.
    const transport = new FakeTransport((endpoint) =>
      endpoint === "/stow" ? ok(EMPTY) : ok(b64(FX.metaBundle)),
    );
    const repo = await connectRelay("http://relay.test", Identity.generate(), { transport });
    await repo.edit("fresh.md", new TextEncoder().encode("brand new"), { visibility: "private" });
    await repo.describe("add a private new path");
    // Composes + stows without a GuardError (a new path has no prior visibility).
    await expect(repo.push()).resolves.toMatch(/^[0-9a-f]+$/);
  });
});
