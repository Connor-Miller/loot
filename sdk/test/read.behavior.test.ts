/**
 * Seam 1 (#423): drive the in-memory `LootRepo` read path against a REAL relay.
 *
 * The relay is the actual `loot serve` binary; the repo state is seeded with the
 * actual `loot` CLI (init → author → finalize → push). No mocks — a green read
 * is the whole stack working: WASM codec + fetch transport + client-side
 * path-scoping + host-side zstd inflate.
 *
 * The read-contract assertions live in `runReadContract(makeRepo)` so the same
 * suite runs verbatim against any `LootRepo` backend — the physical `openRepo`
 * (#422) will reuse it by passing a different factory.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, NotFoundError, type LootRepo } from "../src/index.js";
import { WasmBundle, encodeFetchRequest } from "../wasm/loot_wasm.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 47800 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const README = "readme.md";
const OTHER = "notes.md";
const README_TEXT = "hello from the loot in-memory SDK — slice 1 tracer bullet. ".repeat(4);
const OTHER_TEXT = "a second public file, distinct content, to make path-scoping observable. ".repeat(3);
const EMPTY = new Uint8Array(0);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function loot(cwd: string, args: string[]): string {
  return execFileSync(LOOT, args, { cwd, encoding: "utf8" });
}
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

let relay: ChildProcess;
let work: string;
let relayDir: string;

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "loot-sdk-work-"));
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-relay-"));

  // Seed a working repo with TWO public files and finalize them into a signed
  // change. Two files make path-scoping observable (below).
  loot(work, ["init", "--identity", "tester"]);
  writeFileSync(join(work, README), README_TEXT);
  writeFileSync(join(work, OTHER), OTHER_TEXT);
  loot(work, ["new", "-m", "first change"]);

  // Start an OPEN relay (no --allow ⇒ any valid signature may push).
  relay = spawn(LOOT, ["serve", "--dir", relayDir, "--addr", `127.0.0.1:${PORT}`], {
    stdio: "ignore",
  });

  // Wait until the relay answers a metadata read, then push the change to it.
  const probe = await connectRelay(URL, Identity.generate());
  const deadline = Date.now() + 20_000;
  for (;;) {
    try {
      await probe.list();
      break;
    } catch {
      if (Date.now() > deadline) throw new Error("relay did not become ready");
      await sleep(200);
    }
  }
  loot(work, ["push", "--remote", URL]);
}, 60_000);

afterAll(() => {
  if (relay?.pid) {
    if (process.platform === "win32") {
      try {
        execFileSync("taskkill", ["/PID", String(relay.pid), "/T", "/F"], { stdio: "ignore" });
      } catch {
        /* already gone */
      }
    } else {
      relay.kill("SIGKILL");
    }
  }
  for (const d of [work, relayDir]) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

/** Backend-agnostic read contract — reused verbatim by any `LootRepo` (#422). */
function runReadContract(label: string, makeRepo: () => Promise<LootRepo>) {
  describe(label, () => {
    let repo: LootRepo;
    beforeAll(async () => {
      repo = await makeRepo();
    });

    it("lists both pushed paths with their visibility", async () => {
      const entries = await repo.list();
      expect(entries).toContainEqual({ path: README, visibility: "public" });
      expect(entries).toContainEqual({ path: OTHER, visibility: "public" });
    });

    it("reads each public file back byte-for-byte (decrypt + host zstd inflate)", async () => {
      const dec = new TextDecoder();
      expect(dec.decode(await repo.read(README).bytes())).toBe(README_TEXT);
      expect(dec.decode(await repo.read(OTHER).bytes())).toBe(OTHER_TEXT);
    });

    it("yields the same bytes via async iteration", async () => {
      const chunks: Uint8Array[] = [];
      for await (const chunk of repo.read(README)) chunks.push(chunk);
      expect(Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8")).toBe(README_TEXT);
    });

    it("throws NotFoundError for an absent path", async () => {
      await expect(repo.read("does-not-exist.md").bytes()).rejects.toBeInstanceOf(NotFoundError);
    });
  });
}

runReadContract("in-memory (connectRelay) against a real relay", () =>
  connectRelay(URL, Identity.generate()),
);

describe("client-side path-scoping (#380)", () => {
  async function fetchBundle(have: Uint8Array, wants: Uint8Array): Promise<WasmBundle> {
    const resp = await fetch(`${URL}/fetch`, { method: "POST", body: encodeFetchRequest(have, wants) });
    return WasmBundle.fromBytes(new Uint8Array(await resp.arrayBuffer()));
  }

  it("a scoped fetch returns only the requested object's bytes, not the sibling's", async () => {
    // Metadata fetch (no object bytes) resolves both paths to their addresses.
    const meta = await fetchBundle(EMPTY, EMPTY);
    const tree = (JSON.parse(meta.changesJson()) as { tree: { path: string; oid: string }[] }[]).flatMap(
      (c) => c.tree,
    );
    const readmeOid = hexToBytes(tree.find((e) => e.path === README)!.oid);
    const otherOid = hexToBytes(tree.find((e) => e.path === OTHER)!.oid);

    // Scope the fetch to readme only: its bytes travel, the sibling's do not.
    const scoped = await fetchBundle(EMPTY, readmeOid);
    expect(scoped.object(readmeOid)).toBeInstanceOf(Uint8Array);
    expect(scoped.object(otherOid)).toBeUndefined();
    // Structure (the sibling's address) is still visible — loot scopes content, not names.
    expect(tree.some((e) => e.path === OTHER)).toBe(true);
  });
});
