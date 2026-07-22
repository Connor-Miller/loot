/**
 * Seam 1 (#426): the in-memory private-authoring path against a REAL relay.
 *
 * Proves the sealing side end-to-end: `edit(path, { visibility: "private" })`
 * makes `push()` seal the content so the relay stores CIPHERTEXT (its key never
 * travels); the author reads their own sealed content back this session by
 * unwrapping the ECIES-to-self key; a fresh reader with no key cannot; and the
 * guard model (inherit / new-path default / demote / reveal) is enforced before
 * anything is stowed. No mocks — the relay is the real `loot serve` binary.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, AuthError, GuardError, type LootRepo } from "../src/index.js";
import { WasmBundle, encodeFetchRequest } from "../wasm/loot_wasm.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 49400 + Math.floor(Math.random() * 400);
const URL = `http://127.0.0.1:${PORT}`;
const SECRET = "secret.md";
const PUB = "public.md";
const enc = (s: string) => new TextEncoder().encode(s);
const SECRET_V1 = enc("classified — sealed before it leaves the process\n");
const SECRET_V2 = enc("classified v2 — still private, inherited on re-edit\n");
const PUB_BYTES = enc("a brand-new path with no visibility option → public\n");

const SEED = new Uint8Array(32).fill(9); // fixed pre-registered key
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h: string) => {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
};

let relay: ChildProcess;
let relayDir: string;
let identity: Identity;

/** Fetch the raw sealed object bytes for a path straight off the relay, plus
 * whether its content key travels — the wire-level ciphertext check. */
async function rawObject(path: string): Promise<{ bytes?: Uint8Array; hasKey: boolean }> {
  const meta = await fetch(`${URL}/fetch`, {
    method: "POST",
    body: encodeFetchRequest(new Uint8Array(0), new Uint8Array(0)),
  });
  const bundle = WasmBundle.fromBytes(new Uint8Array(await meta.arrayBuffer()));
  const tree = (JSON.parse(bundle.changesJson()) as { tree: { path: string; oid: string }[] }[]).flatMap(
    (c) => c.tree,
  );
  const oidHex = tree.find((e) => e.path === path)?.oid;
  if (!oidHex) return { hasKey: false };
  const oid = hexToBytes(oidHex);
  const scoped = await fetch(`${URL}/fetch`, {
    method: "POST",
    body: encodeFetchRequest(new Uint8Array(0), oid),
  });
  const b = WasmBundle.fromBytes(new Uint8Array(await scoped.arrayBuffer()));
  return { bytes: b.object(oid), hasKey: b.publicKey(oid) !== undefined };
}

beforeAll(async () => {
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-privrelay-"));
  identity = Identity.fromSeed(SEED);
  const pubkeyHex = hex(identity.publicKey());
  relay = spawn(
    LOOT,
    ["serve", "--dir", relayDir, "--addr", `127.0.0.1:${PORT}`, "--allow", pubkeyHex],
    { stdio: "ignore" },
  );

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
  try {
    rmSync(relayDir, { recursive: true, force: true });
  } catch {
    /* best effort */
  }
});

describe("in-memory private authoring against a real relay", () => {
  let repo: LootRepo;
  beforeAll(async () => {
    repo = await connectRelay(URL, identity);
  });

  it("seals private content: relay stores ciphertext, no key travels", async () => {
    await repo.edit(SECRET, SECRET_V1, { visibility: "private" });
    await repo.describe("add a sealed secret");
    const changeId = await repo.push();
    expect(changeId).toMatch(/^[0-9a-f]{32}$/);

    // The relay holds only ciphertext, and the content key did NOT travel.
    const raw = await rawObject(SECRET);
    expect(raw.bytes).toBeInstanceOf(Uint8Array);
    expect(raw.hasKey).toBe(false);
    expect(Buffer.from(raw.bytes!).equals(Buffer.from(SECRET_V1))).toBe(false);
  });

  it("the author reads their own sealed content back this session", async () => {
    expect(await repo.read(SECRET).bytes()).toEqual(SECRET_V1);
    expect(await repo.read(SECRET).visibility()).toBe("private");
    expect(await repo.list()).toContainEqual({ path: SECRET, visibility: "private" });
  });

  it("a fresh reader (no key) sees it as private but cannot read it", async () => {
    const reader = await connectRelay(URL, Identity.generate());
    expect(await reader.list()).toContainEqual({ path: SECRET, visibility: "private" });
    await expect(reader.read(SECRET).bytes()).rejects.toBeInstanceOf(AuthError);
  });

  it("a brand-new path with no visibility option defaults to public", async () => {
    await repo.edit(PUB, PUB_BYTES);
    await repo.describe("add a public file");
    await repo.push();
    expect(await repo.list()).toContainEqual({ path: PUB, visibility: "public" });
    // A keyless reader can read it — its key travels (public).
    const reader = await connectRelay(URL, Identity.generate());
    expect(await reader.read(PUB).bytes()).toEqual(PUB_BYTES);
  });

  it("a re-edit with no visibility option inherits the path's private visibility", async () => {
    await repo.edit(SECRET, SECRET_V2); // no option → inherit private
    await repo.describe("update the secret");
    await repo.push(); // no guard needed: visibility unchanged
    expect(await repo.read(SECRET).bytes()).toEqual(SECRET_V2);
    expect(await repo.read(SECRET).visibility()).toBe("private");
  });

  it("refuses a silent demote (public→private), then allows it with allowDemote", async () => {
    await repo.edit(PUB, enc("now sealed\n"), { visibility: "private" });
    await repo.describe("demote the public file");
    await expect(repo.push()).rejects.toBeInstanceOf(GuardError);

    // The refused push left the pending change intact — retry WITH the guard.
    const id = await repo.push({ allowDemote: [PUB] });
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(await repo.read(PUB).visibility()).toBe("private");
    expect(await repo.read(PUB).bytes()).toEqual(enc("now sealed\n"));

    const reader = await connectRelay(URL, Identity.generate());
    await expect(reader.read(PUB).bytes()).rejects.toBeInstanceOf(AuthError);
  });

  it("refuses a silent reveal (private→public), then allows it with allowReveal", async () => {
    await repo.edit(PUB, enc("now open again\n"), { visibility: "public" });
    await repo.describe("reveal the file");
    await expect(repo.push()).rejects.toBeInstanceOf(GuardError);

    await repo.push({ allowReveal: true });
    expect(await repo.read(PUB).visibility()).toBe("public");
    const reader = await connectRelay(URL, Identity.generate());
    expect(await reader.read(PUB).bytes()).toEqual(enc("now open again\n"));
  });
});
