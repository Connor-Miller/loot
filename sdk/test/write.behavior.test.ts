/**
 * Seam 1 (#424): drive the in-memory write path against a REAL relay whose
 * allow-list contains the SDK's key. No CLI seeding — the SDK authors the first
 * change itself (edit → describe → push), then reads it back. A green push+read
 * is the whole write stack: capture-first overlay + WASM seal/fold/sign/envelope
 * + `/stow` transport, verified by the relay accepting the signed change.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, type LootRepo } from "../src/index.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 48600 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const README = "readme.md";
const CONTENT = new TextEncoder().encode("authored entirely in the browser-shaped SDK — slice 2\n");

const SEED = new Uint8Array(32).fill(7); // fixed pre-registered key
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let relay: ChildProcess;
let relayDir: string;
let identity: Identity;

beforeAll(async () => {
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-wrelay-"));
  identity = Identity.fromSeed(SEED);
  const pubkeyHex = hex(identity.publicKey());

  // Relay with the SDK key allow-listed (only this key may push).
  relay = spawn(
    LOOT,
    ["serve", "--dir", relayDir, "--addr", `127.0.0.1:${PORT}`, "--allow", pubkeyHex],
    { stdio: "ignore" },
  );

  // Ready when a metadata read succeeds (empty repo ⇒ []).
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

describe("in-memory write against a real relay (allow-listed key)", () => {
  let repo: LootRepo;
  beforeAll(async () => {
    repo = await connectRelay(URL, identity);
  });

  it("status/diff report the pending change before push", async () => {
    await repo.edit(README, CONTENT);
    await repo.describe("first authored change");
    const status = await repo.status();
    expect(status.message).toBe("first authored change");
    expect(status.changes).toContainEqual({ path: README, kind: "added" });
    expect(await repo.diff()).toContainEqual({ path: README, kind: "added" });
  });

  it("push returns a change-id and clears the pending overlay", async () => {
    const changeId = await repo.push();
    expect(changeId).toMatch(/^[0-9a-f]{32}$/); // 16-byte durable id, hex
    const status = await repo.status();
    expect(status.changes).toEqual([]);
    expect(status.message).toBeNull();
  });

  it("the pushed public file reads back byte-for-byte, and lists", async () => {
    // A fresh connection proves it round-tripped through the relay, not memory.
    const reader = await connectRelay(URL, Identity.generate());
    expect(await reader.list()).toContainEqual({ path: README, visibility: "public" });
    const back = await reader.read(README).bytes();
    expect(back).toEqual(CONTENT);
  });

  it("refuses to push without a describe, and with nothing pending", async () => {
    const fresh = await connectRelay(URL, identity);
    await expect(fresh.push()).rejects.toThrow(/describe|nothing/i);
    await fresh.edit("x.md", new Uint8Array([1]));
    // edited but not described:
    await expect(fresh.push()).rejects.toThrow(/describe/i);
  });
});
