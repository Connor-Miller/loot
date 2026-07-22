/**
 * Seam 1 (#427): drive the in-memory streaming-pull path against a REAL relay.
 * Two identities on the same relay: identity A authors + pushes a change; a
 * separate in-memory session (identity B) `pull()`s and observes it — B's
 * `read`/`list` reflect A's change, and the stream surfaces the change once.
 * Pulling again with nothing new completes cleanly (no chunks, no error).
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, type LootRepo } from "../src/index.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 49500 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const README = "readme.md";
const CONTENT = new TextEncoder().encode("authored by A, pulled by B — slice 5\n");

// Two pre-registered keys, both allow-listed so either may push.
const SEED_A = new Uint8Array(32).fill(11);
const SEED_B = new Uint8Array(32).fill(22);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Drain a pull stream, decoding each per-change JSON chunk. */
async function drain(stream: AsyncIterable<Uint8Array>): Promise<{ id: string; message: string }[]> {
  const out: { id: string; message: string }[] = [];
  const dec = new TextDecoder();
  for await (const chunk of stream) out.push(JSON.parse(dec.decode(chunk)));
  return out;
}

let relay: ChildProcess;
let relayDir: string;
let identityA: Identity;
let identityB: Identity;

beforeAll(async () => {
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-prelay-"));
  identityA = Identity.fromSeed(SEED_A);
  identityB = Identity.fromSeed(SEED_B);

  relay = spawn(
    LOOT,
    [
      "serve",
      "--dir",
      relayDir,
      "--addr",
      `127.0.0.1:${PORT}`,
      "--allow",
      hex(identityA.publicKey()),
      "--allow",
      hex(identityB.publicKey()),
    ],
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

describe("streaming pull against a real relay (two identities)", () => {
  let bob: LootRepo;
  let pushedId: string;

  beforeAll(async () => {
    bob = await connectRelay(URL, identityB);
  });

  it("a fresh session pulls nothing when the relay is empty (clean, no chunks)", async () => {
    const chunks = await drain(bob.pull());
    expect(chunks).toEqual([]);
  });

  it("A authors and pushes a change B has never seen", async () => {
    const alice = await connectRelay(URL, identityA);
    await alice.edit(README, CONTENT);
    await alice.describe("A's first change");
    pushedId = await alice.push();
    expect(pushedId).toMatch(/^[0-9a-f]{32}$/);
  });

  it("B pull()s and the stream surfaces A's change", async () => {
    const chunks = await drain(bob.pull());
    expect(chunks.length).toBe(1);
    expect(chunks[0]?.message).toBe("A's first change");
  });

  it("after the pull, B's read/list reflect A's change", async () => {
    expect(await bob.list()).toContainEqual({ path: README, visibility: "public" });
    const back = await bob.read(README).bytes();
    expect(back).toEqual(CONTENT);
  });

  it("pulling again with nothing new completes cleanly (no chunks, no error)", async () => {
    const chunks = await drain(bob.pull());
    expect(chunks).toEqual([]);
  });
});
