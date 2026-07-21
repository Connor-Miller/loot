/**
 * Seam 1 (#423): drive the in-memory `LootRepo` read path against a REAL relay.
 *
 * The relay is the actual `loot serve` binary; the repo state is seeded with the
 * actual `loot` CLI (init → author → finalize → push). No mocks — a 200 here is
 * the whole stack working: WASM codec + fetch transport + client-side
 * path-scoping + host-side zstd inflate.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, NotFoundError, type LootRepo } from "../src/index.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 47800 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const README = "readme.md";
const CONTENT = "hello from the loot in-memory SDK — slice 1 tracer bullet. ".repeat(4);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function loot(cwd: string, args: string[]): string {
  return execFileSync(LOOT, args, { cwd, encoding: "utf8" });
}

let relay: ChildProcess;
let work: string;
let relayDir: string;

beforeAll(async () => {
  work = mkdtempSync(join(tmpdir(), "loot-sdk-work-"));
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-relay-"));

  // Seed a working repo with one public file and finalize it into a signed change.
  loot(work, ["init", "--identity", "tester"]);
  writeFileSync(join(work, README), CONTENT);
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

describe("in-memory read against a real relay", () => {
  let repo: LootRepo;
  beforeAll(async () => {
    repo = await connectRelay(URL, Identity.generate());
  });

  it("lists the pushed path with its visibility", async () => {
    const entries = await repo.list();
    expect(entries).toContainEqual({ path: README, visibility: "public" });
  });

  it("reads the public file back, byte-for-byte (decrypt + host zstd inflate)", async () => {
    const bytes = await repo.read(README).bytes();
    expect(new TextDecoder().decode(bytes)).toBe(CONTENT);
  });

  it("streams the same bytes via async iteration", async () => {
    const chunks: Uint8Array[] = [];
    for await (const chunk of repo.read(README)) chunks.push(chunk);
    const joined = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    expect(joined.toString("utf8")).toBe(CONTENT);
  });

  it("throws NotFoundError for an absent path", async () => {
    await expect(repo.read("does-not-exist.md").bytes()).rejects.toBeInstanceOf(NotFoundError);
  });
});
