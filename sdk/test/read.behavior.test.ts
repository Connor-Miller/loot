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
import { afterAll, beforeAll } from "vitest";
import { connectRelay, Identity } from "../src/index.js";
import { OTHER, OTHER_TEXT, README, README_TEXT, runReadContract } from "./read-contract.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 47800 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;

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

// The read round-trip smoke: the shared backend-agnostic contract against a real
// relay. Client-side path-scoping + decode/decrypt branches moved to fast unit
// tests over a fake transport + golden bundles — see relay.unit.test.ts (#432).
runReadContract("in-memory (connectRelay) against a real relay", () =>
  connectRelay(URL, Identity.generate()),
);
