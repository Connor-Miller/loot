/**
 * #428: drive the PHYSICAL `LootRepo` (`openRepo`) against a real on-disk `.loot/`
 * checkout + the real `loot` binary. The backend-agnostic read contract runs
 * VERBATIM here — the same `runReadContract` the in-memory suite uses — which is
 * what proves the two backends are interchangeable behind one interface.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openRepo, type LootRepo } from "../src/index.js";
import { OTHER, OTHER_TEXT, README, README_TEXT, runReadContract } from "./read-contract.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const loot = (cwd: string, args: string[]) => execFileSync(LOOT, args, { cwd, encoding: "utf8" });

let readRepo: string;
let writeRepo: string;

beforeAll(() => {
  // Seed a checkout with the two read-contract files, finalized into a change.
  readRepo = mkdtempSync(join(tmpdir(), "loot-phys-read-"));
  loot(readRepo, ["init", "--identity", "tester"]);
  writeFileSync(join(readRepo, README), README_TEXT);
  writeFileSync(join(readRepo, OTHER), OTHER_TEXT);
  loot(readRepo, ["new", "-m", "seed"]);

  writeRepo = mkdtempSync(join(tmpdir(), "loot-phys-write-"));
  loot(writeRepo, ["init", "--identity", "author"]);
});

afterAll(() => {
  for (const d of [readRepo, writeRepo]) {
    try {
      rmSync(d, { recursive: true, force: true });
    } catch {
      /* best effort */
    }
  }
});

// The AC: the backend-agnostic read contract, verbatim, against openRepo.
runReadContract("physical (openRepo) against a real checkout", () =>
  openRepo(readRepo, { loot: LOOT }),
);

describe("physical authoring round-trip", () => {
  let repo: LootRepo;
  const HELLO = "hello.md";
  const HELLO_TEXT = new TextEncoder().encode("authored through the physical backend\n");

  beforeAll(async () => {
    repo = await openRepo(writeRepo, { loot: LOOT });
  });

  it("status/diff report the pending change before push", async () => {
    await repo.edit(HELLO, HELLO_TEXT);
    await repo.describe("add hello");
    const status = await repo.status();
    expect(status.message).toBe("add hello");
    expect(status.changes).toContainEqual({ path: HELLO, kind: "added" });
    expect(await repo.diff()).toContainEqual({ path: HELLO, kind: "added" });
  });

  it("push finalizes the change and clears the overlay", async () => {
    const changeId = await repo.push();
    expect(changeId).toMatch(/^[0-9a-f]{32}$/);
    expect((await repo.status()).changes).toEqual([]);
  });

  it("the authored file then lists and reads back", async () => {
    // A fresh handle proves it read from the committed checkout, not overlay memory.
    const fresh = await openRepo(writeRepo, { loot: LOOT });
    expect(await fresh.list()).toContainEqual({ path: HELLO, visibility: "public" });
    expect(await fresh.read(HELLO).bytes()).toEqual(HELLO_TEXT);
  });
});

describe("physical error surface", () => {
  it("openRepo on a non-repo path throws a typed error", async () => {
    const empty = mkdtempSync(join(tmpdir(), "loot-phys-none-"));
    try {
      await expect(openRepo(empty, { loot: LOOT })).rejects.toMatchObject({ code: expect.any(String) });
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});
