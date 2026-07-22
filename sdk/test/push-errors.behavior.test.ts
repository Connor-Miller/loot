/**
 * Seam 1 (#425): the typed error model on the write path, against a REAL relay.
 *
 *  - `unauthorized` — the relay is seeded with a *foreign* key in `--allow`
 *    (mirroring `sync_round_trip.rs`'s allow-list test), so a `push()` from the
 *    SDK's own identity is rejected. The SDK attempts and reports: a typed
 *    `AuthError` (code `"unauthorized"`) carrying the offending pubkey — no
 *    pre-check, no auto-enroll, no downgrade.
 *  - `transport` — an unreachable relay surfaces `TransportError`, distinct from
 *    the loot-level allow-list rejection above.
 *
 * Conflict (`ConflictError`) is deferred and NOT asserted here: the relay's
 * `/stow` is append-only and accepts concurrent forks without ever rejecting a
 * moved parent (see `errors.ts` / loot-core `stow_accumulates_concurrent_forks_
 * without_conflict`), so there is nothing real to trigger.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { connectRelay, Identity, AuthError, TransportError, type LootRepo } from "../src/index.js";

const REPO_ROOT = join(process.cwd(), "..");
const LOOT = join(REPO_ROOT, "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 49400 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const DEAD_URL = `http://127.0.0.1:${PORT + 1}`; // nothing ever listens here

const PUSH_SEED = new Uint8Array(32).fill(9); // the SDK's own key (NOT allow-listed)
const ALLOW_SEED = new Uint8Array(32).fill(11); // a different, enrolled key
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let relay: ChildProcess;
let relayDir: string;
let identity: Identity;

beforeAll(async () => {
  relayDir = mkdtempSync(join(tmpdir(), "loot-sdk-perr-"));
  identity = Identity.fromSeed(PUSH_SEED);
  const allowedPubkeyHex = hex(Identity.fromSeed(ALLOW_SEED).publicKey());

  // Relay allow-lists a FOREIGN key — the SDK's key is deliberately absent.
  relay = spawn(
    LOOT,
    ["serve", "--dir", relayDir, "--addr", `127.0.0.1:${PORT}`, "--allow", allowedPubkeyHex],
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

describe("typed errors on the write path", () => {
  it("a push from a non-allow-listed key throws AuthError(unauthorized) with the pubkey", async () => {
    const repo: LootRepo = await connectRelay(URL, identity);
    await repo.edit("blocked.md", new TextEncoder().encode("this key is not enrolled\n"));
    await repo.describe("push from an unenrolled key");

    const err = await repo.push().then(
      () => {
        throw new Error("push should have been rejected by the allow-list");
      },
      (e: unknown) => e,
    );

    expect(err).toBeInstanceOf(AuthError);
    expect((err as AuthError).code).toBe("unauthorized");
    // Carries the offending pubkey so an operator knows which key to enroll.
    const offending = hex(identity.publicKey());
    expect((err as AuthError).pubkey).toBe(offending);
    expect((err as Error).message).toContain(offending);
  });

  it("an unreachable relay throws TransportError, distinct from the loot-level rejection", async () => {
    const repo: LootRepo = await connectRelay(DEAD_URL, identity);
    await repo.edit("x.md", new Uint8Array([1]));
    await repo.describe("push at a dead relay");

    const err = await repo.push().then(
      () => {
        throw new Error("push at a dead relay should have failed");
      },
      (e: unknown) => e,
    );

    expect(err).toBeInstanceOf(TransportError);
    expect((err as TransportError).code).toBe("transport");
    expect(err).not.toBeInstanceOf(AuthError);
  });
});
