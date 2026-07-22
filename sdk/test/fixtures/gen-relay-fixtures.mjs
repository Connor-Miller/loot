/**
 * One-time generator for the relay golden fixtures (#432). Captures real
 * `/fetch` bundle bytes from a live `loot serve` so the relay unit tests can
 * replay them against a fake transport — decode/path-scoping/decrypt proven with
 * no relay at test time. Re-run after a bundle FORMAT bump:
 *
 *   node test/fixtures/gen-relay-fixtures.mjs > test/fixtures/relay-bundles.json
 *
 * The oids/nonces are random per seal, so the meta + scoped bundles MUST come
 * from one seeding (the test reads the oid out of `meta` at runtime).
 */
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFetchRequest, WasmBundle } from "../../wasm/loot_wasm.js";

const LOOT = join(process.cwd(), "..", "target", "release", process.platform === "win32" ? "loot.exe" : "loot");
const PORT = 47000 + Math.floor(Math.random() * 800);
const URL = `http://127.0.0.1:${PORT}`;
const EMPTY = new Uint8Array(0);
const README = "readme.md";
const OTHER = "notes.md";
const README_TEXT = "hello from the loot SDK read contract — tracer bullet. ".repeat(4);
const OTHER_TEXT = "a second public file, distinct content, to keep the two apart. ".repeat(3);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hexToBytes = (hex) => {
  const o = new Uint8Array(hex.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return o;
};
const fetchBytes = async (body) => {
  const r = await fetch(`${URL}/fetch`, { method: "POST", body });
  return new Uint8Array(await r.arrayBuffer());
};

const work = mkdtempSync(join(tmpdir(), "gen-work-"));
const relayDir = mkdtempSync(join(tmpdir(), "gen-relay-"));
execFileSync(LOOT, ["init", "--identity", "tester"], { cwd: work });
const relay = spawn(LOOT, ["serve", "--dir", relayDir, "--addr", `127.0.0.1:${PORT}`], { stdio: "ignore" });

try {
  for (let i = 0; i < 100; i++) {
    try {
      await fetchBytes(encodeFetchRequest(EMPTY, EMPTY));
      break;
    } catch {
      await sleep(200);
    }
  }
  const emptyBundle = await fetchBytes(encodeFetchRequest(EMPTY, EMPTY));

  writeFileSync(join(work, README), README_TEXT);
  writeFileSync(join(work, OTHER), OTHER_TEXT);
  execFileSync(LOOT, ["new", "-m", "first change"], { cwd: work });
  execFileSync(LOOT, ["push", "--remote", URL], { cwd: work });

  const metaBundle = await fetchBytes(encodeFetchRequest(EMPTY, EMPTY));
  const tree = JSON.parse(WasmBundle.fromBytes(metaBundle).changesJson()).flatMap((c) => c.tree);
  const readmeOid = tree.find((e) => e.path === README).oid;
  const scopedBundle = await fetchBytes(encodeFetchRequest(EMPTY, hexToBytes(readmeOid)));

  process.stdout.write(
    JSON.stringify(
      {
        readme: README,
        other: OTHER,
        readmeText: README_TEXT,
        otherText: OTHER_TEXT,
        readmeOid,
        emptyBundle: Buffer.from(emptyBundle).toString("base64"),
        metaBundle: Buffer.from(metaBundle).toString("base64"),
        scopedBundle: Buffer.from(scopedBundle).toString("base64"),
      },
      null,
      2,
    ) + "\n",
  );
} finally {
  if (relay.pid) {
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
}
