/**
 * #433: the physical adapter's *branches* — error mapping, arg composition, and
 * `pull` streaming — proven against a FAKE `LootRunner`, no real `loot` binary.
 * The seam (`openRepo`'s `opts.runner`) is what makes this possible: the fake
 * returns canned `{ stdout, stderr, code }` / throws `ENOENT`, and the adapter's
 * interpretation is asserted directly. The real-binary round-trip is a separate
 * smoke (`physical.behavior.test.ts`).
 */
import { describe, expect, it } from "vitest";
import {
  GuardError,
  LootError,
  NotFoundError,
  SetupError,
  openRepo,
  type LootRunner,
  type RunResult,
  type StreamHandle,
} from "../src/index.js";

const ENOENT = () => Object.assign(new Error("spawn loot ENOENT"), { code: "ENOENT" });
const ok = (stdout = ""): RunResult => ({ stdout, stderr: "", code: 0 });
const fail = (stderr: string, code = 1): RunResult => ({ stdout: "", stderr, code });
/** The binary's coded failure object (`{"contract":N,"error":{"code","message"}}`
 * on stderr under --json, #430) — what the adapter maps down (#434). */
const coded = (code: string, message = "boom"): RunResult =>
  fail(JSON.stringify({ contract: 8, error: { code, message } }));

/** A programmable {@link LootRunner}: `run` dispatches on the verb via `handlers`
 * (defaulting `surface`/`status` so `openRepo`/`push` init cleanly), records every
 * call, and `spawn` replays a scripted stdout stream + exit. */
class FakeRunner implements LootRunner {
  readonly calls: string[][] = [];
  readonly spawnCalls: string[][] = [];
  constructor(
    private readonly handlers: Record<string, (args: string[]) => RunResult> = {},
    private readonly spawnScript: { chunks?: Uint8Array[]; code?: number; stderr?: string; enoent?: boolean } = {},
  ) {}

  async run(args: string[]): Promise<RunResult> {
    this.calls.push(args);
    const verb = args[0] ?? "";
    const h = this.handlers[verb];
    if (h) return h(args);
    // Sensible defaults so init/push plumbing doesn't need per-test wiring.
    if (verb === "surface") return ok(JSON.stringify({ tree: [] }));
    if (verb === "status") return ok(JSON.stringify({ change: "00112233445566778899aabbccddeeff" }));
    return ok();
  }

  spawn(args: string[]): StreamHandle {
    this.spawnCalls.push(args);
    const s = this.spawnScript;
    async function* stdout(): AsyncGenerator<Uint8Array> {
      for (const c of s.chunks ?? []) yield c;
    }
    const result = s.enoent
      ? Promise.reject(ENOENT())
      : Promise.resolve({ code: s.code ?? 0, stderr: s.stderr ?? "" });
    return { stdout: stdout(), result };
  }
}

const open = (runner: LootRunner) => openRepo("/fake/repo", { runner });

describe("physical error mapping: binary code → LootErrorCode (#434, fake runner)", () => {
  it("a missing binary (ENOENT spawn failure) surfaces as SetupError", async () => {
    const runner: LootRunner = {
      run: () => Promise.reject(ENOENT()),
      spawn: () => {
        throw ENOENT();
      },
    };
    await expect(open(runner)).rejects.toBeInstanceOf(SetupError);
  });

  it.each([
    ["no_repo", SetupError],
    ["unsupported_format", SetupError],
    ["unknown_flag", SetupError],
    ["not_found", NotFoundError],
  ] as const)("a coded %s failure at open surfaces as the mapped setup/not-found error", async (code, Ctor) => {
    const runner = new FakeRunner({ surface: () => coded(code) });
    await expect(open(runner)).rejects.toBeInstanceOf(Ctor);
  });

  it.each(["demotion", "mis_seal", "seal_wip"] as const)(
    "a coded %s failure surfaces as GuardError",
    async (code) => {
      const runner = new FakeRunner({ describe: () => coded(code) });
      const repo = await open(runner);
      await repo.edit("a.md", new Uint8Array([1]));
      await expect(repo.describe("x")).rejects.toBeInstanceOf(GuardError);
    },
  );

  it("an unknown/uncovered code (e.g. backend) maps to a generic LootError(unsupported)", async () => {
    const runner = new FakeRunner({ describe: () => coded("backend", "codec blew up") });
    const repo = await open(runner);
    await repo.edit("a.md", new Uint8Array([1]));
    const err = await repo.describe("x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LootError);
    expect(err).not.toBeInstanceOf(SetupError);
    expect((err as LootError).code).toBe("unsupported");
    expect((err as LootError).message).toContain("codec blew up");
  });

  it("uncoded stderr (a pre-#430 binary emitting prose) falls back to a generic LootError", async () => {
    const runner = new FakeRunner({ describe: () => fail("loot: something went sideways") });
    const repo = await open(runner);
    await repo.edit("a.md", new Uint8Array([1]));
    const err = await repo.describe("x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(LootError);
    expect((err as LootError).code).toBe("unsupported");
    expect((err as LootError).message).toContain("something went sideways");
  });
});

describe("physical arg composition (fake runner)", () => {
  it("describe passes -m and the demote guard through (with --json appended)", async () => {
    const runner = new FakeRunner();
    const repo = await open(runner);
    await repo.edit("a.md", new Uint8Array([1]));
    await repo.describe("named it", { allowDemote: ["a.md"] });
    // `run` appends --json so a failure would carry the coded error object.
    expect(runner.calls).toContainEqual(["describe", "-m", "named it", "--allow-demote", "a.md", "--json"]);
  });

  it("push finalizes via `new` then reads the change id from `status`", async () => {
    const runner = new FakeRunner();
    const repo = await open(runner);
    await repo.edit("a.md", new Uint8Array([1]));
    await repo.describe("named it");
    const id = await repo.push();
    expect(runner.calls).toContainEqual(["new", "-m", "named it", "--json"]);
    expect(runner.calls).toContainEqual(["status", "--json"]);
    expect(id).toBe("00112233445566778899aabbccddeeff");
  });
});

describe("physical pull streaming (fake runner)", () => {
  it("streams the child's stdout chunks then completes on a clean exit", async () => {
    const chunks = [new TextEncoder().encode("reconciled 1\n"), new TextEncoder().encode("reconciled 2\n")];
    const runner = new FakeRunner({}, { chunks, code: 0 });
    const repo = await open(runner);
    const got: string[] = [];
    const dec = new TextDecoder();
    for await (const c of repo.pull()) got.push(dec.decode(c));
    expect(got).toEqual(["reconciled 1\n", "reconciled 2\n"]);
    expect(runner.spawnCalls).toContainEqual(["pull", "--json"]);
  });

  it("classifies a non-zero pull exit from its coded stderr", async () => {
    const stderr = JSON.stringify({ contract: 8, error: { code: "no_repo", message: "no .loot here" } });
    const runner = new FakeRunner({}, { code: 1, stderr });
    const repo = await open(runner);
    const drain = async () => {
      for await (const _ of repo.pull()) void _;
    };
    await expect(drain()).rejects.toBeInstanceOf(SetupError);
  });

  it("a spawn failure during pull surfaces as SetupError", async () => {
    const runner = new FakeRunner({}, { enoent: true });
    const repo = await open(runner);
    const drain = async () => {
      for await (const _ of repo.pull()) void _;
    };
    await expect(drain()).rejects.toBeInstanceOf(SetupError);
  });
});

describe("physical read (fake runner) still maps a missing path to NotFoundError", () => {
  it("visibility() on an absent path throws NotFoundError", async () => {
    const runner = new FakeRunner({ surface: () => ok(JSON.stringify({ tree: [] })) });
    const repo = await open(runner);
    await expect(repo.read("nope.md").visibility()).rejects.toBeInstanceOf(NotFoundError);
  });
});
