import { createReadStream } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { GuardError, LootError, NotFoundError, SetupError } from "./errors.js";
import { type LootRunner, SubprocessRunner } from "./loot-runner.js";
import type {
  ChangeSummary,
  EditOptions,
  LootRepo,
  PathEntry,
  ReadStream,
  Status,
  Visibility,
  VisibilityGuard,
} from "./repo.js";
import { WorkingOverlay } from "./working-overlay.js";

/**
 * Map the binary's machine error channel (`{"contract":N,"error":{"code","message"}}`
 * on stderr under `--json`, #430) down to the SDK's collapsed `LootErrorCode`
 * taxonomy — in ONE place, driven by the stable `code` slug, not stderr prose
 * (#434). The binary serves every consumer with its own richer taxonomy; the SDK
 * maps it down here.
 *
 * Not mapped: the *conflict family* (a moved parent / non-fast-forward). loot's
 * engine has no such error — `/stow` accumulates concurrent forks and convergence
 * is a pull-time job, so no `RepoError` variant (and thus no coded slug) exists
 * to map (see `ConflictError` in errors.ts, deferred). It falls to the generic
 * `LootError` until a slug lands, rather than being reverse-engineered from prose.
 */
function classifyCodedFailure(verb: string | undefined, stderr: string): LootError {
  const parsed = parseCodedError(stderr);
  const message = parsed?.message ?? stderr.trim();
  const context = `loot ${verb ?? "command"} failed: ${message}`;
  switch (parsed?.code) {
    // A visibility/seal guard the binary refused (public→private demotion, a
    // mis-seal of a secret-shaped path, a sealed-WIP guard).
    case "demotion":
    case "mis_seal":
    case "seal_wip":
      return new GuardError(context);
    // An environment problem: the binary can't read this repo's format, it isn't
    // a loot checkout, or it's too old to know a flag the SDK sent.
    case "unsupported_format":
    case "no_repo":
    case "unknown_flag":
      return new SetupError(`incompatible or missing loot checkout: ${message}`);
    case "not_found":
      return new NotFoundError(context);
    // Everything else the binary can emit (backend, bad_signature, embargoed,
    // expired, the generic `error`) — and any code the SDK doesn't branch on, or
    // stderr that wasn't coded JSON at all — is a generic loot failure.
    default:
      return new LootError("unsupported", context);
  }
}

/** The `ENOENT`-spawn-failure error, shared by the buffered (`run`) and
 * streaming (`pull`) paths: a missing/non-executable binary is a setup problem. */
function missingBinaryError(loot: string): SetupError {
  return new SetupError(`loot binary not found: ${loot} — install loot or pass { loot } to openRepo`);
}

/** Parse the binary's coded failure object off stderr. Returns `undefined` when
 * stderr isn't the `{"error":{"code","message"}}` shape (e.g. a pre-#430 binary
 * emitting prose), so the caller falls back to a generic error. */
function parseCodedError(stderr: string): { code: string; message: string } | undefined {
  const trimmed = stderr.trim();
  if (!trimmed) return undefined;
  // The coded object is a single line; if other output precedes it, the last
  // non-empty line is the failure `fail()` printed.
  const line = trimmed.slice(trimmed.lastIndexOf("\n") + 1).trim();
  for (const candidate of line === trimmed ? [trimmed] : [line, trimmed]) {
    try {
      const obj = JSON.parse(candidate) as { error?: { code?: unknown; message?: unknown } };
      const code = obj.error?.code;
      if (typeof code === "string") {
        return { code, message: typeof obj.error?.message === "string" ? obj.error.message : candidate };
      }
    } catch {
      /* not coded JSON — try the next candidate, else fall through */
    }
  }
  return undefined;
}

/** Options for {@link openRepo}. `loot` overrides the binary (default: `loot` on
 * PATH); `runner` injects the subprocess seam (default: a {@link SubprocessRunner}
 * over `loot`), so tests drive the physical branches without the real binary. */
export interface OpenRepoOptions {
  loot?: string;
  runner?: LootRunner;
}

interface SurfaceEntry {
  path: string;
  visibility: string;
}

function toVisibility(raw: string): Visibility {
  return raw === "public" ? "public" : "private";
}

/** Stream a materialized file as byte chunks, mapping a missing file to NotFound. */
async function* streamFile(abs: string, path: string): AsyncGenerator<Uint8Array> {
  try {
    for await (const chunk of createReadStream(abs)) yield new Uint8Array(chunk as Buffer);
  } catch (e) {
    if ((e as { code?: string }).code === "ENOENT") throw new NotFoundError(`path not found: ${path}`);
    throw e;
  }
}

/**
 * Physical `LootRepo` (#428): drives an on-disk `.loot/` checkout by shelling out
 * to the installed `loot` binary — the binary owns all crypto/codec. `edit`/
 * `remove` write the working copy (capture-first) and record an overlay so
 * `status`/`diff` report the pending change; `push` finalizes via `loot new`.
 * `list` reads `surface --json` (machine output, not human text); `read` streams
 * the materialized file.
 */
class PhysicalRepo implements LootRepo {
  /** Capture-first pending change (#429). Physical's payload is the absolute
   * path written; the overlay owns the message + guard union + status kinds.
   * Visibility resolution / guard enforcement is delegated to the binary. */
  private readonly working = new WorkingOverlay<string>();
  /** The committed tree paths the overlay is authored on top of — captured at
   * open and refreshed after each `push`. Kept separate from live `surface`
   * because loot folds a *described* working change into the current tree, so
   * surface alone can't tell an added path from a modified one. */
  private baseline = new Set<string>();

  constructor(
    private readonly path: string,
    private readonly loot: string,
    private readonly runner: LootRunner,
  ) {}

  /** Fail fast on a missing binary / non-repo, and snapshot the committed tree. */
  async init(): Promise<void> {
    this.baseline = new Set((await this.list()).map((e) => e.path));
  }

  /**
   * Run a `loot` verb in the repo and return its (buffered) stdout, mapping a
   * subprocess failure to a typed error. `--json` is appended so a failure emits
   * the binary's coded error object on stderr (#430/#434); the runner never
   * throws on a non-zero exit — it hands back `{ code, stderr }` — so a failure
   * is classified here from that `code`. A genuine spawn failure (`ENOENT`) is
   * the one throw, and it is a setup problem.
   */
  private async run(args: string[]): Promise<string> {
    let result;
    try {
      result = await this.runner.run([...args, "--json"]);
    } catch (e) {
      // A missing / non-executable binary is a setup problem — its own code.
      if ((e as NodeJS.ErrnoException).code === "ENOENT") throw missingBinaryError(this.loot);
      throw e;
    }
    if (result.code === 0) return result.stdout;
    throw classifyCodedFailure(args[0], result.stderr);
  }

  async list(): Promise<PathEntry[]> {
    const out = await this.run(["surface"]);
    const { tree } = JSON.parse(out) as { tree: SurfaceEntry[] };
    return tree.map((e) => ({ path: e.path, visibility: toVisibility(e.visibility) }));
  }

  read(path: string): ReadStream {
    const abs = join(this.path, path);
    const collect = async (): Promise<Uint8Array> => {
      const chunks: Uint8Array[] = [];
      for await (const chunk of streamFile(abs, path)) chunks.push(chunk);
      return new Uint8Array(Buffer.concat(chunks.map((c) => Buffer.from(c))));
    };
    let cached: Promise<Uint8Array> | undefined;
    const bytes = () => (cached ??= collect());
    const visibility = async (): Promise<Visibility> => {
      const entry = (await this.list()).find((e) => e.path === path);
      if (!entry) throw new NotFoundError(`path not found: ${path}`);
      return entry.visibility;
    };
    return {
      bytes,
      visibility,
      [Symbol.asyncIterator]: () => streamFile(abs, path),
    };
  }

  async edit(path: string, bytes: Uint8Array, opts?: EditOptions): Promise<void> {
    if (opts?.visibility === "private") {
      // Physical private visibility is a `.lootattributes` rule the binary reads;
      // slice 6 authors public content (the in-memory backend covers private).
      throw new LootError(
        "unsupported",
        "physical mode authors public content in slice 6; set visibility via .lootattributes",
      );
    }
    const abs = join(this.path, path);
    await mkdir(dirname(abs), { recursive: true });
    await writeFile(abs, bytes); // capture-first: the working copy IS the change
    this.working.put(path, abs, opts?.visibility);
  }

  async remove(path: string): Promise<void> {
    await rm(join(this.path, path), { force: true });
    this.working.remove(path);
  }

  /** Map a guard onto the binary's flags. `allowReveal` (private→public) can't
   * arise in slice-6 physical authoring (which writes public content), so it is
   * rejected rather than silently dropped. */
  private guardArgs(guard: VisibilityGuard): string[] {
    if (guard.allowReveal) {
      throw new LootError(
        "unsupported",
        "physical mode authors public content in slice 6; allowReveal is not mappable",
      );
    }
    return (guard.allowDemote ?? []).flatMap((p) => ["--allow-demote", p]);
  }

  async describe(message: string, guard?: VisibilityGuard): Promise<void> {
    this.working.describe(message, guard);
    await this.run(["describe", "-m", message, ...this.guardArgs(guard ?? {})]);
  }

  async status(): Promise<Status> {
    return { message: this.working.message, changes: this.working.classify(this.baseline) };
  }

  async diff(): Promise<ChangeSummary[]> {
    return (await this.status()).changes;
  }

  async push(guard?: VisibilityGuard): Promise<string> {
    // The two push preconditions (usage bugs, plain Error) live in the overlay.
    this.working.requirePushable();
    const effective = this.working.effectiveGuard(guard);
    // Finalize the working copy into a signed change (the binary snapshots +
    // signs). A configured remote is pushed to separately by the operator.
    await this.run(["new", "-m", this.working.message!, ...this.guardArgs(effective)]);
    // The durable change id is the `change` field of the machine status.
    const { change } = JSON.parse(await this.run(["status"])) as { change: string | null };
    this.working.clear();
    // The just-finalized change is the new baseline for the next edit cycle.
    this.baseline = new Set((await this.list()).map((e) => e.path));
    return change ?? "";
  }

  async *pull(): AsyncGenerator<Uint8Array> {
    // Sync from the checkout's configured remote, STREAMING the child's stdout
    // (the reconciliation report) as it arrives rather than buffering it, then
    // classifying on the exit code once it closes.
    // `--json` so a pull failure emits the coded error object on stderr; its
    // stdout (the reconciliation report) is streamed opaquely to the caller.
    const { stdout, result } = this.runner.spawn(["pull", "--json"]);
    // Observe `result` defensively so a spawn failure surfaced through the
    // stdout stream can't leave its rejection unhandled.
    result.catch(() => {});
    try {
      for await (const chunk of stdout) yield chunk;
      const outcome = await result;
      if (outcome.code !== 0) throw classifyCodedFailure("pull", outcome.stderr);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") throw missingBinaryError(this.loot);
      throw e;
    }
  }
}

/**
 * Open an on-disk `.loot/` checkout as a `LootRepo`, driven by the installed
 * `loot` binary (#428). Returns the *same* interface `connectRelay` does, so
 * calling code is backend-agnostic. Takes no identity — the checkout's `.loot/id`
 * is what the binary signs with.
 */
export async function openRepo(path: string, opts?: OpenRepoOptions): Promise<LootRepo> {
  const loot = opts?.loot ?? "loot";
  const runner = opts?.runner ?? new SubprocessRunner(loot, path);
  const repo = new PhysicalRepo(path, loot, runner);
  await repo.init(); // fail fast on a missing binary / non-repo; snapshot the baseline
  return repo;
}
