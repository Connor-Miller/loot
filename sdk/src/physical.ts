import { execFile, spawn } from "node:child_process";
import { createReadStream } from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { ConflictError, LootError, NotFoundError, SetupError } from "./errors.js";
import type {
  ChangeKind,
  ChangeSummary,
  EditOptions,
  LootRepo,
  PathEntry,
  ReadStream,
  Status,
  Visibility,
  VisibilityGuard,
} from "./repo.js";

const execFileAsync = promisify(execFile);

/** Options for {@link openRepo}. `loot` overrides the binary (default: `loot` on PATH). */
export interface OpenRepoOptions {
  loot?: string;
}

/** The overlay: a path replaced with new bytes, or removed. Mirrors the
 * in-memory backend so `status`/`diff` report kinds without extra CLI output. */
type Pending = { kind: "put"; visibility?: Visibility } | { kind: "remove" };

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
  private readonly overlay = new Map<string, Pending>();
  private message: string | null = null;
  private guard: VisibilityGuard = {};
  /** The committed tree paths the overlay is authored on top of — captured at
   * open and refreshed after each `push`. Kept separate from live `surface`
   * because loot folds a *described* working change into the current tree, so
   * surface alone can't tell an added path from a modified one. */
  private baseline = new Set<string>();

  constructor(
    private readonly path: string,
    private readonly loot: string,
  ) {}

  /** Fail fast on a missing binary / non-repo, and snapshot the committed tree. */
  async init(): Promise<void> {
    this.baseline = new Set((await this.list()).map((e) => e.path));
  }

  /**
   * Run a `loot` verb in the repo and return its (buffered) stdout. Maps
   * subprocess failure to typed errors. loot has no machine error codes, so the
   * taxonomy mapping reads stderr prose — the pragmatic reality of wrapping a
   * CLI; only the load-bearing cases (setup, conflict) are matched, everything
   * else is a generic `LootError`.
   */
  private async run(args: string[]): Promise<string> {
    try {
      const { stdout } = await execFileAsync(this.loot, args, { cwd: this.path, maxBuffer: 64 << 20 });
      return stdout;
    } catch (e) {
      const err = e as { code?: string; stderr?: string; message?: string };
      // A missing / non-executable binary is a setup problem — its own code.
      if (err.code === "ENOENT") {
        throw new SetupError(
          `loot binary not found: ${this.loot} — install loot or pass { loot } to openRepo`,
        );
      }
      const detail = (err.stderr ?? err.message ?? "").trim();
      // An old binary lacking a verb/flag (e.g. `surface --json`) or reading an
      // older format is a setup problem, not a repo error.
      if (/unknown (flag|command)|reads up to v|unsupported format/i.test(detail)) {
        throw new SetupError(`incompatible loot binary: ${detail}`);
      }
      if (/no \.loot|not a loot repo/i.test(detail)) {
        throw new SetupError(`not a loot checkout at ${this.path}: ${detail}`);
      }
      if (/moved|non-fast-forward|diverged|reconcile/i.test(detail)) {
        throw new ConflictError(`loot ${args[0]} failed: ${detail}`);
      }
      throw new LootError("unsupported", `loot ${args[0]} failed: ${detail}`);
    }
  }

  async list(): Promise<PathEntry[]> {
    const out = await this.run(["surface", "--json"]);
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
    this.overlay.set(path, { kind: "put", visibility: opts?.visibility });
  }

  async remove(path: string): Promise<void> {
    await rm(join(this.path, path), { force: true });
    this.overlay.set(path, { kind: "remove" });
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
    this.message = message;
    if (guard) this.guard = guard;
    await this.run(["describe", "-m", message, ...this.guardArgs(guard ?? {})]);
  }

  async status(): Promise<Status> {
    const changes: ChangeSummary[] = [...this.overlay.entries()].map(([path, p]) => {
      const kind: ChangeKind =
        p.kind === "remove" ? "removed" : this.baseline.has(path) ? "modified" : "added";
      return { path, kind };
    });
    return { message: this.message, changes };
  }

  async diff(): Promise<ChangeSummary[]> {
    return (await this.status()).changes;
  }

  async push(guard?: VisibilityGuard): Promise<string> {
    if (this.message === null) throw new Error("describe the change before pushing (no message set)");
    if (this.overlay.size === 0) throw new Error("nothing to push (no pending edits)");
    const effective: VisibilityGuard = {
      allowDemote: [...(this.guard.allowDemote ?? []), ...(guard?.allowDemote ?? [])],
      allowReveal: Boolean(this.guard.allowReveal || guard?.allowReveal),
    };
    // Finalize the working copy into a signed change (the binary snapshots +
    // signs). A configured remote is pushed to separately by the operator.
    await this.run(["new", "-m", this.message, ...this.guardArgs(effective)]);
    // The durable change id is the `change` field of the machine status.
    const { change } = JSON.parse(await this.run(["status", "--json"])) as { change: string | null };
    this.overlay.clear();
    this.message = null;
    this.guard = {};
    // The just-finalized change is the new baseline for the next edit cycle.
    this.baseline = new Set((await this.list()).map((e) => e.path));
    return change ?? "";
  }

  async *pull(): AsyncGenerator<Uint8Array> {
    // Sync from the checkout's configured remote, STREAMING the child's stdout
    // (the reconciliation report) as it arrives rather than buffering it.
    const child = spawn(this.loot, ["pull", "--porcelain"], { cwd: this.path });
    const stderr: Buffer[] = [];
    child.stderr?.on("data", (c: Buffer) => stderr.push(c));
    const done = new Promise<number>((resolve, reject) => {
      child.on("error", (e: NodeJS.ErrnoException) =>
        reject(e.code === "ENOENT" ? new SetupError(`loot binary not found: ${this.loot}`) : e),
      );
      child.on("close", (code) => resolve(code ?? 0));
    });
    if (child.stdout) {
      for await (const chunk of child.stdout) yield new Uint8Array(chunk as Buffer);
    }
    const code = await done;
    if (code !== 0) {
      throw new LootError("unsupported", `loot pull failed: ${Buffer.concat(stderr).toString("utf8").trim()}`);
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
  const repo = new PhysicalRepo(path, opts?.loot ?? "loot");
  await repo.init(); // fail fast on a missing binary / non-repo; snapshot the baseline
  return repo;
}
