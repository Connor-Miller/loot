/**
 * LootRunner (#433) — the narrow subprocess seam the physical `LootRepo` adapter
 * drives instead of touching `child_process` directly. It does **only** process
 * I/O; every interpretation (exit-code / stderr → typed errors, arg composition,
 * `pull` classification) stays adapter-side, so those branches are unit-testable
 * against a fake runner with no real `loot` binary.
 *
 * `run` is buffered and **never throws on a non-zero exit** — it hands back the
 * raw `{ stdout, stderr, code }` so the adapter inspects `code`/`stderr` and maps
 * to typed errors itself. A genuine spawn failure (`ENOENT` — the binary is
 * missing) is the one thing it *does* throw, so the adapter can tell "loot ran
 * and failed" apart from "loot isn't there" (→ `SetupError`).
 *
 * `spawn` hands back the live `stdout` stream plus a `result` promise for the
 * exit code + captured stderr, so `pull` streams the child's output as it
 * arrives and classifies once the process closes.
 */
import { spawn as spawnChild } from "node:child_process";

/** The buffered outcome of a finished `loot` invocation. */
export interface RunResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** A live streaming invocation: `stdout` as it arrives, `result` once it closes. */
export interface StreamHandle {
  stdout: AsyncIterable<Uint8Array>;
  result: Promise<{ code: number; stderr: string }>;
}

export interface LootRunner {
  /** Run a verb to completion, buffering output. Resolves with the raw result
   * even on a non-zero exit; rejects only on a genuine spawn failure (`ENOENT`). */
  run(args: string[]): Promise<RunResult>;
  /** Start a verb and stream its `stdout`; `result` resolves with exit code +
   * stderr once it closes. A spawn failure surfaces as a rejection on either the
   * `stdout` iteration or `result` (whichever the caller reaches first). */
  spawn(args: string[]): StreamHandle;
}

/** The default {@link LootRunner}: shells out to the real `loot` binary in `cwd`. */
export class SubprocessRunner implements LootRunner {
  constructor(
    private readonly loot: string,
    private readonly cwd: string,
  ) {}

  run(args: string[]): Promise<RunResult> {
    return new Promise((resolve, reject) => {
      const child = spawnChild(this.loot, args, { cwd: this.cwd });
      const out: Buffer[] = [];
      const err: Buffer[] = [];
      child.stdout?.on("data", (c: Buffer) => out.push(c));
      child.stderr?.on("data", (c: Buffer) => err.push(c));
      // A spawn failure (ENOENT) is the only throw — a non-zero exit resolves.
      child.on("error", reject);
      child.on("close", (code) =>
        resolve({
          stdout: Buffer.concat(out).toString("utf8"),
          stderr: Buffer.concat(err).toString("utf8"),
          code: code ?? 0,
        }),
      );
    });
  }

  spawn(args: string[]): StreamHandle {
    const child = spawnChild(this.loot, args, { cwd: this.cwd });
    const err: Buffer[] = [];
    child.stderr?.on("data", (c: Buffer) => err.push(c));
    const result = new Promise<{ code: number; stderr: string }>((resolve, reject) => {
      child.on("error", reject);
      child.on("close", (code) => resolve({ code: code ?? 0, stderr: Buffer.concat(err).toString("utf8") }));
    });
    async function* stdout(): AsyncGenerator<Uint8Array> {
      if (child.stdout) {
        for await (const chunk of child.stdout) yield new Uint8Array(chunk as Buffer);
      }
    }
    return { stdout: stdout(), result };
  }
}
