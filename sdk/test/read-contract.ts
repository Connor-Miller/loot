/**
 * The backend-agnostic read contract (#422/#428). The same assertions run
 * verbatim against ANY `LootRepo` — the in-memory `connectRelay` and the
 * physical `openRepo` — by passing a factory. Each backend's test seeds a repo
 * holding `README` = `README_TEXT` and `OTHER` = `OTHER_TEXT` (both public),
 * then calls `runReadContract`.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { NotFoundError, type LootRepo } from "../src/index.js";

export const README = "readme.md";
export const OTHER = "notes.md";
export const README_TEXT = "hello from the loot SDK read contract — tracer bullet. ".repeat(4);
export const OTHER_TEXT = "a second public file, distinct content, to keep the two apart. ".repeat(3);

export function runReadContract(label: string, makeRepo: () => Promise<LootRepo>) {
  describe(label, () => {
    let repo: LootRepo;
    beforeAll(async () => {
      repo = await makeRepo();
    });

    it("lists both paths with their visibility", async () => {
      const entries = await repo.list();
      expect(entries).toContainEqual({ path: README, visibility: "public" });
      expect(entries).toContainEqual({ path: OTHER, visibility: "public" });
    });

    it("reads each public file back byte-for-byte", async () => {
      const dec = new TextDecoder();
      expect(dec.decode(await repo.read(README).bytes())).toBe(README_TEXT);
      expect(dec.decode(await repo.read(OTHER).bytes())).toBe(OTHER_TEXT);
    });

    it("yields the same bytes via async iteration", async () => {
      const chunks: Uint8Array[] = [];
      for await (const chunk of repo.read(README)) chunks.push(chunk);
      expect(Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8")).toBe(README_TEXT);
    });

    it("throws NotFoundError for an absent path", async () => {
      await expect(repo.read("does-not-exist.md").bytes()).rejects.toBeInstanceOf(NotFoundError);
    });
  });
}
