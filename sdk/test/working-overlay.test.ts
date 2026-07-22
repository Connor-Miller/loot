/**
 * #429: unit tests for the pure core of WorkingOverlay<P>. No relay, no binary —
 * `classify` is fed hand-built committed-path sets; `effectiveGuard` and
 * `requirePushable` are exercised directly. This is the capture-first behaviour
 * that used to be copied into both `LootRepo` adapters, now proven once.
 */
import { describe, expect, it } from "vitest";
import { WorkingOverlay } from "../src/working-overlay.js";

describe("WorkingOverlay.classify (pure kind derivation)", () => {
  it("derives added / modified / removed against a committed baseline", () => {
    const o = new WorkingOverlay<string>();
    o.put("new.md", "/abs/new.md"); // not committed -> added
    o.put("readme.md", "/abs/readme.md"); // committed -> modified
    o.remove("stale.md"); // remove -> removed
    const committed = new Set(["readme.md", "stale.md"]);
    expect(o.classify(committed)).toEqual([
      { path: "new.md", kind: "added" },
      { path: "readme.md", kind: "modified" },
      { path: "stale.md", kind: "removed" },
    ]);
  });

  it("a removed path is `removed` even when it was never committed", () => {
    const o = new WorkingOverlay<string>();
    o.remove("ghost.md");
    expect(o.classify(new Set())).toEqual([{ path: "ghost.md", kind: "removed" }]);
  });

  it("re-putting a path keeps a single slot (last write wins)", () => {
    const o = new WorkingOverlay<number>();
    o.put("a", 1);
    o.put("a", 2);
    expect(o.size).toBe(1);
    expect(o.classify(new Set())).toEqual([{ path: "a", kind: "added" }]);
  });

  it("is empty before any staging", () => {
    const o = new WorkingOverlay<string>();
    expect(o.classify(new Set(["x"]))).toEqual([]);
    expect(o.size).toBe(0);
  });
});

describe("WorkingOverlay.describe / message", () => {
  it("message is null until described, then reflects the name", () => {
    const o = new WorkingOverlay<string>();
    expect(o.message).toBeNull();
    o.describe("named");
    expect(o.message).toBe("named");
  });
});

describe("WorkingOverlay.effectiveGuard (the guard union)", () => {
  it("unions describe-time and push-time guards, de-duping demote paths", () => {
    const o = new WorkingOverlay<string>();
    o.describe("m", { allowDemote: ["a", "b"] });
    const g = o.effectiveGuard({ allowDemote: ["b", "c"], allowReveal: true });
    expect(new Set(g.allowDemote)).toEqual(new Set(["a", "b", "c"]));
    expect(g.allowReveal).toBe(true);
  });

  it("accumulates guards across multiple describes", () => {
    const o = new WorkingOverlay<string>();
    o.describe("m", { allowDemote: ["a"] });
    o.describe("m", { allowReveal: true });
    const g = o.effectiveGuard();
    expect(g.allowDemote).toEqual(["a"]);
    expect(g.allowReveal).toBe(true);
  });

  it("with no guards anywhere, reveal is false and demote empty", () => {
    const o = new WorkingOverlay<string>();
    const g = o.effectiveGuard();
    expect(g.allowReveal).toBe(false);
    expect(g.allowDemote).toEqual([]);
  });
});

describe("WorkingOverlay.requirePushable (the two preconditions)", () => {
  it("throws when nothing is described", () => {
    const o = new WorkingOverlay<string>();
    o.put("a", "/abs/a");
    expect(() => o.requirePushable()).toThrow(/describe/i);
  });

  it("throws when the overlay is empty", () => {
    const o = new WorkingOverlay<string>();
    o.describe("named");
    expect(() => o.requirePushable()).toThrow(/nothing/i);
  });

  it("passes once described with pending edits", () => {
    const o = new WorkingOverlay<string>();
    o.put("a", "/abs/a");
    o.describe("named");
    expect(() => o.requirePushable()).not.toThrow();
  });
});

describe("WorkingOverlay.entries / clear (composition seam + reset)", () => {
  it("entries expose kind, visibility, and payload for the adapter to fold", () => {
    const o = new WorkingOverlay<string>();
    o.put("a", "/abs/a", "private");
    o.remove("b");
    const map = new Map(o.entries());
    expect(map.get("a")).toEqual({ kind: "put", payload: "/abs/a", visibility: "private" });
    expect(map.get("b")).toEqual({ kind: "remove" });
  });

  it("clear drops the overlay, message, and accumulated guard", () => {
    const o = new WorkingOverlay<string>();
    o.put("a", "/abs/a");
    o.describe("named", { allowDemote: ["a"] });
    o.clear();
    expect(o.size).toBe(0);
    expect(o.message).toBeNull();
    expect(o.effectiveGuard().allowDemote).toEqual([]);
  });
});
