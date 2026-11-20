import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { TaintSessionStore } from "../src/session-taint.js";

describe("M1: Modularization & Bounded TaintSessionStore", () => {
  it("memastikan Core package.json tetap 0 runtime dependencies dan memiliki 3 entrypoint exports", () => {
    const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
    const pkg = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      exports?: Record<string, unknown>;
      peerDependencies?: Record<string, string>;
    };

    expect(pkg.dependencies).toBeUndefined();
    expect(pkg.exports?.["."]).toBeDefined();
    expect(pkg.exports?.["./semantic"]).toBeDefined();
    expect(pkg.exports?.["./mcp"]).toBeDefined();
    expect(pkg.peerDependencies?.["onnxruntime-node"]).toBeDefined();
    expect(pkg.peerDependencies?.["@modelcontextprotocol/sdk"]).toBeDefined();
  });

  it("melacak taint per sesi, menerapkan TTL expiration, dan LRU eviction pada batas maxSessions", () => {
    let nowMs = 1_000_000;
    const store = new TaintSessionStore({
      maxSessions: 3,
      ttlMs: 10_000,
      now: () => nowMs,
    });

    store.touch("s1");
    expect(store.isTainted("s1")).toBe(false);

    store.markTainted("s1", "inspect_fraud_subgraph", ["1"]);
    expect(store.isTainted("s1")).toBe(true);
    expect(store.getState("s1")?.taintSources).toEqual(["inspect_fraud_subgraph"]);
    expect(store.getState("s1")?.poisonedTargets).toEqual(["1"]);

    // Fill capacity -> adding s4 evicts oldest untouched entry (s2 after touching s1)
    nowMs += 100;
    store.touch("s2");
    nowMs += 100;
    store.touch("s3");
    nowMs += 100;
    store.touch("s1"); // refresh s1 LRU position
    nowMs += 100;
    store.touch("s4");

    expect(store.size()).toBe(3);
    expect(store.getState("s2")).toBeUndefined();
    expect(store.isTainted("s1")).toBe(true);

    // Advance clock past TTL -> expires cleanly
    nowMs += 15_000;
    expect(store.isTainted("s1")).toBe(false);
    expect(store.pruneExpired()).toBeGreaterThanOrEqual(2);
    expect(store.size()).toBe(0);
  });

  it("lulus 50.000 operasi sesi soak test tanpa kebocoran memori (size selalu <= maxSessions)", () => {
    let nowMs = 0;
    const maxSessions = 500;
    const store = new TaintSessionStore({
      maxSessions,
      ttlMs: 60_000,
      now: () => nowMs,
    });

    for (let i = 0; i < 50_000; i++) {
      nowMs += 5;
      const sid = `soak-session-${i}`;
      if (i % 3 === 0) {
        store.markTainted(sid, "inspect_fraud_subgraph");
      } else {
        store.touch(sid);
      }
      if (i % 5_000 === 0) {
        expect(store.size()).toBeLessThanOrEqual(maxSessions);
      }
    }

    expect(store.size()).toBeLessThanOrEqual(maxSessions);
  });
});
