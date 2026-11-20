export interface SessionTaintState {
  sessionId: string;
  taintedByUntrustedData: boolean;
  taintedAtMs: number | null;
  lastSeenMs: number;
  taintSources: string[];
  poisonedTargets: string[];
}

export interface TaintSessionStoreOptions {
  /** Maximum sessions retained in memory before LRU eviction (default: 10_000). */
  maxSessions?: number;
  /** Session idle TTL in milliseconds (default: 30 minutes). */
  ttlMs?: number;
  /** Maximum distinct taint source labels kept per session (default: 32). */
  maxSourcesPerSession?: number;
  /** Injectable clock for deterministic unit/soak tests. */
  now?: () => number;
}

interface InternalSessionEntry {
  taintedByUntrustedData: boolean;
  taintedAtMs: number | null;
  lastSeenMs: number;
  taintSources: Set<string>;
  poisonedTargets: Set<string>;
}

/**
 * Bounded, TTL-expiring session taint tracker for multi-turn agent & MCP lifecycles.
 * Guarantees O(1) amortized lookup/update and zero unbounded memory growth under 50k+ sessions.
 */
export class TaintSessionStore {
  private readonly maxSessions: number;
  private readonly ttlMs: number;
  private readonly maxSourcesPerSession: number;
  private readonly now: () => number;
  private readonly store = new Map<string, InternalSessionEntry>();

  public constructor(options: TaintSessionStoreOptions = {}) {
    this.maxSessions = Math.max(1, options.maxSessions ?? 10_000);
    this.ttlMs = Math.max(1, options.ttlMs ?? 30 * 60 * 1000);
    this.maxSourcesPerSession = Math.max(1, options.maxSourcesPerSession ?? 32);
    this.now = options.now ?? (() => Date.now());
  }

  public size(): number {
    return this.store.size;
  }

  public pruneExpired(currentTimeMs: number = this.now()): number {
    let removed = 0;
    for (const [sessionId, entry] of this.store) {
      if (currentTimeMs - entry.lastSeenMs >= this.ttlMs) {
        this.store.delete(sessionId);
        removed++;
      } else {
        // Insertion order is maintained on touch(), so once we reach a non-expired entry we can stop early
        break;
      }
    }
    return removed;
  }

  public touch(sessionId: string): SessionTaintState {
    const nowMs = this.now();
    this.pruneExpired(nowMs);
    const existing = this.store.get(sessionId);
    if (existing) {
      existing.lastSeenMs = nowMs;
      // Refresh LRU position
      this.store.delete(sessionId);
      this.store.set(sessionId, existing);
      return this.toPublicState(sessionId, existing);
    }

    this.evictIfFull();
    const fresh: InternalSessionEntry = {
      taintedByUntrustedData: false,
      taintedAtMs: null,
      lastSeenMs: nowMs,
      taintSources: new Set<string>(),
      poisonedTargets: new Set<string>(),
    };
    this.store.set(sessionId, fresh);
    return this.toPublicState(sessionId, fresh);
  }

  public markTainted(
    sessionId: string,
    source: string,
    poisonedTargets: readonly string[] = []
  ): SessionTaintState {
    const nowMs = this.now();
    this.pruneExpired(nowMs);
    let entry = this.store.get(sessionId);
    if (!entry) {
      this.evictIfFull();
      entry = {
        taintedByUntrustedData: true,
        taintedAtMs: nowMs,
        lastSeenMs: nowMs,
        taintSources: new Set<string>(),
        poisonedTargets: new Set<string>(),
      };
    } else {
      entry.taintedByUntrustedData = true;
      if (entry.taintedAtMs === null) {
        entry.taintedAtMs = nowMs;
      }
      entry.lastSeenMs = nowMs;
      this.store.delete(sessionId);
    }

    if (source && entry.taintSources.size < this.maxSourcesPerSession) {
      entry.taintSources.add(source);
    }
    for (const target of poisonedTargets) {
      if (target && entry.poisonedTargets.size < this.maxSourcesPerSession) {
        entry.poisonedTargets.add(target);
      }
    }

    this.store.set(sessionId, entry);
    return this.toPublicState(sessionId, entry);
  }

  public isTainted(sessionId: string): boolean {
    const nowMs = this.now();
    const entry = this.store.get(sessionId);
    if (!entry) return false;
    if (nowMs - entry.lastSeenMs >= this.ttlMs) {
      this.store.delete(sessionId);
      return false;
    }
    return entry.taintedByUntrustedData;
  }

  public getState(sessionId: string): SessionTaintState | undefined {
    const nowMs = this.now();
    const entry = this.store.get(sessionId);
    if (!entry) return undefined;
    if (nowMs - entry.lastSeenMs >= this.ttlMs) {
      this.store.delete(sessionId);
      return undefined;
    }
    return this.toPublicState(sessionId, entry);
  }

  public clear(sessionId: string): boolean {
    return this.store.delete(sessionId);
  }

  public clearAll(): void {
    this.store.clear();
  }

  private evictIfFull(): void {
    while (this.store.size >= this.maxSessions) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey === undefined) break;
      this.store.delete(oldestKey);
    }
  }

  private toPublicState(sessionId: string, entry: InternalSessionEntry): SessionTaintState {
    return {
      sessionId,
      taintedByUntrustedData: entry.taintedByUntrustedData,
      taintedAtMs: entry.taintedAtMs,
      lastSeenMs: entry.lastSeenMs,
      taintSources: Array.from(entry.taintSources),
      poisonedTargets: Array.from(entry.poisonedTargets),
    };
  }
}
