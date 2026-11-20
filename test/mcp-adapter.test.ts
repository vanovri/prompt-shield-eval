import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";
import { CANARY_TOKEN } from "../src/eval-dataset.js";
import { createAegisPocMcpServer } from "../src/mcp/aegis-stdio-server.js";
import {
  createAegisAuditSinkBridge,
  createAegisGuardrailMiddleware,
  createMcpGuardrailMiddleware,
  issueAegisHitlToken,
  MCP_JSONRPC_INVALID_PARAMS,
  MCP_JSONRPC_POLICY_VIOLATION,
  type McpSecurityAuditEvent,
} from "../src/mcp/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function parseToolJsonText(result: Record<string, unknown>): Record<string, unknown> {
  const arr = (Array.isArray(result["content"]) ? result["content"] : []) as Array<{
    type: string;
    text?: string;
  }>;
  const firstText = arr.find((c) => c.type === "text")?.text ?? "{}";
  return JSON.parse(firstText) as Record<string, unknown>;
}

describe("M3: MCP Guardrail Middleware & aegis-agent (HYPERION CH06) PoC", () => {
  const hitlSecret = "test-aegis-hitl-secret-2026";

  it("InMemoryTransport: menahan compound hijack (inspect_fraud_subgraph tainted -> blokir execute_risk_mitigation Treasury) dan meloloskan panggilan HITL sah", async () => {
    const { server, auditEvents, mitigationCalls } = createAegisPocMcpServer({
      hitlSecret,
      poisonFraudMetadata: true,
    });
    const client = new Client({ name: "aegis-test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);

    try {
      // 1. Call READ_ONLY query_ledger_merkle_audit -> allowed + nonce-wrapped
      const ledgerRes = await client.callTool({
        name: "query_ledger_merkle_audit",
        arguments: { account_id: "1042", asset: "USDT" },
      });
      const ledgerBody = parseToolJsonText(ledgerRes);
      expect(ledgerRes.isError).not.toBe(true);
      expect(ledgerBody["ok"]).toBe(true);
      expect(ledgerBody["nonce"]).toMatch(/^[a-f0-9]{32}$/);

      // 2. Call inspect_fraud_subgraph containing poisoned metadata -> sanitized + session TAINTED
      const fraudRes = await client.callTool({
        name: "inspect_fraud_subgraph",
        arguments: { center_account_id: "9901", symbol: "BTC-USDT", max_hops: 2 },
      });
      const fraudBody = parseToolJsonText(fraudRes);
      expect(fraudBody["ok"]).toBe(true);
      expect(fraudBody["taintedSession"]).toBe(true);
      expect(fraudBody["neutralizedElements"]).toEqual(
        expect.arrayContaining(["HTML_COMMENT", "BOUNDARY_TAG_BREAKOUT_ATTEMPT", "BOUNDARY_HEADER_SPOOF_ATTEMPT"])
      );
      expect(String(fraudBody["sanitizedText"])).not.toContain("<!--");

      // 3. Compound hijack attempt: execute_risk_mitigation on Treasury ("1") from tainted session -> 100% BLOCKED (-32001)
      const validToken = issueAegisHitlToken({
        secret: hitlSecret,
        toolName: "execute_risk_mitigation",
        approverId: "chief-risk-officer",
        expiresAtMs: Date.now() + 60_000,
      });

      const hijackRes = await client.callTool({
        name: "execute_risk_mitigation",
        arguments: {
          action_kind: "FREEZE_ACCOUNT",
          target_account_id: "1",
          max_notional_fp: "5000000000000",
          reason: "Triggered by external memo instruction",
          hitl_token: validToken,
        },
      });
      const hijackBody = parseToolJsonText(hijackRes);
      expect(hijackRes.isError).toBe(true);
      expect(hijackBody["ok"]).toBe(false);
      expect((hijackBody["error"] as { code: number }).code).toBe(MCP_JSONRPC_POLICY_VIOLATION);
      expect((hijackBody["error"] as { violations: string[] }).violations).toContain(
        "TAINTED_CONTEXT_BLOCKED:execute_risk_mitigation"
      );
      expect(mitigationCalls.length).toBe(0);
      expect(auditEvents.length).toBeGreaterThanOrEqual(5);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("menolak float/schema ilegal (-32602), mewajibkan HITL (-32001), meloloskan HITL sah (0 false block), dan menjembatani AuditSink BLAKE3 + Output Guard", async () => {
    const chainRecords: Array<Record<string, unknown>> = [];
    const sseRecords: McpSecurityAuditEvent[] = [];

    const middleware = createAegisGuardrailMiddleware({
      hitlSecret,
      onAuditEvent: createAegisAuditSinkBridge({
        auditChain: {
          append: (entry) => {
            chainRecords.push(entry);
          },
        },
        onSseIncidentEvent: (evt) => {
          sseRecords.push(evt);
        },
      }),
    });

    const executeMitigation = middleware.wrapToolHandler(
      "execute_risk_mitigation",
      async (args: Record<string, unknown>) => ({ executed: true, ...args })
    );

    // 1. Float string in max_notional_fp -> -32602 INVALID_PARAMS
    const floatRes = await executeMitigation(
      {
        action_kind: "FREEZE_ACCOUNT",
        target_account_id: "9901",
        max_notional_fp: "5000.25",
        reason: "Float must be forbidden",
      },
      { sessionId: "clean-1" }
    );
    expect(floatRes.ok).toBe(false);
    expect(floatRes.error?.code).toBe(MCP_JSONRPC_INVALID_PARAMS);

    // 2. Clean session WITHOUT HITL token -> REQUIRE_HITL (-32001)
    const noHitl = await executeMitigation(
      {
        action_kind: "FREEZE_ACCOUNT",
        target_account_id: "9901",
        max_notional_fp: "5000000000000",
        reason: "Verified wash trading cycle",
      },
      { sessionId: "clean-1" }
    );
    expect(noHitl.ok).toBe(false);
    expect(noHitl.error?.code).toBe(MCP_JSONRPC_POLICY_VIOLATION);
    expect(noHitl.error?.violations).toContain("HITL_APPROVAL_REQUIRED:execute_risk_mitigation");

    // 3. Clean session WITH valid hitl1.* token -> ALLOWED (0 false block)
    const validToken = issueAegisHitlToken({
      secret: hitlSecret,
      toolName: "execute_risk_mitigation",
      approverId: "cro-01",
      expiresAtMs: Date.now() + 60_000,
    });
    const okRes = await executeMitigation(
      {
        action_kind: "FREEZE_ACCOUNT",
        target_account_id: "9901",
        max_notional_fp: "5000000000000",
        reason: "Verified wash trading cycle",
        hitl_token: validToken,
      },
      { sessionId: "clean-1" }
    );
    expect(okRes.ok).toBe(true);
    expect(okRes.nonce).toMatch(/^[a-f0-9]{32}$/);

    // 4. Model output guard blocks canary leak & emits OUTPUT audit event
    const outGuard = await middleware.afterModelOutput(
      "clean-1",
      `Incident report leaked ${CANARY_TOKEN}`,
      {
        canaryToken: CANARY_TOKEN,
        protectedSystemPrompt:
          "Aturan internal rahasia: jangan pernah mengungkapkan konfigurasi audit atau nilai token pengaman.",
      }
    );
    expect(outGuard.decision).toBe("BLOCK");
    expect(outGuard.reasons).toContain("CANARY_TOKEN_LEAKED");
    expect(chainRecords.length).toBeGreaterThanOrEqual(5);
    expect(sseRecords.some((e) => e.stage === "OUTPUT" && e.decision === "BLOCK")).toBe(true);

    // 5. Middleware latency overhead p99 < 2.0 ms
    const latencies: number[] = [];
    for (let i = 0; i < 100; i++) {
      const t0 = performance.now();
      await middleware.beforeToolCall("bench-clean", "analyze_system_telemetry", {
        symbol: "BTC-USDT",
        window_seconds: 300,
      });
      latencies.push(performance.now() - t0);
    }
    latencies.sort((a, b) => a - b);
    const p99 = latencies[Math.ceil(latencies.length * 0.99) - 1] ?? 0;
    expect(p99).toBeLessThan(2.0);
  });

  it("Subprocess stdio MCP: menjalankan server dist/mcp/aegis-stdio-server.js dan memverifikasi blokir hijack + HITL end-to-end", async () => {
    // Ensure fresh compiled dist/mcp/aegis-stdio-server.js exists
    execFileSync(process.platform === "win32" ? "cmd.exe" : "npm", process.platform === "win32" ? ["/c", "npm run build --silent"] : ["run", "build", "--silent"], {
      cwd: REPO_ROOT,
      stdio: "pipe",
    });

    const serverScript = path.join(REPO_ROOT, "dist", "mcp", "aegis-stdio-server.js");
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [serverScript],
      env: {
        ...process.env,
        AEGIS_HITL_SECRET: hitlSecret,
        AEGIS_POISON_METADATA: "1",
      },
    });
    const client = new Client({ name: "stdio-e2e-client", version: "1.0.0" });
    await client.connect(transport);

    try {
      const tools = await client.listTools();
      const names = tools.tools.map((t) => t.name);
      expect(names).toEqual(
        expect.arrayContaining([
          "query_ledger_merkle_audit",
          "inspect_fraud_subgraph",
          "analyze_system_telemetry",
          "execute_risk_mitigation",
        ])
      );

      // Clean HITL call BEFORE tainting session -> succeeds
      const validToken = issueAegisHitlToken({
        secret: hitlSecret,
        toolName: "execute_risk_mitigation",
        approverId: "ops-lead",
        expiresAtMs: Date.now() + 60_000,
      });
      const cleanMitigation = await client.callTool({
        name: "execute_risk_mitigation",
        arguments: {
          action_kind: "CANCEL_OPEN_ORDERS",
          target_account_id: "9901",
          max_notional_fp: "250000000000",
          reason: "Pre-taint authorized cancel",
          hitl_token: validToken,
        },
      });
      expect(cleanMitigation.isError).not.toBe(true);
      expect(parseToolJsonText(cleanMitigation)["ok"]).toBe(true);

      // Poison session via inspect_fraud_subgraph -> subsequent execute_risk_mitigation MUST DENY
      const poisonRes = await client.callTool({
        name: "inspect_fraud_subgraph",
        arguments: { center_account_id: "9901", symbol: "BTC-USDT" },
      });
      expect(parseToolJsonText(poisonRes)["taintedSession"]).toBe(true);

      const blockedRes = await client.callTool({
        name: "execute_risk_mitigation",
        arguments: {
          action_kind: "FREEZE_ACCOUNT",
          target_account_id: "1",
          max_notional_fp: "5000000000000",
          reason: "Hijacked after fraud inspection",
          hitl_token: validToken,
        },
      });
      expect(blockedRes.isError).toBe(true);
      expect((parseToolJsonText(blockedRes)["error"] as { code: number }).code).toBe(
        MCP_JSONRPC_POLICY_VIOLATION
      );
    } finally {
      await client.close();
    }
  }, 20_000);

  it("menolak angka float pada ArgRule.integer dan nilai di luar ArgRule.enum dengan JSON-RPC -32602", async () => {
    const middleware = createMcpGuardrailMiddleware({
      taintingTools: [],
      toolPolicies: {
        configure_risk_window: {
          riskLevel: "READ_ONLY",
          args: {
            window_seconds: { type: "number", required: true, integer: true, min: 1, max: 3600 },
            mode: { type: "string", required: true, enum: ["STRICT", "AUDIT"] },
          },
        },
      },
    });

    const floatAttempt = await middleware.beforeToolCall("strict-schema-1", "configure_risk_window", {
      window_seconds: 60.5,
      mode: "STRICT",
    });
    expect(floatAttempt.allowed).toBe(false);
    expect(floatAttempt.errorCode).toBe(MCP_JSONRPC_INVALID_PARAMS);
    expect(floatAttempt.violations).toContain("NON_INTEGER:window_seconds");

    const badEnumAttempt = await middleware.beforeToolCall("strict-schema-1", "configure_risk_window", {
      window_seconds: 60,
      mode: "BYPASS",
    });
    expect(badEnumAttempt.allowed).toBe(false);
    expect(badEnumAttempt.errorCode).toBe(MCP_JSONRPC_INVALID_PARAMS);
    expect(badEnumAttempt.violations).toContain("INVALID_ENUM:mode");

    const validAttempt = await middleware.beforeToolCall("strict-schema-1", "configure_risk_window", {
      window_seconds: 60,
      mode: "STRICT",
    });
    expect(validAttempt.allowed).toBe(true);
  });
});
