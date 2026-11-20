import { createHmac, timingSafeEqual } from "node:crypto";
import type { ToolPolicy } from "../output-tool-gate.js";
import {
  createMcpGuardrailMiddleware,
  type McpGuardrailConfig,
  type McpGuardrailMiddleware,
  type McpSecurityAuditEvent,
} from "./middleware.js";

/**
 * Strict 4-tool MCP policy matrix matching HYPERION CH06 `aegis-agent`:
 * - READ_ONLY tools allowed even in tainted contexts (outputs sanitized with 128-bit L4 nonce).
 * - `inspect_fraud_subgraph` taints the session because it ingests external account/order metadata.
 * - `execute_risk_mitigation` is CRITICAL: strictly denies tainted invocations, bans floats via
 *   fixed-point integer string regex (`/^\d+$/`), and mandates verified `hitl1.*` approval tokens.
 */
export const AEGIS_TOOL_POLICIES: Record<string, ToolPolicy> = {
  query_ledger_merkle_audit: {
    riskLevel: "READ_ONLY",
    allowFromTaintedContext: true,
    args: {
      account_id: { type: "string", required: true, pattern: /^\d{1,20}$/ },
      asset: { type: "string", required: true, pattern: /^[A-Z]{2,10}$/ },
      at_engine_seq: { type: "string", required: false, pattern: /^\d{1,20}$/ },
      expected_state_root_blake3: { type: "string", required: false, pattern: /^[a-f0-9]{64}$/ },
    },
  },
  inspect_fraud_subgraph: {
    riskLevel: "READ_ONLY",
    allowFromTaintedContext: true,
    args: {
      center_account_id: { type: "string", required: true, pattern: /^\d{1,20}$/ },
      symbol: { type: "string", required: true, pattern: /^[A-Z0-9]{2,12}-[A-Z0-9]{2,10}$/ },
      max_hops: { type: "number", required: false, min: 1, max: 4 },
    },
  },
  analyze_system_telemetry: {
    riskLevel: "READ_ONLY",
    allowFromTaintedContext: true,
    args: {
      symbol: { type: "string", required: true, pattern: /^[A-Z0-9]{2,12}-[A-Z0-9]{2,10}$/ },
      window_seconds: { type: "number", required: true, min: 10, max: 3600 },
    },
  },
  execute_risk_mitigation: {
    riskLevel: "CRITICAL",
    allowFromTaintedContext: false,
    args: {
      action_kind: {
        type: "string",
        required: true,
        pattern: /^(?:FREEZE_ACCOUNT|CANCEL_OPEN_ORDERS|ENABLE_VOLATILITY_GUARD)$/,
      },
      target_account_id: { type: "string", required: true, pattern: /^\d{1,20}$/ },
      // Fixed-point 1e8 integer string (no IEEE-754 floats permitted in financial risk actions)
      max_notional_fp: { type: "string", required: true, pattern: /^\d{1,24}$/ },
      reason: { type: "string", required: true, pattern: /^.{4,240}$/ },
      hitl_token: { type: "string", required: false, pattern: /^hitl1\.[A-Za-z0-9_-]+\.[a-f0-9]{32,64}$/ },
    },
  },
};

export const AEGIS_TAINTING_TOOLS: readonly string[] = ["inspect_fraud_subgraph"];

/**
 * Issues a cryptographically signed `hitl1.<payloadB64Url>.<hmacHex>` approval token
 * scoped to a specific tool name.
 */
export function issueAegisHitlToken(params: {
  secret: string;
  toolName: string;
  approverId: string;
  expiresAtMs: number;
}): string {
  const payload = Buffer.from(
    JSON.stringify({
      tool: params.toolName,
      approver: params.approverId,
      exp: params.expiresAtMs,
    }),
    "utf8"
  ).toString("base64url");
  const sig = createHmac("sha256", params.secret).update(payload).digest("hex");
  return `hitl1.${payload}.${sig}`;
}

/**
 * Verifies a `hitl1.*` approval token with constant-time HMAC comparison, tool-name binding,
 * and expiration enforcement.
 */
export function verifyAegisHitlToken(
  token: string,
  expectedToolName: string,
  secret: string,
  nowMs: number = Date.now()
): boolean {
  if (!token.startsWith("hitl1.")) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [, payload, sigHex] = parts;
  if (!payload || !sigHex || !/^[a-f0-9]{64}$/i.test(sigHex)) return false;

  const expectedHex = createHmac("sha256", secret).update(payload).digest("hex");
  const actualBuf = Buffer.from(sigHex, "hex");
  const expectedBuf = Buffer.from(expectedHex, "hex");
  if (actualBuf.length !== expectedBuf.length || !timingSafeEqual(actualBuf, expectedBuf)) {
    return false;
  }

  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as {
      tool?: string;
      exp?: number;
    };
    if (parsed.tool !== expectedToolName) return false;
    if (typeof parsed.exp !== "number" || parsed.exp <= nowMs) return false;
    return true;
  } catch {
    return false;
  }
}

export interface AegisGuardrailOptions {
  hitlSecret: string;
  onAuditEvent?: (event: McpSecurityAuditEvent) => void | Promise<void>;
  cascade?: McpGuardrailConfig["cascade"];
  now?: () => number;
}

/**
 * Drop-in guardrail middleware pre-configured for all 4 `aegis-agent` (HYPERION CH06) MCP tools.
 */
export function createAegisGuardrailMiddleware(
  options: AegisGuardrailOptions
): McpGuardrailMiddleware {
  const now = options.now ?? (() => Date.now());
  return createMcpGuardrailMiddleware({
    toolPolicies: AEGIS_TOOL_POLICIES,
    taintingTools: [...AEGIS_TAINTING_TOOLS],
    verifyHitlToken: (token, toolName) =>
      verifyAegisHitlToken(token, toolName, options.hitlSecret, now()),
    ...(options.cascade ? { cascade: options.cascade } : {}),
    ...(options.onAuditEvent ? { onAuditEvent: options.onAuditEvent } : {}),
  });
}
