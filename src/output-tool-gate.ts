import { canonicalizeInput } from "./normalizer.js";

export interface OutputGuardConfig {
  canaryToken: string;
  protectedSystemPrompt: string;
  ngramSize?: number;
  maxNgramOverlap?: number;
}

export interface OutputGuardResult {
  allowed: boolean;
  decision: "ALLOW" | "BLOCK";
  reasons: string[];
  ngramOverlap: number;
  redactedOutput: string;
}

function tokenizeWords(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length > 0);
}

function buildNgrams(words: string[], n: number): Set<string> {
  const grams = new Set<string>();
  for (let i = 0; i <= words.length - n; i++) {
    grams.add(words.slice(i, i + n).join(" "));
  }
  return grams;
}

export function evaluateModelOutput(
  modelOutput: string,
  config: OutputGuardConfig
): OutputGuardResult {
  const reasons: string[] = [];
  const ngramSize = config.ngramSize ?? 4;
  const maxOverlap = config.maxNgramOverlap ?? 0.3;

  const norm = canonicalizeInput(modelOutput, 2);
  const candidates = [
    modelOutput,
    norm.homoglyphNormalized,
    norm.leetNormalized,
    ...norm.decodedPayloads,
  ];

  const canaryLower = config.canaryToken.toLowerCase();
  const canaryCompact = canaryLower.replace(/[^a-z0-9]/g, "");

  // 1. Cek kebocoran canary langsung, ter-obfuscate, ter-encode, atau terspasi
  const canaryLeaked = candidates.some((text) => {
    const lower = text.toLowerCase();
    const compact = lower.replace(/[^a-z0-9]/g, "");
    return lower.includes(canaryLower) || compact.includes(canaryCompact);
  });

  if (canaryLeaked) {
    reasons.push("CANARY_TOKEN_LEAKED");
  }

  // 2. Cek kemiripan n-gram terhadap protected system prompt (termasuk hasil dekode & de-leet)
  const promptGrams = buildNgrams(tokenizeWords(config.protectedSystemPrompt), ngramSize);
  const ngramTargets = new Set<string>([norm.homoglyphNormalized, norm.leetNormalized]);
  for (const decoded of norm.decodedPayloads) {
    const inner = canonicalizeInput(decoded, 1);
    ngramTargets.add(inner.homoglyphNormalized);
    ngramTargets.add(inner.leetNormalized);
  }

  let bestMatchedGrams = 0;
  let ngramOverlap = 0;
  for (const target of ngramTargets) {
    const outputGrams = buildNgrams(tokenizeWords(target), ngramSize);
    let matchedGrams = 0;
    for (const gram of promptGrams) {
      if (outputGrams.has(gram)) matchedGrams++;
    }
    const overlap = promptGrams.size === 0 ? 0 : matchedGrams / promptGrams.size;
    if (overlap > ngramOverlap) {
      ngramOverlap = overlap;
      bestMatchedGrams = matchedGrams;
    }
  }

  if (bestMatchedGrams >= 2 && ngramOverlap >= maxOverlap) {
    reasons.push("SYSTEM_PROMPT_NGRAM_LEAK");
  }

  const blocked = reasons.length > 0;
  return {
    allowed: !blocked,
    decision: blocked ? "BLOCK" : "ALLOW",
    reasons,
    ngramOverlap: Number(ngramOverlap.toFixed(4)),
    redactedOutput: blocked
      ? "[OUTPUT_BLOCKED_BY_SECURITY_POLICY]"
      : modelOutput,
  };
}

export type ToolRiskLevel = "READ_ONLY" | "WRITE" | "CRITICAL";

export interface ArgRule {
  type: "string" | "number" | "boolean";
  required?: boolean;
  pattern?: RegExp;
  min?: number;
  max?: number;
  integer?: boolean;
  enum?: readonly (string | number | boolean)[];
}

export interface ToolPolicy {
  riskLevel: ToolRiskLevel;
  allowFromTaintedContext?: boolean;
  args: Record<string, ArgRule>;
}

export interface ToolCallRequest {
  name: string;
  args: Record<string, unknown>;
}

export interface ToolCallContext {
  taintedByUntrustedData: boolean;
  validHitlToken?: boolean;
}

export interface ToolGateResult {
  decision: "ALLOW" | "REQUIRE_HITL" | "DENY";
  violations: string[];
}

export function evaluateToolCall(
  request: ToolCallRequest,
  allowlist: Record<string, ToolPolicy>,
  context: ToolCallContext
): ToolGateResult {
  const violations: string[] = [];
  const policy = allowlist[request.name];

  if (!policy) {
    return { decision: "DENY", violations: [`TOOL_NOT_ALLOWLISTED:${request.name}`] };
  }

  // Tolak parameter tidak dikenal (strict schema)
  for (const key of Object.keys(request.args)) {
    if (!(key in policy.args)) {
      violations.push(`UNKNOWN_ARG:${key}`);
    }
  }

  // Validasi tipe, wajib, regex, dan rentang numerik
  for (const [argName, rule] of Object.entries(policy.args)) {
    const val = request.args[argName];
    if (val === undefined || val === null) {
      if (rule.required) violations.push(`MISSING_REQUIRED_ARG:${argName}`);
      continue;
    }

    if (typeof val !== rule.type) {
      violations.push(`INVALID_TYPE:${argName}`);
      continue;
    }

    if (rule.type === "string" && rule.pattern && !rule.pattern.test(val as string)) {
      violations.push(`PATTERN_MISMATCH:${argName}`);
    }

    if (rule.type === "number") {
      const num = val as number;
      if (!Number.isFinite(num)) violations.push(`NON_FINITE_NUMBER:${argName}`);
      if (rule.integer && !Number.isInteger(num)) violations.push(`NON_INTEGER:${argName}`);
      if (rule.min !== undefined && num < rule.min) violations.push(`BELOW_MIN:${argName}`);
      if (rule.max !== undefined && num > rule.max) violations.push(`ABOVE_MAX:${argName}`);
    }

    if (rule.enum && !rule.enum.includes(val as string | number | boolean)) {
      violations.push(`INVALID_ENUM:${argName}`);
    }
  }

  if (violations.length > 0) {
    return { decision: "DENY", violations };
  }

  // Taint isolation: data eksternal tidak boleh memicu tool WRITE/CRITICAL
  if (context.taintedByUntrustedData && !policy.allowFromTaintedContext) {
    if (policy.riskLevel !== "READ_ONLY") {
      return {
        decision: "DENY",
        violations: [`TAINTED_CONTEXT_BLOCKED:${request.name}`],
      };
    }
  }

  // Aksi CRITICAL dari user sah tetap wajib HITL jika belum disetujui
  if (policy.riskLevel === "CRITICAL" && !context.validHitlToken) {
    return {
      decision: "REQUIRE_HITL",
      violations: [`HITL_APPROVAL_REQUIRED:${request.name}`],
    };
  }

  return { decision: "ALLOW", violations: [] };
}
