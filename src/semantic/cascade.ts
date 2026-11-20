import { evaluatePromptSecurity } from "../hardened-detector.js";
import type { Decision, SourceChannel } from "../types.js";
import type {
  CascadeDetectorOptions,
  CascadeDetectorResult,
  SemanticPrediction,
} from "./types.js";

const FRAMING_CUE_RE =
  /\b(?:novel|screenplay|script|movie|drama|fiction(?:al)?|story|storytelling|chapter|dialogue|character|protagonist|hypothetical|thought\s+experiment|academic|research(?:\s+paper|\s+study)?|professor|thesis|seminar|roleplay|imagine\s+a\s+world|cerita|fiksi|naskah|skenario|bab|tokoh|dialog|hipotetis|penelitian|akademis|riset|skripsi|jurnal|sandiwara)\b/i;

const LONG_INSTRUCTIVE_CUE_RE =
  /\b(?:explain|describe|demonstrate|draft|compose|write|reveal|print|output|show|disclose|bypass|override|ignore|extract|simulate|tuliskan|jelaskan|gambarkan|tunjukkan|ungkapkan|keluarkan|abaikan|lewati|simulasikan)\b/i;

const MULTILINGUAL_CUE_RE =
  /(?:\p{Script=Hiragana}|\p{Script=Katakana}|\p{Script=Han}|\p{Script=Arabic}|\p{Script=Devanagari}|\p{Script=Hangul}|[àáâãäåæçèéêëìíîïñòóôõöøùúûüýÿœß¡¿]|\b(?:translate|terjemahkan|traduire|traducir|übersetzen|oubliez?|ignorez?|r[eé]v[eè]lez?|ignora|muestra|revela|ignoriere|zeige|verrate|nggak\s+usah|ora\s+sah|teu\s+kudu|cuekin|bocorin|spill)\b)/iu;

export function detectSemanticEscalationReasons(
  windowText: string,
  deterministicScore: number,
  grayZoneMinScore: number
): string[] {
  const reasons: string[] = [];

  if (deterministicScore >= grayZoneMinScore && deterministicScore < 50) {
    reasons.push("GRAY_ZONE_SCORE");
  }
  if (FRAMING_CUE_RE.test(windowText)) {
    reasons.push("FRAMING_CUE");
  }
  if (windowText.length > 120 && LONG_INSTRUCTIVE_CUE_RE.test(windowText)) {
    reasons.push("LONG_INSTRUCTIVE_CUE");
  }
  if (MULTILINGUAL_CUE_RE.test(windowText)) {
    reasons.push("MULTILINGUAL_CUE");
  }

  return reasons;
}

async function classifyWithTimeout(
  provider: NonNullable<CascadeDetectorOptions["semanticProvider"]>,
  text: string,
  timeoutMs: number
): Promise<{ prediction?: SemanticPrediction; timedOut: boolean; error?: unknown }> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;

  const timeoutPromise = new Promise<"TIMEOUT">((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve("TIMEOUT");
    }, timeoutMs);
  });

  try {
    const outcome = await Promise.race([
      provider.classify(text, controller.signal),
      timeoutPromise,
    ]);

    if (outcome === "TIMEOUT") {
      return { timedOut: true };
    }
    return { prediction: outcome, timedOut: outcome.timedOut };
  } catch (error) {
    if (controller.signal.aborted) {
      return { timedOut: true };
    }
    return { timedOut: false, error };
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/**
 * Hybrid Cascade Security Evaluator:
 * - Fast-path L1-L3 deterministic engine (0 ms ONNX overhead on clear BLOCK or clean non-cued inputs).
 * - Selective escalation to L3.5 Semantic Provider (ONNX INT8 or deterministic mock) for gray-zone,
 *   subtle framing (PI-06), and cross-lingual (PI-09) prompts with hard timeout + explicit failMode.
 */
export async function evaluatePromptSecurityAsync(
  history: string[],
  sourceChannel: SourceChannel = "user",
  options: CascadeDetectorOptions = {}
): Promise<CascadeDetectorResult> {
  const base = evaluatePromptSecurity(history, sourceChannel);

  const provider = options.semanticProvider;
  // Fast-path short-circuit: already blocked by deterministic L1-L3 or no semantic provider configured
  if (!provider || base.decision === "BLOCK") {
    return {
      ...base,
      semanticEscalated: false,
      escalationReasons: [],
      semanticFailOpen: false,
    };
  }

  const grayZoneMinScore = options.grayZoneMinScore ?? 15;
  const timeoutMs = options.semanticTimeoutMs ?? 25;
  const blockThreshold = options.semanticBlockThreshold ?? 0.85;
  const quarantineThreshold = options.semanticQuarantineThreshold ?? 0.65;
  const failMode = options.failMode ?? "QUARANTINE";

  const recentWindow = history.slice(-5).join("\n");
  const escalationReasons = detectSemanticEscalationReasons(
    recentWindow,
    base.score,
    grayZoneMinScore
  );

  if (escalationReasons.length === 0) {
    return {
      ...base,
      semanticEscalated: false,
      escalationReasons: [],
      semanticFailOpen: false,
    };
  }

  // Pass normalized text with Unicode tags/invisible stripped while preserving multilingual script cues
  const semanticInput = recentWindow.normalize("NFKC");
  const outcome = await classifyWithTimeout(provider, semanticInput, timeoutMs);

  const matchedRules = new Set(base.matchedRules);
  let score = base.score;
  let decision: Decision = base.decision;
  let semanticFailOpen = false;

  if (outcome.timedOut || outcome.error || !outcome.prediction) {
    if (failMode === "QUARANTINE") {
      matchedRules.add(
        outcome.timedOut ? "L3.5-semantic-timeout-quarantine" : "L3.5-semantic-error-quarantine"
      );
      if (decision === "ALLOW") decision = "QUARANTINE";
      score = Math.max(score, 35);
    } else {
      semanticFailOpen = true;
    }

    return {
      ...base,
      decision,
      score: Math.min(100, score),
      matchedRules: Array.from(matchedRules),
      semanticEscalated: true,
      escalationReasons,
      semanticPrediction: {
        label: "BENIGN",
        confidence: 0,
        latencyMs: timeoutMs,
        timedOut: outcome.timedOut,
        provider: provider.name === "onnx-int8" ? "onnx-int8" : "mock-deterministic",
      },
      semanticFailOpen,
    };
  }

  const pred = outcome.prediction;
  if (pred.label !== "BENIGN") {
    const ruleId =
      pred.label === "PI06_ROLEPLAY_BYPASS"
        ? "L3.5-semantic-pi06-roleplay"
        : "L3.5-semantic-pi09-crosslang";

    if (pred.confidence >= blockThreshold) {
      matchedRules.add(ruleId);
      score = Math.max(score, Math.round(55 + pred.confidence * 35));
      decision = sourceChannel === "user" ? "BLOCK" : "QUARANTINE";
    } else if (pred.confidence >= quarantineThreshold) {
      matchedRules.add(ruleId);
      score = Math.max(score, Math.round(30 + pred.confidence * 20));
      if (decision === "ALLOW") decision = "QUARANTINE";
    }
  }

  return {
    ...base,
    decision,
    score: Math.min(100, score),
    matchedRules: Array.from(matchedRules),
    semanticEscalated: true,
    escalationReasons,
    semanticPrediction: pred,
    semanticFailOpen,
  };
}
