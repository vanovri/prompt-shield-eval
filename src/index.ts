export type {
  Decision,
  DetectorResult,
  EvalCase,
  EvalFailure,
  EvalReport,
  NormalizationResult,
  SourceChannel,
  TaxonomyId,
} from "./types.js";

export { canonicalizeInput } from "./normalizer.js";
export { evaluatePromptSecurity, warmupDetector } from "./hardened-detector.js";
export {
  buildTrustBoundaryPrompt,
  sanitizeUntrustedContent,
  type TrustBoundaryResult,
} from "./trust-boundary.js";
export {
  evaluateModelOutput,
  evaluateToolCall,
  type ArgRule,
  type OutputGuardConfig,
  type OutputGuardResult,
  type ToolCallContext,
  type ToolCallRequest,
  type ToolGateResult,
  type ToolPolicy,
  type ToolRiskLevel,
} from "./output-tool-gate.js";
export {
  TaintSessionStore,
  type SessionTaintState,
  type TaintSessionStoreOptions,
} from "./session-taint.js";
export { CANARY_TOKEN, EVAL_DATASET, encodeUnicodeTags } from "./eval-dataset.js";
export { runEvalHarness, type EvalHarnessOptions } from "./eval-harness.js";
