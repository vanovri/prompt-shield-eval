import type {
  DetectorResult,
  EvalCase,
  EvalFailure,
  EvalReport,
  SourceChannel,
} from "./types.js";

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil(sorted.length * p) - 1));
  return Number((sorted[idx] ?? 0).toFixed(3));
}

export interface EvalHarnessOptions {
  warmup?: boolean;
}

export async function runEvalHarness(
  cases: EvalCase[],
  evaluateTurn: (history: string[], sourceChannel: SourceChannel) => Promise<DetectorResult> | DetectorResult,
  options: EvalHarnessOptions = {}
): Promise<EvalReport> {
  if (options.warmup !== false) {
    await evaluateTurn(["warmup baseline check"], "user");
    await evaluateTurn(["\u0406gn\u043Er\u0435 warmup SGVsbG8gV29ybGQgMjAyNg=="], "user");
  }

  let tp = 0;
  let fn = 0;
  let fp = 0;
  let tn = 0;
  let exactMatches = 0;

  const latenciesMs: number[] = [];
  const failures: EvalFailure[] = [];

  for (const tc of cases) {
    const channel: SourceChannel = tc.sourceChannel ?? "user";
    const history: string[] = [];
    let finalResult: DetectorResult = {
      decision: "ALLOW",
      score: 0,
      matchedRules: [],
      normalizedText: "",
      signals: {
        hiddenCharCount: 0,
        unicodeTagCount: 0,
        homoglyphCount: 0,
        leetSubstitutions: 0,
        maxDecodeDepth: 0,
      },
    };

    const start = performance.now();
    for (const turn of tc.turns) {
      history.push(turn);
      finalResult = await evaluateTurn(history, channel);
      if (finalResult.decision === "BLOCK") break;
    }
    latenciesMs.push(performance.now() - start);

    const isAttack = tc.expectedDecision !== "ALLOW";
    const flagged = finalResult.decision !== "ALLOW";
    const isExact = finalResult.decision === tc.expectedDecision;

    if (isExact) exactMatches++;

    if (isAttack && flagged) {
      tp++;
      if (!isExact) {
        failures.push({
          id: tc.id,
          taxonomyId: tc.taxonomyId,
          kind: "DECISION_MISMATCH",
          expected: tc.expectedDecision,
          actual: finalResult.decision,
          score: finalResult.score,
          matchedRules: finalResult.matchedRules,
        });
      }
    } else if (isAttack && !flagged) {
      fn++;
      failures.push({
        id: tc.id,
        taxonomyId: tc.taxonomyId,
        kind: "MISSED_ATTACK",
        expected: tc.expectedDecision,
        actual: finalResult.decision,
        score: finalResult.score,
        matchedRules: finalResult.matchedRules,
      });
    } else if (!isAttack && flagged) {
      fp++;
      failures.push({
        id: tc.id,
        taxonomyId: tc.taxonomyId,
        kind: "FALSE_POSITIVE",
        expected: tc.expectedDecision,
        actual: finalResult.decision,
        score: finalResult.score,
        matchedRules: finalResult.matchedRules,
      });
    } else {
      tn++;
    }
  }

  latenciesMs.sort((a, b) => a - b);

  const attackCases = tp + fn;
  const benignCases = fp + tn;
  const tpr = attackCases === 0 ? 1 : tp / attackCases;
  const fpr = benignCases === 0 ? 0 : fp / benignCases;
  const exactMatchRate = cases.length === 0 ? 1 : exactMatches / cases.length;

  return {
    totalCases: cases.length,
    attackCases,
    benignCases,
    tpr: Number(tpr.toFixed(4)),
    fpr: Number(fpr.toFixed(4)),
    bypassRate: Number((1 - tpr).toFixed(4)),
    exactMatchRate: Number(exactMatchRate.toFixed(4)),
    p50LatencyMs: percentile(latenciesMs, 0.5),
    p99LatencyMs: percentile(latenciesMs, 0.99),
    failures,
  };
}
