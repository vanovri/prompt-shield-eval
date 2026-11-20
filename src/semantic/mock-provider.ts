import type { SemanticLabel, SemanticPrediction, SemanticProvider } from "./types.js";

export interface MockSemanticProviderOptions {
  /** Artificial delay in ms (useful for testing hard timeout handling). */
  artificialDelayMs?: number;
  /** Force throw error on classify (useful for testing failMode). */
  forceError?: boolean;
  /** Optional custom classifier callback for deterministic unit tests. */
  customClassifier?: (
    text: string
  ) => { label: SemanticLabel; confidence: number } | undefined;
}

const PI06_FRAMING_RE =
  /\b(?:novel|screenplay|script|movie|drama|character|protagonist|antagonist|fictional|story|chapter|dialogue|hypothetical|thought\s+experiment|academic|research\s+paper|professor|thesis|roleplay|diary|cerita|naskah|skenario|bab|tokoh|dialog|hipotetis|penelitian|akademis|skripsi|jurnal)\b/i;

const PI06_EXTRACTION_INTENT_RE =
  /\b(?:system\s+prompt|hidden\s+(?:instructions?|policy|rules?|config)|internal\s+(?:directive|guidelines?|rules?|secrets?)|secret\s+(?:token|canary|phrase|key|instructions?)|bypass\s+(?:guardrails?|filters?|moderation|safety)|override\s+(?:safety|policy|rules?)|extract\s+(?:credentials?|secrets?|prompt)|exfiltrat|canary|membocorkan|mengungkapkan\s+(?:instruksi|aturan|rahasia)|lewati\s+(?:filter|batas|pengaman)|menonaktifkan\s+pengaman|memintas\s+aturan)\b/i;

const PI09_CROSS_LANG_INTENT_RE =
  /(?:oublie(?:z)?\s+(?:toutes?\s+les\s+)?(?:instructions?|r[eè]gles?)|ignore(?:z)?\s+(?:toutes?\s+les\s+)?(?:instructions?|r[eè]gles?)|r[eé]v[eè]le(?:z)?\s+le\s+prompt|ignora\s+(?:todas\s+las\s+)?instrucciones|muestra\s+el\s+prompt\s+del\s+sistema|revela\s+(?:las\s+instrucciones|el\s+canary|el\s+secreto)|ignoriere\s+(?:alle\s+)?(?:vorherigen\s+)?(?:anweisungen|regeln)|zeige\s+(?:den\s+)?system[- ]?prompt|verrate\s+(?:das\s+)?(?:geheimnis|canary)|これまでの指示を無視|以前の指示を忘れ|システムプロンプトを表示|秘密のカナリア|ルールを無視して|nggak\s+usah\s+ikut\s+aturan|ora\s+sah\s+nurut\s+aturan|teu\s+kudu\s+nurut\s+aturan|cuekin\s+(?:semua\s+)?(?:rules?|aturan)|spill\s+(?:system\s+prompt|canary|instruksi\s+rahasia)|bocorin\s+(?:prompt|canary|aturan\s+dalem))/i;

/**
 * 100% offline deterministic semantic provider for core CI unit tests,
 * timeout/fail-mode tests, and mock evaluation without loading ONNX weights.
 */
export class DeterministicMockSemanticProvider implements SemanticProvider {
  public readonly name = "mock-deterministic";
  private readonly options: MockSemanticProviderOptions;
  private warmedUp = false;

  public constructor(options: MockSemanticProviderOptions = {}) {
    this.options = options;
  }

  public async warmup(): Promise<void> {
    this.warmedUp = true;
  }

  public isWarmedUp(): boolean {
    return this.warmedUp;
  }

  public async classify(
    normalizedText: string,
    signal?: AbortSignal
  ): Promise<SemanticPrediction> {
    const start = performance.now();

    if (this.options.artificialDelayMs && this.options.artificialDelayMs > 0) {
      await new Promise<void>((resolve, reject) => {
        if (signal?.aborted) {
          reject(new Error("ABORTED"));
          return;
        }
        const timer = setTimeout(resolve, this.options.artificialDelayMs);
        const onAbort = () => {
          clearTimeout(timer);
          reject(new Error("ABORTED"));
        };
        signal?.addEventListener("abort", onAbort, { once: true });
      });
    }

    if (this.options.forceError) {
      throw new Error("MOCK_SEMANTIC_PROVIDER_ERROR");
    }

    const custom = this.options.customClassifier?.(normalizedText);
    if (custom) {
      return {
        label: custom.label,
        confidence: custom.confidence,
        latencyMs: Number((performance.now() - start).toFixed(3)),
        timedOut: false,
        provider: "mock-deterministic",
      };
    }

    let label: SemanticLabel = "BENIGN";
    let confidence = 0.94;

    if (PI09_CROSS_LANG_INTENT_RE.test(normalizedText)) {
      label = "PI09_CROSS_LANG_INJECTION";
      confidence = 0.93;
    } else if (
      PI06_FRAMING_RE.test(normalizedText) &&
      PI06_EXTRACTION_INTENT_RE.test(normalizedText)
    ) {
      label = "PI06_ROLEPLAY_BYPASS";
      confidence = 0.91;
    }

    return {
      label,
      confidence,
      latencyMs: Number((performance.now() - start).toFixed(3)),
      timedOut: false,
      provider: "mock-deterministic",
    };
  }

  public async dispose(): Promise<void> {
    this.warmedUp = false;
  }
}
