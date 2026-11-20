import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  extractSemanticFeatures,
  SEMANTIC_FEATURE_DIM,
  SEMANTIC_MAX_SEQ_LEN,
} from "./tokenizer.js";
import type {
  CentroidsArtifact,
  SemanticLabel,
  SemanticModelManifest,
  SemanticPrediction,
  SemanticProvider,
} from "./types.js";

const LABELS: readonly SemanticLabel[] = [
  "BENIGN",
  "PI06_ROLEPLAY_BYPASS",
  "PI09_CROSS_LANG_INJECTION",
];

export class SemanticArtifactIntegrityError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = "SemanticArtifactIntegrityError";
  }
}

export interface OnnxInt8SemanticProviderOptions {
  /** Directory containing manifest.v1.json, model .onnx, and centroids.v1.json. Defaults to package models/ directory. */
  modelsDir?: string;
  /** Override explicit path to ONNX INT8 model file. */
  modelPath?: string;
  /** Override explicit path to centroids.v1.json file. */
  centroidsPath?: string;
  /** Override expected SHA-256 hex digest of ONNX model file (enforced on warmup). */
  expectedModelSha256?: string;
  /** Override expected SHA-256 hex digest of centroids JSON file (enforced on warmup). */
  expectedCentroidsSha256?: string;
  /** Classification strategy: calibrated centroid cosine similarity (default) or ONNX 3-class linear probe head. */
  mode?: "centroid" | "probe";
  /** Temperature scaling parameter override for softmax calibration. */
  temperature?: number;
  /** Number of intra-op CPU threads for ONNX Runtime (default: 1 for deterministic low jitter). */
  intraOpNumThreads?: number;
}

interface OrtTensorLike {
  readonly data: Float32Array | Int32Array | BigInt64Array | ArrayLike<number>;
  readonly dims: readonly number[];
}

interface OrtSessionLike {
  run(feeds: Record<string, unknown>): Promise<Record<string, OrtTensorLike>>;
  release?: () => Promise<void>;
}

interface OrtModuleLike {
  Tensor: new (type: string, data: Float32Array | BigInt64Array, dims: readonly number[]) => unknown;
  InferenceSession: {
    create(
      modelPathOrBuffer: string | Uint8Array,
      options?: Record<string, unknown>
    ): Promise<OrtSessionLike>;
  };
}

function sha256Hex(buffer: Uint8Array): string {
  return createHash("sha256").update(buffer).digest("hex");
}

function cosineSimilarity(a: ArrayLike<number>, b: readonly number[]): number {
  const len = Math.min(a.length, b.length);
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < len; i++) {
    const va = a[i] ?? 0;
    const vb = b[i] ?? 0;
    dot += va * vb;
    normA += va * va;
    normB += vb * vb;
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

function calibratedSoftmax(scores: readonly number[], temperature: number): number[] {
  const t = Math.max(1e-4, temperature);
  let maxScaled = -Infinity;
  const scaled = scores.map((s) => {
    const v = s / t;
    if (v > maxScaled) maxScaled = v;
    return v;
  });
  const exps = scaled.map((v) => Math.exp(v - maxScaled));
  const sum = exps.reduce((acc, v) => acc + v, 0) || 1;
  return exps.map((v) => v / sum);
}

function resolveDefaultModelsDir(): string {
  const currentDir = path.dirname(fileURLToPath(import.meta.url));
  // Works both from src/semantic/ (Vitest/tsx) and dist/semantic/ (compiled ESM)
  return path.resolve(currentDir, "..", "..", "models");
}

/**
 * Layer 3.5 ONNX Runtime INT8 Semantic Classifier Provider.
 *
 * - Dynamically imports `onnxruntime-node` (keeping Core 0-runtime-dependency).
 * - Enforces SHA-256 verification of both ONNX INT8 model and `centroids.v1.json` before loading.
 * - Supports calibrated Centroid Cosine mode (updatable without retraining) and 3-class Linear Probe mode.
 */
export class OnnxInt8SemanticProvider implements SemanticProvider {
  public readonly name = "onnx-int8";
  private readonly options: OnnxInt8SemanticProviderOptions;
  private ort: OrtModuleLike | null = null;
  private session: OrtSessionLike | null = null;
  private centroids: CentroidsArtifact | null = null;
  private manifest: SemanticModelManifest | null = null;
  private verifiedModelSha256: string | null = null;
  private verifiedCentroidsSha256: string | null = null;

  public constructor(options: OnnxInt8SemanticProviderOptions = {}) {
    this.options = options;
  }

  public getIntegrityInfo(): {
    modelSha256: string | null;
    centroidsSha256: string | null;
    manifest: SemanticModelManifest | null;
  } {
    return {
      modelSha256: this.verifiedModelSha256,
      centroidsSha256: this.verifiedCentroidsSha256,
      manifest: this.manifest,
    };
  }

  public async warmup(): Promise<void> {
    if (this.session) return;

    const modelsDir = this.options.modelsDir ?? resolveDefaultModelsDir();
    const manifestPath = path.join(modelsDir, "manifest.v1.json");
    const manifestRaw = await readFile(manifestPath, "utf8");
    const manifest = JSON.parse(manifestRaw) as SemanticModelManifest;
    this.manifest = manifest;

    const modelPath = this.options.modelPath ?? path.join(modelsDir, manifest.modelFile);
    const centroidsPath =
      this.options.centroidsPath ?? path.join(modelsDir, manifest.centroidsFile);

    const expectedModelSha = this.options.expectedModelSha256 ?? manifest.modelSha256;
    const expectedCentroidsSha =
      this.options.expectedCentroidsSha256 ?? manifest.centroidsSha256;

    const [modelBytes, centroidsBytes] = await Promise.all([
      readFile(modelPath),
      readFile(centroidsPath),
    ]);

    const actualModelSha = sha256Hex(modelBytes);
    if (actualModelSha !== expectedModelSha) {
      throw new SemanticArtifactIntegrityError(
        `ONNX model SHA-256 mismatch for ${modelPath}: expected ${expectedModelSha}, got ${actualModelSha}`
      );
    }

    const actualCentroidsSha = sha256Hex(centroidsBytes);
    if (actualCentroidsSha !== expectedCentroidsSha) {
      throw new SemanticArtifactIntegrityError(
        `Centroids artifact SHA-256 mismatch for ${centroidsPath}: expected ${expectedCentroidsSha}, got ${actualCentroidsSha}`
      );
    }

    const centroids = JSON.parse(centroidsBytes.toString("utf8")) as CentroidsArtifact;
    if (centroids.modelSha256 !== actualModelSha) {
      throw new SemanticArtifactIntegrityError(
        `Centroids artifact modelSha256 (${centroids.modelSha256}) does not match loaded ONNX model (${actualModelSha})`
      );
    }

    let ortModule: OrtModuleLike;
    try {
      const imported = (await import("onnxruntime-node")) as unknown as {
        default?: OrtModuleLike;
      } & Partial<OrtModuleLike>;
      ortModule = (imported.InferenceSession ? imported : imported.default) as OrtModuleLike;
    } catch (error) {
      throw new Error(
        `Optional peer dependency "onnxruntime-node" is required for OnnxInt8SemanticProvider: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }

    const threads = Math.max(1, this.options.intraOpNumThreads ?? 1);
    const session = await ortModule.InferenceSession.create(modelBytes, {
      executionProviders: ["cpu"],
      graphOptimizationLevel: "all",
      intraOpNumThreads: threads,
      interOpNumThreads: 1,
    });

    this.ort = ortModule;
    this.session = session;
    this.centroids = centroids;
    this.verifiedModelSha256 = actualModelSha;
    this.verifiedCentroidsSha256 = actualCentroidsSha;

    // Warmup single pass to prime ONNX Runtime CPU threadpool & allocator
    await this.classify("warmup baseline benign check");
  }

  public async classify(
    normalizedText: string,
    signal?: AbortSignal
  ): Promise<SemanticPrediction> {
    if (signal?.aborted) {
      return {
        label: "BENIGN",
        confidence: 0,
        latencyMs: 0,
        timedOut: true,
        provider: "onnx-int8",
      };
    }

    if (!this.session || !this.ort || !this.centroids) {
      await this.warmup();
    }

    const start = performance.now();
    const featureDim = this.centroids?.featureDim ?? SEMANTIC_FEATURE_DIM;
    const maxSeqLen = this.centroids?.maxSeqLen ?? SEMANTIC_MAX_SEQ_LEN;
    const features = extractSemanticFeatures(normalizedText, featureDim, maxSeqLen);

    const inputTensor = new this.ort!.Tensor("float32", features, [1, featureDim]);
    const outputs = await this.session!.run({ features: inputTensor });

    if (signal?.aborted) {
      return {
        label: "BENIGN",
        confidence: 0,
        latencyMs: Number((performance.now() - start).toFixed(3)),
        timedOut: true,
        provider: "onnx-int8",
      };
    }

    const mode = this.options.mode ?? "centroid";
    const embeddingTensor = outputs["embedding"];
    const logitsTensor = outputs["logits"];

    let probs: number[];
    let similarities: Record<SemanticLabel, number> | undefined;

    if (mode === "probe" && logitsTensor) {
      const rawLogits = [
        Number(logitsTensor.data[0] ?? 0),
        Number(logitsTensor.data[1] ?? 0),
        Number(logitsTensor.data[2] ?? 0),
      ];
      const temp = this.options.temperature ?? 1.0;
      probs = calibratedSoftmax(rawLogits, temp);
    } else {
      if (!embeddingTensor) {
        throw new Error("ONNX model did not return expected 'embedding' output tensor.");
      }
      const emb = embeddingTensor.data as Float32Array;
      const c = this.centroids!.centroids;

      let benignSim = cosineSimilarity(emb, c.BENIGN);
      if (this.centroids!.benignAnchors) {
        for (const anchorVec of Object.values(this.centroids!.benignAnchors)) {
          const anchorSim = cosineSimilarity(emb, anchorVec);
          if (anchorSim > benignSim) benignSim = anchorSim;
        }
      }
      const pi06Sim = cosineSimilarity(emb, c.PI06_ROLEPLAY_BYPASS);
      const pi09Sim = cosineSimilarity(emb, c.PI09_CROSS_LANG_INJECTION);

      similarities = {
        BENIGN: Number(benignSim.toFixed(4)),
        PI06_ROLEPLAY_BYPASS: Number(pi06Sim.toFixed(4)),
        PI09_CROSS_LANG_INJECTION: Number(pi09Sim.toFixed(4)),
      };

      const temp = this.options.temperature ?? this.centroids!.temperature;
      probs = calibratedSoftmax([benignSim, pi06Sim, pi09Sim], temp);
    }

    const benignProb = probs[0] ?? 0;
    const pi06Prob = probs[1] ?? 0;
    const pi09Prob = probs[2] ?? 0;
    const attackProb = pi06Prob + pi09Prob;

    let bestIdx = 0;
    let confidence = benignProb;
    if (attackProb > benignProb) {
      bestIdx = pi06Prob >= pi09Prob ? 1 : 2;
      confidence = Math.min(1, attackProb);
    }

    return {
      label: LABELS[bestIdx] ?? "BENIGN",
      confidence: Number(confidence.toFixed(4)),
      latencyMs: Number((performance.now() - start).toFixed(3)),
      timedOut: false,
      provider: "onnx-int8",
      ...(similarities ? { similarities } : {}),
    };
  }

  public async dispose(): Promise<void> {
    if (this.session?.release) {
      await this.session.release();
    }
    this.session = null;
  }
}
