import type { DetectorResult } from "../types.js";

export type SemanticLabel =
  | "BENIGN"
  | "PI06_ROLEPLAY_BYPASS"
  | "PI09_CROSS_LANG_INJECTION";

export interface SemanticPrediction {
  label: SemanticLabel;
  /** Calibrated probability in [0.0, 1.0]. */
  confidence: number;
  latencyMs: number;
  timedOut: boolean;
  provider: "onnx-int8" | "mock-deterministic";
  /** Optional cosine similarity diagnostics for auditability. */
  similarities?: Record<SemanticLabel, number>;
}

export interface SemanticProvider {
  readonly name: string;
  warmup(): Promise<void>;
  classify(normalizedText: string, signal?: AbortSignal): Promise<SemanticPrediction>;
  dispose(): Promise<void>;
}

export interface CascadeDetectorOptions {
  semanticProvider?: SemanticProvider;
  /** Minimum L1-L3 score that enters the gray zone (default: 15). */
  grayZoneMinScore?: number;
  /** Hard timeout in ms for L3.5 semantic inference (default: 25). */
  semanticTimeoutMs?: number;
  /** Confidence threshold for BLOCK on user channel (default: 0.85). */
  semanticBlockThreshold?: number;
  /** Confidence threshold for QUARANTINE (default: 0.65). */
  semanticQuarantineThreshold?: number;
  /** Failure strategy on timeout or inference error (default: "QUARANTINE"). */
  failMode?: "QUARANTINE" | "FAIL_OPEN";
}

export interface CascadeDetectorResult extends DetectorResult {
  semanticEscalated: boolean;
  escalationReasons: string[];
  semanticPrediction?: SemanticPrediction;
  semanticFailOpen: boolean;
}

export interface CentroidsArtifact {
  version: string;
  embeddingDim: number;
  featureDim: number;
  maxSeqLen: number;
  temperature: number;
  centroids: Record<SemanticLabel, number[]>;
  benignAnchors?: Record<string, number[]>;
  modelSha256: string;
  createdAtIso: string;
}

export interface SemanticModelManifest {
  version: string;
  modelFile: string;
  modelSha256: string;
  centroidsFile: string;
  centroidsSha256: string;
  architecture: "mini-hash-int8" | "transformer-int8";
  quantization: "INT8";
  featureDim: number;
  embeddingDim: number;
  maxSeqLen: number;
}
