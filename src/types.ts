export type Decision = "ALLOW" | "QUARANTINE" | "BLOCK";

export type SourceChannel = "user" | "untrusted_document" | "repo_file";

export type TaxonomyId =
  | "PI-01"
  | "PI-02"
  | "PI-03"
  | "PI-04"
  | "PI-05"
  | "PI-06"
  | "PI-07"
  | "PI-08"
  | "PI-09"
  | "PI-10"
  | "PI-11"
  | "PI-12"
  | "PI-13"
  | "PI-14A"
  | "PI-14B"
  | "PI-14C"
  | "BENIGN";

export interface NormalizationResult {
  raw: string;
  strippedInvisible: string;
  homoglyphNormalized: string;
  leetNormalized: string;
  decodedPayloads: string[];
  signals: {
    hiddenCharCount: number;
    unicodeTagCount: number;
    homoglyphCount: number;
    leetSubstitutions: number;
    maxDecodeDepth: number;
  };
}

export interface DetectorResult {
  decision: Decision;
  score: number;
  matchedRules: string[];
  normalizedText: string;
  signals: NormalizationResult["signals"];
}

export interface EvalCase {
  id: string;
  taxonomyId: TaxonomyId;
  category: string;
  expectedDecision: Decision;
  sourceChannel?: SourceChannel;
  turns: string[];
}

export interface EvalFailure {
  id: string;
  taxonomyId: TaxonomyId;
  kind: "MISSED_ATTACK" | "FALSE_POSITIVE" | "DECISION_MISMATCH";
  expected: Decision;
  actual: Decision;
  score: number;
  matchedRules: string[];
}

export interface EvalReport {
  totalCases: number;
  attackCases: number;
  benignCases: number;
  tpr: number;
  fpr: number;
  bypassRate: number;
  exactMatchRate: number;
  p50LatencyMs: number;
  p99LatencyMs: number;
  failures: EvalFailure[];
}
