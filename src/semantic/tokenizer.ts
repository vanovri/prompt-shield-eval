export const SEMANTIC_FEATURE_DIM = 1024;
export const SEMANTIC_MAX_SEQ_LEN = 256;

const UTF8_ENCODER = new TextEncoder();
const TOKEN_RE = /[\p{L}\p{N}]+/gu;
const CJK_KANA_RE = /[\u3040-\u30FF\u3400-\u4DBF\u4E00-\u9FFF]/u;
const LATIN_DIACRITIC_RE = /[àáâãäåæçèéêëìíîïðñòóôõöøùúûüýÿœß¡¿]/i;
const NON_ASCII_SCRIPT_RE = /[^\x00-\x7F]/;

/**
 * Deterministic 32-bit FNV-1a hash over UTF-8 bytes.
 * Bit-for-bit identical to the Python implementation in scripts/build-semantic-artifacts.py.
 */
export function fnv1a32Utf8(input: string): number {
  const bytes = UTF8_ENCODER.encode(input);
  let hash = 0x811c9dc5;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i]!;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function addHashedFeature(vec: Float32Array, feature: string, weight: number): void {
  const h = fnv1a32Utf8(feature);
  const bucket = (h >>> 1) % vec.length;
  const sign = (h & 1) === 0 ? 1 : -1;
  vec[bucket] = (vec[bucket] ?? 0) + sign * weight;
}

/**
 * Extracts Unicode-aware multilingual tokens (Latin, accented European, Indonesian/regional,
 * and Japanese Hiragana/Katakana/Kanji) capped to maxSeqLen tokens.
 */
export function tokenizeMultilingual(
  text: string,
  maxSeqLen: number = SEMANTIC_MAX_SEQ_LEN
): string[] {
  const normalized = text.normalize("NFKC").toLowerCase();
  const rawMatches = normalized.match(TOKEN_RE) ?? [];
  const tokens: string[] = [];

  for (const tok of rawMatches) {
    if (CJK_KANA_RE.test(tok)) {
      // Split CJK/Japanese runs into overlapping character units + full run for script recall
      const chars = Array.from(tok);
      if (chars.length <= 6) {
        tokens.push(tok);
      }
      for (let i = 0; i < chars.length; i++) {
        tokens.push(chars[i]!);
        if (i + 1 < chars.length) {
          tokens.push(`${chars[i]!}${chars[i + 1]!}`);
        }
        if (tokens.length >= maxSeqLen) return tokens.slice(0, maxSeqLen);
      }
    } else {
      tokens.push(tok);
    }
    if (tokens.length >= maxSeqLen) return tokens.slice(0, maxSeqLen);
  }

  return tokens;
}

/**
 * Converts normalized text into an L2-normalized float32 feature vector of length featureDim.
 * Pure O(N), zero dependencies, bit-for-bit consistent between Node.js and Python.
 */
export function extractSemanticFeatures(
  text: string,
  featureDim: number = SEMANTIC_FEATURE_DIM,
  maxSeqLen: number = SEMANTIC_MAX_SEQ_LEN
): Float32Array {
  const vec = new Float32Array(featureDim);
  const normalized = text.normalize("NFKC").toLowerCase();
  const tokens = tokenizeMultilingual(normalized, maxSeqLen);

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    addHashedFeature(vec, `w:${tok}`, 1.0);

    if (i + 1 < tokens.length) {
      addHashedFeature(vec, `b:${tok}_${tokens[i + 1]!}`, 1.15);
    }

    // Character n-grams for cross-lingual stems & morphology
    const chars = Array.from(tok);
    if (chars.length >= 4 && !CJK_KANA_RE.test(tok)) {
      const padded = `^${tok}$`;
      const pChars = Array.from(padded);
      const limit = Math.min(pChars.length, 24);
      for (let j = 0; j + 3 <= limit; j++) {
        addHashedFeature(vec, `c3:${pChars.slice(j, j + 3).join("")}`, 0.45);
      }
      for (let j = 0; j + 4 <= limit; j++) {
        addHashedFeature(vec, `c4:${pChars.slice(j, j + 4).join("")}`, 0.55);
      }
    }
  }

  // Structural cues
  if (NON_ASCII_SCRIPT_RE.test(normalized)) {
    addHashedFeature(vec, "meta:non_ascii", 0.6);
  }
  if (CJK_KANA_RE.test(normalized)) {
    addHashedFeature(vec, "meta:cjk_kana", 0.9);
  }
  if (LATIN_DIACRITIC_RE.test(normalized)) {
    addHashedFeature(vec, "meta:latin_diacritic", 0.7);
  }
  if (normalized.length > 120) {
    addHashedFeature(vec, "meta:len_gt_120", 0.4);
  }

  let normSq = 0;
  for (let i = 0; i < vec.length; i++) {
    const v = vec[i]!;
    normSq += v * v;
  }
  const denom = Math.sqrt(normSq) + 1e-8;
  for (let i = 0; i < vec.length; i++) {
    vec[i] = vec[i]! / denom;
  }

  return vec;
}
