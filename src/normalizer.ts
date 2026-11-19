import type { NormalizationResult } from "./types.js";

const ZERO_WIDTH_AND_BIDI_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;
const UNICODE_TAG_RE = /[\u{E0000}-\u{E007F}]/gu;

// Lookaround mencegah kegagalan boundary \b pada karakter padding '='
const BASE64_CHUNK_RE = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])/g;
const HEX_CHUNK_RE = /(?<![0-9A-Fa-f])(?:0x)?(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])/g;
const URL_PERCENT_TOKEN_RE = /%[0-9A-Fa-f]{2}/g;
const URL_PERCENT_RUN_RE = /(?:%[0-9A-Fa-f]{2})+/g;
const TECHNICAL_ALNUM_RE =
  /^(?:q[1-4]|v\d+|p(?:50|90|95|99)|base64|base32|utf8|utf16|sha256|sha512|md5|ipv4|ipv6|http2|http3|es2022|oauth2|x64|x86)$/;
const MAX_DECODE_CHUNK_LEN = 4096;
const MAX_DECODE_PAYLOADS = 16;

const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic confusables
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p", "\u0441": "c",
  "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u043A": "k",
  "\u043C": "m", "\u043D": "h", "\u0442": "t", "\u0432": "b",
  "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041A": "K", "\u041C": "M",
  "\u041D": "H", "\u041E": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
  "\u0425": "X", "\u0406": "I", "\u0408": "J",
  // Greek confusables
  "\u03B1": "a", "\u03B2": "b", "\u03B5": "e", "\u03B9": "i", "\u03BA": "k",
  "\u03BD": "v", "\u03BF": "o", "\u03C1": "p", "\u03C4": "t", "\u03C5": "u",
  "\u03C7": "x", "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
  "\u0397": "H", "\u0399": "I", "\u039A": "K", "\u039C": "M", "\u039D": "N",
  "\u039F": "O", "\u03A1": "P", "\u03A4": "T", "\u03A5": "Y", "\u03A7": "X",
};

const UNAMBIGUOUS_LEET: Record<string, string> = {
  "0": "o",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  "$": "s",
};

// Kamus stem untuk disambiguasi angka '1' -> 'i' vs 'l' per token (mis. 1gn0r3 vs ru13s)
const ONE_AS_L_WORDS = new Set([
  "all", "rule", "rules", "leak", "call", "kill", "illegal", "jailbreak",
  "tell", "only", "global", "control", "developer", "lead", "literal",
  "eval", "tool", "file", "shell", "policy", "reveal", "steal", "lawless",
  "berlaku", "keluarkan", "lupakan", "ulangi", "seluruh", "panggil",
]);

const ONE_AS_I_WORDS = new Set([
  "ignore", "previous", "prior", "instructions", "instruction", "system",
  "sistem", "rahasia", "instruksi", "pirated", "kill", "print", "bypass",
  "admin", "internal", "hidden", "override", "script", "filter", "evil",
  "hijack", "api", "canary", "perintah", "kebalikan", "diam",
]);

function isPrintableUtf8(text: string): boolean {
  if (text.length < 8 || text.includes("\uFFFD")) return false;
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code >= 0x20 && code <= 0x7e) || code === 0x09 || code === 0x0a || code === 0x0d) {
      printable++;
    }
  }
  return printable / text.length >= 0.9;
}

function decodeUnicodeTags(text: string): { decoded: string | null; count: number } {
  const tags = text.match(UNICODE_TAG_RE);
  if (!tags || tags.length === 0) return { decoded: null, count: 0 };

  let out = "";
  for (const ch of tags) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && cp >= 0xe0020 && cp <= 0xe007e) {
      out += String.fromCharCode(cp - 0xe0000);
    }
  }
  return { decoded: out.length >= 6 ? out : null, count: tags.length };
}

interface SingleStepDecodeResult {
  decoded: string[];
  matchedEncodedSpans: string[];
  hasUrlEncodedDecode: boolean;
}

function extractSingleStepDecodes(text: string): SingleStepDecodeResult {
  const decoded: string[] = [];
  const matchedEncodedSpans: string[] = [];
  let hasUrlEncodedDecode = false;

  // 1. URL percent-encoding (tangkap baik blok beruntun maupun kalimat dengan >=3 %XX seperti %20)
  const percentTokens = text.match(URL_PERCENT_TOKEN_RE);
  if (percentTokens && percentTokens.length >= 3) {
    const urlDecoded = text.replace(URL_PERCENT_RUN_RE, (seg) => {
      if (seg.length > MAX_DECODE_CHUNK_LEN) return seg;
      try {
        return decodeURIComponent(seg);
      } catch {
        return seg;
      }
    });
    if (urlDecoded !== text && isPrintableUtf8(urlDecoded)) {
      decoded.push(urlDecoded);
      hasUrlEncodedDecode = true;
    }
  }

  // 2. Base64
  const b64Matches = text.match(BASE64_CHUNK_RE) ?? [];
  for (const chunk of b64Matches.slice(0, 6)) {
    if (chunk.length > MAX_DECODE_CHUNK_LEN || chunk.length % 4 === 1) continue;
    const padded = chunk.padEnd(chunk.length + ((4 - (chunk.length % 4)) % 4), "=");
    try {
      const candidate = Buffer.from(padded, "base64").toString("utf8");
      if (candidate !== chunk && isPrintableUtf8(candidate)) {
        decoded.push(candidate);
        matchedEncodedSpans.push(chunk);
      }
    } catch {
      // Abaikan Base64 tidak valid
    }
  }

  // 3. Hex
  const hexMatches = text.match(HEX_CHUNK_RE) ?? [];
  for (const rawHex of hexMatches.slice(0, 6)) {
    if (rawHex.length > MAX_DECODE_CHUNK_LEN) continue;
    const cleanHex = rawHex.startsWith("0x") || rawHex.startsWith("0X") ? rawHex.slice(2) : rawHex;
    if (cleanHex.length % 2 !== 0) continue;
    try {
      const candidate = Buffer.from(cleanHex, "hex").toString("utf8");
      if (candidate !== rawHex && isPrintableUtf8(candidate)) {
        decoded.push(candidate);
        matchedEncodedSpans.push(rawHex);
      }
    } catch {
      // Abaikan Hex tidak valid
    }
  }

  return { decoded, matchedEncodedSpans, hasUrlEncodedDecode };
}

function normalizeHomoglyphs(text: string): { normalized: string; count: number } {
  let count = 0;
  let out = "";
  for (const ch of text) {
    const mapped = HOMOGLYPH_MAP[ch];
    if (mapped) {
      out += mapped;
      count++;
    } else {
      out += ch;
    }
  }
  return { normalized: out, count };
}

function normalizeLeetspeak(text: string): { normalized: string; substitutions: number } {
  let substitutions = 0;
  const lower = text.toLowerCase();

  const normalized = lower.replace(/[a-z0-9@$]+/g, (token) => {
    // Jangan ubah angka murni (mis. "2026", "12"), ID pendek ("q3", "v2"), atau istilah teknis ("base64")
    if (/^\d+$/.test(token)) return token;
    if (!/[a-z]/.test(token)) return token;
    if (TECHNICAL_ALNUM_RE.test(token)) return token;

    let step1 = "";
    for (const ch of token) {
      const mapped = UNAMBIGUOUS_LEET[ch];
      if (mapped) {
        step1 += mapped;
        substitutions++;
      } else {
        step1 += ch;
      }
    }

    if (!step1.includes("1")) return step1;

    const asI = step1.replace(/1/g, "i");
    const asL = step1.replace(/1/g, "l");
    const oneCount = (step1.match(/1/g) ?? []).length;

    if (ONE_AS_I_WORDS.has(asI)) {
      substitutions += oneCount;
      return asI;
    }
    if (ONE_AS_L_WORDS.has(asL)) {
      substitutions += oneCount;
      return asL;
    }

    // Heuristik posisi: '1' setelah u/o sebelum e/s/l/akhir atau setelah a sebelum e/s/l cenderung 'l' (ru1es -> rules, a1l -> all), sedangkan 'a1$' cenderung 'ai' (n1la1 -> nilai)
    substitutions += oneCount;
    return step1
      .replace(/([uo])1(?=[esl]|$)/g, "$1l")
      .replace(/a1(?=[esl])/g, "al")
      .replace(/1/g, "i");
  });

  return { normalized: normalized.replace(/\s+/g, " ").trim(), substitutions };
}

export function canonicalizeInput(raw: string, maxDepth = 2): NormalizationResult {
  const nfkc = raw.normalize("NFKC");

  const zwMatches = nfkc.match(ZERO_WIDTH_AND_BIDI_RE);
  const tagResult = decodeUnicodeTags(nfkc);
  const hiddenCharCount = (zwMatches?.length ?? 0) + tagResult.count;

  const strippedInvisible = nfkc
    .replace(ZERO_WIDTH_AND_BIDI_RE, "")
    .replace(UNICODE_TAG_RE, "");

  const { normalized: homoglyphNormalized, count: homoglyphCount } =
    normalizeHomoglyphs(strippedInvisible);

  // BFS dekode rekursif hingga maxDepth = 2 (URL -> Base64, Base64 -> Hex, dst.)
  const decodedPayloads: string[] = [];
  const topLevelEncodedSpans = new Set<string>();
  let topLevelHasUrlDecode = false;
  const seen = new Set<string>([strippedInvisible]);
  const queue: Array<{ text: string; depth: number }> = [];
  let maxDecodeDepth = 0;

  if (tagResult.decoded) {
    decodedPayloads.push(tagResult.decoded);
    seen.add(tagResult.decoded);
    queue.push({ text: tagResult.decoded, depth: 1 });
    maxDecodeDepth = 1;
  }

  queue.push({ text: strippedInvisible, depth: 0 });

  while (queue.length > 0 && decodedPayloads.length < MAX_DECODE_PAYLOADS) {
    const current = queue.shift()!;
    if (current.depth >= maxDepth) continue;

    const { decoded, matchedEncodedSpans, hasUrlEncodedDecode } = extractSingleStepDecodes(current.text);
    if (current.depth === 0) {
      if (hasUrlEncodedDecode) topLevelHasUrlDecode = true;
      for (const span of matchedEncodedSpans) {
        topLevelEncodedSpans.add(span);
      }
    }

    for (const candidate of decoded) {
      if (decodedPayloads.length >= MAX_DECODE_PAYLOADS) break;
      if (seen.has(candidate)) continue;
      seen.add(candidate);
      const nextDepth = current.depth + 1;
      maxDecodeDepth = Math.max(maxDecodeDepth, nextDepth);
      decodedPayloads.push(candidate);
      queue.push({ text: candidate, depth: nextDepth });
    }
  }

  // Masking blok encoded valid agar digit di dalam Base64/Hex/URL tidak salah dihitung sebagai leetspeak
  let leetSource = homoglyphNormalized;
  if (topLevelHasUrlDecode) {
    leetSource = leetSource.replace(URL_PERCENT_RUN_RE, " ");
  }
  for (const span of topLevelEncodedSpans) {
    leetSource = leetSource.replaceAll(span, " ");
  }
  const { normalized: leetNormalized, substitutions: leetSubstitutions } =
    normalizeLeetspeak(leetSource);

  return {
    raw,
    strippedInvisible,
    homoglyphNormalized,
    leetNormalized,
    decodedPayloads,
    signals: {
      hiddenCharCount,
      unicodeTagCount: tagResult.count,
      homoglyphCount,
      leetSubstitutions,
      maxDecodeDepth,
    },
  };
}
