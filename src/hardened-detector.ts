import { canonicalizeInput } from "./normalizer.js";
import type { Decision, DetectorResult, SourceChannel } from "./types.js";

interface RuleSpec {
  id: string;
  weight: number;
  pattern: RegExp;
}

const RULES: RuleSpec[] = [
  {
    id: "PI-01-direct-override",
    weight: 55,
    pattern:
      /\b(?:(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+)?(?:(?:previous|prior|above|earlier|original|system)\s+)?(?:instructions?|rules?|directives?|prompts?|guidelines?|constraints?)|(?:abaikan|lupakan|hiraukan|kesampingkan)\s+(?:semua\s+|seluruh\s+|segala\s+)?(?:(?:instruksi|aturan|perintah|pedoman|prompt)\s+(?:sebelumnya|di\s+atas|sistem|awal)|(?:sebelumnya|di\s+atas)\s+(?:instruksi|aturan|perintah)))\b/i,
  },
  {
    id: "PI-02-prompt-leak",
    weight: 55,
    pattern:
      /\b(?:(?:repeat|reveal|show|print|output|dump|leak|expose|disclose|echo|display)\b.{0,50}\b(?:system\s+prompt|developer\s+(?:prompt|message|instructions?)|internal\s+(?:rules?|instructions?|policy)|hidden\s+instructions?|canary(?:_[a-z0-9]+)*)|(?:ulangi|tampilkan|ungkapkan|keluarkan|sebutkan|salin|(?:men)?cetak)\b.{0,55}\b(?:aturan\s+sistem|instruksi\s+sistem|system\s+prompt|pesan\s+developer|kode\s+rahasia\s+sistem|rahasia\s+sistem|nilai\s+canary|canary(?:_[a-z0-9]+)*))\b/i,
  },
  {
    id: "PI-03-jailbreak",
    weight: 55,
    pattern:
      /\b(?:jailbreak\s+mode|unrestricted\s+(?:access|mode)|developer\s+mode\s+(?:enabled|on|aktif)|god\s+mode|no\s+ethical\s+(?:bounds|limits|guardrails)|disable\s+(?:all\s+)?(?:safety|security|policy)\s+(?:filters?|guardrails?|protocols?|checks?)|mode\s+(?:tanpa\s+batasan|bebas\s+aturan|unrestricted)|nonaktifkan\s+(?:semua\s+)?(?:filter|guardrail|protokol|validator)\s+(?:keamanan|etika|policy)|lewati\s+semua\s+(?:batasan|filter)\s+keamanan)\b/i,
  },
  {
    id: "PI-04-authority",
    weight: 35,
    pattern:
      /(?:\[\s*(?:system\s+admin|admin\s+override|root\s+command|developer\s+override)\b|\b(?:i\s+am\s+(?:your\s+)?(?:lead\s+developer|system\s+admin|administrator|creator|root\s+engineer)|saya\s+(?:adalah\s+)?(?:lead\s+developer|lead\s+engineer|admin\s+sistem|administrator\s+utama|pemilik\s+sistem)|authorized\s+admin\s+override|otorisasi\s+admin\s+darurat)\b)/i,
  },
  {
    id: "PI-05-rule-changing",
    weight: 55,
    pattern:
      /\b(?:(?:from\s+now\s+on|starting\s+now)\s*,?\s*(?:you\s+are\s+(?:a\s+)?(?:lawless|unfiltered|unrestricted|unbound)|old\s+rules?\s+(?:do\s+not|don't|no\s+longer)\s+exist)|(?:old|previous)\s+rules?\s+(?:no\s+longer\s+apply|are\s+void|do\s+not\s+exist)|(?:mulai\s+sekarang|sejak\s+detik\s+ini)\s*,?\s*(?:aturan\s+lama\s+tidak\s+berlaku|kamu\s+adalah\s+terminal\s+(?:tanpa\s+hukum|bebas\s+aturan)|semua\s+batasan\s+dihapus))\b/i,
  },
  {
    id: "PI-06-roleplay-framing",
    weight: 50,
    pattern:
      /\b(?:(?:for\s+a\s+(?:movie\s+script|novel|fictional\s+story)|in\s+a\s+fictional\s+world|write\s+a\s+story\s+where)\b.{0,80}\b(?:explains?\s+exact(?:ly)?|step[- ]by[- ]step\s+(?:instructions?|guide)|how\s+to\s+(?:bypass|exploit|exfiltrate|leak|craft\s+malware|hack)|prints?\s+the\s+secret\s+canary)|(?:untuk\s+(?:naskah\s+film|cerita\s+fiksi|novel)|dalam\s+dunia\s+fiksi|tulis\s+cerita\s+di\s+mana)\b.{0,80}\b(?:menjelaskan\s+langkah\s+eksak|cara\s+eksploitasi|cara\s+membobol|membocorkan\s+(?:canary|kredensial|system\s+prompt)))\b/i,
  },
  {
    id: "PI-07-dual-persona",
    weight: 55,
    pattern:
      /\b(?:do\s+anything\s+now|dan\s+mode|persona\s+dan|(?:respond|answer|jawab)\s+(?:as|sebagai)\s+(?:two|dua)\s+(?:entities|personas|entitas|persona)|(?:safe_ai|good\s+ai).{0,40}(?:free_ai|bad\s+ai|evil\s+ai|unrestricted_ai))\b/i,
  },
  {
    id: "PI-08-opposite-mode",
    weight: 55,
    pattern:
      /\b(?:(?:enter|aktifkan|masuk\s+ke)\s+['"`]?(?:antigpt|opposite\s+mode|mode\s+kebalikan|evilgpt|reverse\s+mode)['"`]?|(?:opposite\s+mode|mode\s+kebalikan)\b.{0,50}\b(?:reverse|kebalikan|berbahaya|dangerous|opposite\s+of\s+helpful)|(?:give|berikan)\s+(?:the\s+most\s+dangerous|saran\s+paling\s+berbahaya))\b/i,
  },
  {
    id: "PI-09-translation-trick",
    weight: 50,
    pattern:
      /\b(?:(?:translate|terjemahkan)\b.{0,85}\b(?:ignore\s+(?:all\s+)?rules|system\s+prompt|canary|bypass\s+security|exploit|membobol|senjata|weapon)\b.{0,75}\b(?:and\s+(?:give|answer|execute|respond)|lalu\s+(?:jawab|berikan\s+jawaban|jalankan))|(?:answer|jawab|execute|jalankan)\s+(?:the\s+following\s+)?(?:in|dalam\s+bahasa)\s+(?:french|spanish|german|japanese|russian|latin|prancis|spanyol|jerman|jepang)\b.{0,60}\b(?:ignore|bypass|canary|system\s+prompt|exploit))\b/i,
  },
  {
    id: "PI-10-spellcheck-exploit",
    weight: 35,
    pattern:
      /\b(?:fix\s+(?:the\s+)?typos?|spell[- ]?check|perbaiki\s+(?:typo|ejaan|tata\s+bahasa)|koreksi\s+kalimat)\b.{0,70}\b(?:kill|hate|exploit|bypass|ignore\s+rules|steal\s+credentials|bunuh|benci\s+semua|bobol|serang|canary)\b/i,
  },
  {
    id: "PI-11-repetition-exploit",
    weight: 50,
    pattern:
      /\b(?:(?:repeat|echo|ulangi|salin)\b.{0,55}(?:(?:word\s+for\s+word|verbatim|kata\s+demi\s+kata|tanpa\s+(?:sensor|menyensor)).{0,55}\b(?:rant|toxic|override|canary|system\s+prompt|instruksi|ujaran\s+kebencian)|(?:rant|toxic|override|canary|system\s+prompt|ujaran\s+kebencian).{0,55}\b(?:word\s+for\s+word|verbatim|kata\s+demi\s+kata|tanpa\s+(?:sensor|menyensor)))|(?:summarize|ringkas)\s+(?:and\s+execute|dan\s+jalankan))\b/i,
  },
  {
    id: "PI-14A-reassemble-directive",
    weight: 50,
    pattern:
      /\b(?:combine|gabungkan|concatenate)\b.{0,45}\b(?:fragments?|fragmen|message\s+\d|pesan\s+\d)\b.{0,50}\b(?:execute|run|jalankan|perintah|instruction)\b/i,
  },
  {
    id: "PI-14B-indirect-injection",
    weight: 40,
    pattern:
      /\b(?:ignore\s+the\s+user|abaikan\s+(?:pengguna|ringkasan)\b.{0,45}\b(?:panggil\s+tool|call\s+tool|kirim\s+data|tell\s+them))\b/i,
  },
  {
    id: "PI-14C-ide-repo-injection",
    weight: 40,
    pattern:
      /(?:(?:\/\/|#|\/\*)\s*(?:ai(?:\s+assistant)?|assistant|copilot|cursor|llm|agent|system)\s*[:\-].{0,95}\b(?:backdoor|secretly\s+add|diam-diam\s+tambahkan|exfiltrate|kirim\s+\.env|disable\s+auth|bypass\s+auth|ignore\s+security)\b|\b(?:whenever\s+you\s+write\s+new\s+code|setiap\s+kali\s+menulis\s+kode).{0,80}\b(?:backdoor|secret\s+login|exfiltrate|kirim\s+token)\b)/i,
  },
];

const HIDDEN_COMMENT_DIRECTIVE_RE =
  /(?:\b(?:ignore|abaikan|call\s+tool|panggil\s+tool|override|exfiltrate|transfer|canary)\b|\bexecute_[a-z0-9_]+)/i;

// Ekstraksi O(N) isi komentar HTML (<!-- ... -->) dan Markdown ([//]: # (...)) tanpa regex backtracking
function hasSuspiciousHiddenComment(text: string): boolean {
  if (text.includes("<!--") && text.includes("-->")) {
    let cursor = 0;
    while (cursor < text.length) {
      const start = text.indexOf("<!--", cursor);
      if (start === -1) break;
      const end = text.indexOf("-->", start + 4);
      if (end === -1) break;
      if (HIDDEN_COMMENT_DIRECTIVE_RE.test(text.slice(start + 4, end))) return true;
      cursor = end + 3;
    }
  }

  if (text.includes("[//]:") && text.includes(")")) {
    let cursor = 0;
    while (cursor < text.length) {
      const start = text.indexOf("[//]:", cursor);
      if (start === -1) break;
      let idx = start + 5;
      while (idx < text.length && (text[idx] === " " || text[idx] === "\t")) idx++;
      if (text[idx] !== "#") {
        cursor = start + 5;
        continue;
      }
      idx++;
      while (idx < text.length && (text[idx] === " " || text[idx] === "\t")) idx++;
      if (text[idx] !== "(") {
        cursor = idx;
        continue;
      }
      const closeIdx = text.indexOf(")", idx + 1);
      if (closeIdx === -1) break;
      if (HIDDEN_COMMENT_DIRECTIVE_RE.test(text.slice(idx + 1, closeIdx))) return true;
      cursor = closeIdx + 1;
    }
  }

  return false;
}

function extractQuotedFragments(turns: string[]): string {
  const fragments: string[] = [];
  const quoteRe = /['"]([^'"]{3,120})['"]/g;
  for (const turn of turns) {
    for (const match of turn.matchAll(quoteRe)) {
      if (match[1]) fragments.push(match[1].trim());
      if (fragments.length >= 24) return fragments.join(" ");
    }
  }
  return fragments.join(" ");
}

export function evaluatePromptSecurity(
  history: string[],
  sourceChannel: SourceChannel = "user"
): DetectorResult {
  // Lapis 2: Sliding window 5 pesan terakhir untuk deteksi payload splitting (PI-14A)
  const recentTurns = history.slice(-5);
  const windowText = recentTurns.join("\n");
  const joinedFragments = recentTurns.length > 1 ? extractQuotedFragments(recentTurns) : "";

  const norm = canonicalizeInput(windowText, 2);
  const fragmentNorm = joinedFragments ? canonicalizeInput(joinedFragments, 2) : null;

  const scanTargets = new Set<string>([
    norm.strippedInvisible,
    norm.homoglyphNormalized,
    norm.leetNormalized,
    ...norm.decodedPayloads,
  ]);

  let innerHasObfuscation = false;

  // Normalisasi ulang payload hasil dekode (menangkap Base64 berisi leetspeak/homoglyph)
  for (const decoded of norm.decodedPayloads) {
    const innerNorm = canonicalizeInput(decoded, 1);
    scanTargets.add(innerNorm.homoglyphNormalized);
    scanTargets.add(innerNorm.leetNormalized);
    if (
      innerNorm.signals.homoglyphCount >= 2 ||
      innerNorm.signals.hiddenCharCount >= 2 ||
      innerNorm.signals.leetSubstitutions >= 3
    ) {
      innerHasObfuscation = true;
    }
  }

  if (fragmentNorm) {
    scanTargets.add(fragmentNorm.homoglyphNormalized);
    scanTargets.add(fragmentNorm.leetNormalized);
  }

  const matchedRules = new Set<string>();
  let score = 0;

  for (const target of scanTargets) {
    if (!target) continue;
    if (!matchedRules.has("PI-14B-indirect-injection") && hasSuspiciousHiddenComment(target)) {
      matchedRules.add("PI-14B-indirect-injection");
      score += 40;
    }
    for (const rule of RULES) {
      if (!matchedRules.has(rule.id) && rule.pattern.test(target)) {
        matchedRules.add(rule.id);
        score += rule.weight;
      }
    }
  }

  // Lapis 3: Skor korelasi untuk obfuscation & encoding (PI-12 & PI-13)
  if (norm.decodedPayloads.length > 0 && score >= 35) {
    matchedRules.add("PI-12-encoded-injection");
    score += 25;
  }

  const hasObfuscationSignal =
    norm.signals.homoglyphCount >= 2 ||
    norm.signals.hiddenCharCount >= 2 ||
    norm.signals.leetSubstitutions >= 3 ||
    innerHasObfuscation;

  if (hasObfuscationSignal && score >= 35) {
    matchedRules.add("PI-13-evasion-obfuscation");
    score += 20;
  }

  // Penentuan keputusan berbasis trust level channel
  let decision: Decision = "ALLOW";
  if (sourceChannel === "user") {
    if (score >= 50) decision = "BLOCK";
    else if (score >= 30) decision = "QUARANTINE";
  } else {
    // Dokumen eksternal / file repo dikarantina agar orkestrator bisa membuang payload tanpa memutus sesi user
    if (score >= 25) decision = "QUARANTINE";
  }

  return {
    decision,
    score: Math.min(100, score),
    matchedRules: Array.from(matchedRules),
    normalizedText: norm.leetNormalized,
    signals: norm.signals,
  };
}

export function warmupDetector(): void {
  evaluatePromptSecurity(["warmup baseline check"], "user");
  evaluatePromptSecurity(["\u0406gn\u043Er\u0435 warmup SGVsbG8gV29ybGQgMjAyNg=="], "user");
}
