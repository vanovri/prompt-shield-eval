# Changelog

All notable changes to `prompt-shield-eval` are documented in this file.

## [1.1.0] - 2026-11-20

### Added
- **Modular Zero-Bloat Package Exports (`package.json` `exports`)**:
  - `prompt-shield-eval` (Core): 0 runtime dependencies, L1–L5 deterministic engine + `TaintSessionStore`.
  - `prompt-shield-eval/semantic`: Layer 3.5 Cascade Semantic Classifier (`OnnxInt8SemanticProvider`, `DeterministicMockSemanticProvider`, `evaluatePromptSecurityAsync`, multilingual feature tokenizer) with optional peer `onnxruntime-node`.
  - `prompt-shield-eval/mcp`: MCP Guardrail Middleware (`createMcpGuardrailMiddleware`, `createAegisGuardrailMiddleware`, `createAegisAuditSinkBridge`, `AEGIS_TOOL_POLICIES`, `issueAegisHitlToken`, `verifyAegisHitlToken`) with optional peer `@modelcontextprotocol/sdk`.
- **Bounded Session Taint Store (`src/session-taint.ts`)**: `TaintSessionStore` with configurable `maxSessions` LRU eviction and `ttlMs` expiration (verified under 50,000-session soak test with 0 memory leak).
- **Layer 3.5 ONNX INT8 Semantic Engine**:
  - Real ONNX opset 19 INT8 quantized (`DynamicQuantizeLinear` + `MatMulInteger` + `LpNormalization`) multilingual mini-encoder (`models/semantic-mini-encoder.int8.onnx`), calibrated `models/centroids.v1.json`, and SHA-256 integrity manifest (`models/manifest.v1.json`).
  - Reproducible training/quantization/calibration script (`scripts/build-semantic-artifacts.py`).
  - Selective Cascade Routing (0 ms fast-path short-circuit on L1–L3 `BLOCK` and uncued benign prompts; selective escalation on gray-zone score, framing cues, and multilingual cues; hard 25 ms timeout; explicit `failMode: "QUARANTINE" | "FAIL_OPEN"`).
  - Dual classification mode: Centroid Cosine Similarity (default, updatable without retraining) and 3-class Linear Probe with temperature scaling.
- **Expanded 60-Case Evaluation Dataset (`src/eval-dataset-v11.ts`)**:
  - +14 subtle `PI-06` storytelling/academic/dialogue framing attacks.
  - +10 subtle `PI-09` multilingual attacks (French, Spanish, Japanese, German, Indonesian–English–Javanese/Sundanese code-switching).
  - +10 hard negative benign controls (legit cybersecurity fiction, technical doc translations, MCP JSON payloads).
- **MCP Guardrail Middleware & `aegis-agent` PoC (`src/mcp/`)**:
  - 4 interception points: `beforeToolCall` (L1–L3/L3.5 + L5 allowlist/strict schema/taint/HITL returning `-32602` or `-32001`), `afterToolCall` (taint tracking + L4 128-bit nonce trust-boundary wrapping), `afterModelOutput` (L5 canary + 4-gram leak guard), and `onAuditEvent` (structured audit sink + `createAegisAuditSinkBridge`).
  - Drop-in preset for all 4 `aegis-agent` (HYPERION CH06) tools (`query_ledger_merkle_audit`, `inspect_fraud_subgraph`, `analyze_system_telemetry`, `execute_risk_mitigation`) + runnable `stdio` PoC server (`src/mcp/aegis-stdio-server.ts`).
- **Dual-Mode CLI, Zero-Deps Gate & 3-Job CI Matrix**:
  - CLI flags `--with-semantic`, `--semantic-provider=onnx|mock`, `--semantic-mode=centroid|probe`, and `--suite mcp` with lazy dynamic `import()` so the Core CLI runs in a zero-dependency environment.
  - Static Core isolation checker (`scripts/verify-core-zero-deps.mjs`) plus isolated clean-room `npm pack` tarball smoke test in `ci-core`.
  - GitHub Actions 3-job parallel pipeline: `ci-core`, `ci-semantic-onnx`, and `ci-mcp-adapter`.
  - Strict ESLint 9 flat config (`npm run lint`, `--max-warnings=0`) and `files` whitelist in `package.json`.

### Verified Benchmarks (`v1.1.0`, Node v24.20.0)
- **Vitest:** `5/5` test files, `30/30` tests PASS (Core, Fuzz/Anti-ReDoS, 50k Session Taint Soak, ONNX INT8 + 50k Cascade Soak, MCP InMemory + Subprocess `stdio` + `integer`/`enum` `-32602`).
- **Core Eval (26 cases):** `100.00%` TPR, `0.00%` FPR, `100.00%` Exact Decision Match, warm `p50 = 0.046 ms`, `p99 = 0.690 ms`.
- **Hybrid ONNX INT8 Eval (60 cases):** `100.00%` TPR, `0.00%` FPR, `100.00%` Exact Decision Match, escalation `37/60` (`61.7%`), hybrid warm `p50 = 0.287 ms` / `p99 = 0.876 ms`, ONNX INT8 `p50 = 0.299 ms` / `p99 = 0.762 ms` (`models/semantic-mini-encoder.int8.onnx` `104.2 KB`, SHA-256 `057d4b6895579e7bf2ab15a5fc448843107496df9bf07cc2182d46490d85fa33`).
- **MCP Guardrail Eval (`aegis-agent`):** `20/20` (`100%`) compound hijack blocked (`-32001`), `20/20` legitimate HITL allowed, `20/20` anti-float schema violations rejected (`-32602`), middleware overhead `p50 = 0.217 ms` / `p99 = 0.752 ms`, `121` audit events emitted.

### Changed
- `src/cli-eval.ts` extended with `suite`, `semanticMetrics`, and `mcpMetrics` reporting while preserving backward compatibility for default `npm run eval` (Core 26 cases).

## [1.0.0] - 2026-11-20

### Added
- Initial 5-layer deterministic TypeScript LLM prompt injection defense engine (`normalizer.ts`, `hardened-detector.ts`, `trust-boundary.ts`, `output-tool-gate.ts`).
- 26-case evaluation harness covering all 16 OWASP LLM01 taxonomy IDs (`PI-01`–`PI-14C`) + 6 hard negatives (`TPR 100%`, `FPR 0%`, warm `p99 = 0.620 ms`).
- Seeded 480-case fuzz suite + 10 pathological 20–50 KB anti-ReDoS payloads (`O(N)` comment scanners).
- CLI Markdown/JSON Quality Gate reporter and GitHub Actions CI.
