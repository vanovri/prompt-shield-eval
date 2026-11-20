import { builtinModules } from "node:module";
import fs from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const DIST_DIR = path.join(ROOT, "dist");
const PKG_PATH = path.join(ROOT, "package.json");

const BUILTIN_SET = new Set([
  ...builtinModules,
  ...builtinModules.map((m) => (m.startsWith("node:") ? m.slice(5) : `node:${m}`)),
]);

const BANNED_OPTIONAL_PREFIXES = [
  "onnxruntime-node",
  "@modelcontextprotocol/",
  "zod",
];

function fail(msg) {
  console.error(`[ZERO-DEPS GATE FAIL] ${msg}`);
  process.exit(1);
}

// 1. Verify package.json: Core must have 0 runtime dependencies & publish dist/
const pkg = JSON.parse(fs.readFileSync(PKG_PATH, "utf8"));
const runtimeDeps = Object.keys(pkg.dependencies ?? {});
if (runtimeDeps.length > 0) {
  fail(
    `package.json has runtime dependencies: [${runtimeDeps.join(", ")}]. ` +
      `Move optional packages to peerDependencies (optional: true) + devDependencies.`
  );
}

if (!Array.isArray(pkg.files) || !pkg.files.includes("dist")) {
  fail(`package.json "files" must include "dist" so npm pack ships compiled ESM + types.`);
}

// 2. Verify all 3 subpath exports (., ./semantic, ./mcp) resolve to built files
for (const subpath of [".", "./semantic", "./mcp"]) {
  const entry = pkg.exports?.[subpath];
  if (!entry || !entry.import || !entry.types) {
    fail(`package.json exports["${subpath}"] must define both "import" and "types".`);
  }
  for (const field of ["import", "types"]) {
    const resolved = path.join(ROOT, entry[field]);
    if (!fs.existsSync(resolved)) {
      fail(`Export target "${subpath}".${field} does not exist: ${entry[field]}`);
    }
  }
}

if (!fs.existsSync(DIST_DIR)) {
  fail("dist/ directory not found. Run `npm run build` first.");
}

function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1");
}

const STATIC_IMPORT_PATTERNS = [
  /\b(?:import|export)\s+(?:type\s+)?[\s\S]*?\bfrom\s*["']([^"']+)["']/g,
  /\bimport\s*["']([^"']+)["']/g,
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g,
];

const DYNAMIC_IMPORT_PATTERN = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;

function extractSpecifiers(code, includeDynamic) {
  const specs = [];
  const patterns = includeDynamic
    ? [...STATIC_IMPORT_PATTERNS, DYNAMIC_IMPORT_PATTERN]
    : STATIC_IMPORT_PATTERNS;

  for (const regex of patterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(code)) !== null) {
      specs.push(match[1].trim());
    }
  }
  return specs;
}

function resolveDistFile(fromFile, spec, isDts) {
  let target = path.resolve(path.dirname(fromFile), spec);
  if (isDts && target.endsWith(".js")) {
    const dtsCandidate = target.slice(0, -3) + ".d.ts";
    if (fs.existsSync(dtsCandidate)) return dtsCandidate;
  }
  if (fs.existsSync(target) && fs.statSync(target).isFile()) return target;
  for (const ext of isDts ? [".d.ts", ".js"] : [".js", ".d.ts"]) {
    if (fs.existsSync(target + ext)) return target + ext;
  }
  return target;
}

function isOptionalSubpath(targetPath) {
  const rel = path.relative(DIST_DIR, targetPath).replaceAll("\\", "/");
  return (
    rel === "semantic" ||
    rel.startsWith("semantic/") ||
    rel === "mcp" ||
    rel.startsWith("mcp/")
  );
}

const violations = [];
const visitedCoreFiles = new Set();

// 3. Walk the full transitive import graph of Core entrypoints (dist/index.js & dist/index.d.ts)
function auditCoreGraph(entryPath, isDts) {
  const normalized = path.resolve(entryPath);
  if (visitedCoreFiles.has(normalized)) return;
  if (!fs.existsSync(normalized)) {
    violations.push(`Missing core module in build graph: ${path.relative(ROOT, normalized)}`);
    return;
  }
  visitedCoreFiles.add(normalized);

  const rel = path.relative(ROOT, normalized).replaceAll("\\", "/");
  const code = stripComments(fs.readFileSync(normalized, "utf8"));
  const specs = extractSpecifiers(code, true);

  for (const spec of specs) {
    const isRelative = spec.startsWith("./") || spec.startsWith("../");
    if (isRelative) {
      const target = resolveDistFile(normalized, spec, isDts);
      if (isOptionalSubpath(target)) {
        violations.push(`${rel} imports optional subpath via relative path: "${spec}"`);
        continue;
      }
      auditCoreGraph(target, isDts);
      continue;
    }

    if (BUILTIN_SET.has(spec)) {
      continue;
    }

    const isBanned = BANNED_OPTIONAL_PREFIXES.some((p) => spec === p || spec.startsWith(p));
    violations.push(
      `${rel} imports external dependency${isBanned ? " (forbidden in Core)" : ""}: "${spec}"`
    );
  }
}

auditCoreGraph(path.join(ROOT, pkg.exports["."].import), false);
auditCoreGraph(path.join(ROOT, pkg.exports["."].types), true);

// 4. Verify CLI runner (dist/cli-eval.js) has ZERO static external or optional subpath imports
//    (optional ./semantic and ./mcp must only be loaded lazily via dynamic import())
const cliJs = path.join(DIST_DIR, "cli-eval.js");
if (!fs.existsSync(cliJs)) {
  fail("dist/cli-eval.js not found.");
}
const cliStaticSpecs = extractSpecifiers(stripComments(fs.readFileSync(cliJs, "utf8")), false);
for (const spec of cliStaticSpecs) {
  const isRelative = spec.startsWith("./") || spec.startsWith("../");
  if (isRelative) {
    const target = resolveDistFile(cliJs, spec, false);
    if (isOptionalSubpath(target)) {
      violations.push(
        `dist/cli-eval.js statically imports optional module "${spec}" (must use lazy dynamic import())`
      );
    }
    continue;
  }
  if (!BUILTIN_SET.has(spec)) {
    violations.push(`dist/cli-eval.js statically imports external dependency "${spec}"`);
  }
}

if (violations.length > 0) {
  fail(`Found ${violations.length} Core isolation violation(s):\n  - ${violations.join("\n  - ")}`);
}

console.log(
  `[ZERO-DEPS GATE PASS] 0 runtime dependencies in package.json; ` +
    `"files" includes "dist"; ${visitedCoreFiles.size} Core build artifacts verified free of external deps & semantic/mcp leakage; ` +
    `dist/cli-eval.js uses lazy dynamic imports only.`
);
