// Core scanner: runs crypto and secret rules over file contents.

import { ALGORITHMS, CRYPTO_RULES, langFor } from "./rules.ts";
import { scanInfra } from "./infra.ts";
import { findSecrets, mask } from "./secrets.ts";
import { findPqc, type PqcSignal } from "./pqc.ts";
import { findInventory, type InventoryItem } from "./inventory.ts";
import { communityRulesFor } from "./community.ts";
import type { Finding, ScanResult } from "./types.ts";

const MAX_LINE = 2000;
const TYPES_FILE = /\.d\.[cm]?ts$/;
// A line that is only a comment: //, /*, a * continuation, or # (not a shebang, Rust attribute or C preprocessor line).
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*(?:\s|\/|$)|#(?![!\[]|include|define|if|else|endif|pragma|import|undef|error))/;
const DOC_FILE = /\.(md|mdx|rst|txt|html?|adoc)$/i;
// Test code is full of throwaway keys and passwords, including fakes in real token formats, so no secret counts there.
export const TEST_PATH = /(^|\/)(tests?|__tests__|__snapshots__|testdata|test-data|testing|test[-_]?(?:utils?|helpers?|support|env|suite|fixtures?)|e2e[-_][a-z0-9_-]+|[a-z0-9_-]+[-_]tests?|(?!(?:la|con|at|pro|de)test\/)[a-z0-9]+test|fixtures?|spec|specs|mocks?|e2e|integration(?:[-_]?tests?)?|vectors|test[-_]?vectors|[a-z0-9_]+_vectors)\/|(_test\.go|_test\.py|\.(test|spec)\.[cm]?[jt]sx?)$|(^|\/)test[-_][^/]*$|(^|\/)testing[-_]?utils?\.[a-z]+$|(^|\/)fixtures?\.[cm]?[jt]sx?$/i;
// Example and tutorial code, which is documentation in code form.
// Translation files: "password" and "token" there are labels shown to people.
export const LOCALE_PATH = /(^|\/)(locales?|i18n|l10n|translations?|nls)\/|\.(po|pot|xliff|xlf|ftl|strings)$/i;
// Example settings files (.env.example), API specs and docs-site configs (public search keys).
export const EXAMPLE_FILE = /\.(example|sample|template|tmpl|dist)$|(^|\/)\.env\.(example|sample|template)|(^|\/)(openapi|swagger)[^/]*\.(ya?ml|json)$|(^|\/)docusaurus\.config\.[cm]?[jt]s$|\.stories\.[cm]?[jt]sx?$|(^|\/)\.secrets\.baseline$/i;
export const EXAMPLE_PATH = /(^|\/)(docs?_src|docs?|examples?|samples?|tutorials?)\//i;
const LOOSE_SECRET_RULES = new Set(["private-key", "generic-assignment", "db-url-password"]);
const SKIP_PATH = /(^|\/)(node_modules|vendor|dist|build|\.git|__pycache__|\.venv|venv|target)\//;
const SKIP_FILE = /(\.min\.js|\.map|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|\.lock)$/;

export function shouldScan(path: string): boolean {
  if (SKIP_PATH.test(path) || SKIP_FILE.test(path)) return false;
  return true;
}

function trimSnippet(line: string): string {
  const t = line.trim();
  return t.length > 160 ? `${t.slice(0, 157)}...` : t;
}

/**
 * Scan one file.
 * @param onlyLines if given, only report findings on these 1-based line numbers
 *                  (used for pull requests: only what the change added).
 */
export function scanFile(path: string, content: string, onlyLines?: Set<number>): Finding[] {
  if (content.includes("\u0000")) return []; // binary
  const lines = content.split(/\r?\n/).map((text, i) => ({ no: i + 1, text }));
  // Scan the whole file so settings see their surrounding block, then keep only the lines asked for.
  const findings = scanLines(path, lines);
  return onlyLines ? findings.filter((f) => onlyLines.has(f.line)) : findings;
}

/** Scan the lines a pull request added, straight from GitHub's patch text. No file download needed. */
export function scanPatch(path: string, patch: string | undefined): Finding[] {
  return scanLines(path, patchAddedLines(patch));
}

export function scanLines(path: string, lines: { no: number; text: string }[]): Finding[] {
  if (!shouldScan(path)) return [];
  const lang = langFor(path);
  const rules = [...CRYPTO_RULES.filter((r) => r.langs.includes("any") || (lang !== null && r.langs.includes(lang))), ...communityRulesFor(path)];
  const findings: Finding[] = [];

  for (let idx = 0; idx < lines.length; idx++) {
    const { no: lineNo, text: raw } = lines[idx];
    if (raw.length > MAX_LINE) continue;


    // Secrets: every text file.
    for (const hit of findSecrets(raw)) {
      // A private-key header only counts when real key material follows it (docs often show "XXXX").
      if (hit.rule.id === "private-key" && !hasKeyMaterial(raw, lines[idx + 1])) continue;
      // Docs are full of example passwords; only specific token formats count there.
      if (hit.rule.id === "generic-assignment" && (DOC_FILE.test(path) || LOCALE_PATH.test(path) || TYPES_FILE.test(path) || COMMENT_LINE.test(raw))) continue;
      if (hit.rule.id === "db-url-password" && DOC_FILE.test(path)) continue;
      if (TEST_PATH.test(path)) continue;
      if (LOOSE_SECRET_RULES.has(hit.rule.id) && (EXAMPLE_PATH.test(path) || EXAMPLE_FILE.test(path) || DOC_FILE.test(path))) continue;
      findings.push({
        kind: "secret",
        ruleId: hit.rule.id,
        title: `${hit.rule.name} committed to the repository`,
        algorithm: hit.rule.name,
        primitive: "credential",
        risk: "secret",
        severity: "critical",
        file: path,
        line: lineNo,
        snippet: trimSnippet(raw.split(hit.value).join(mask(hit.value))),
        fix: "Revoke it and issue a new one, then load it from a secret store. Deleting it from the code leaves it in git history.",
      });
    }

    // Crypto: language-scoped rules. Type declarations and comments describe code; they don't run it.
    if (TYPES_FILE.test(path) || COMMENT_LINE.test(raw)) continue;
    for (const rule of rules) {
      const m = raw.match(rule.pattern);
      if (!m) continue;
      let algorithm = typeof rule.algorithm === "string" ? rule.algorithm : rule.algorithm(m);
      if (!algorithm) continue;
      let info = ALGORITHMS[algorithm];
      if (!info) continue;
      // Encryption in test code is not what ships, so it stays out of the inventory and the check.
      if (TEST_PATH.test(path)) continue;
      // Python's usedforsecurity=False marks a hash that is only a checksum.
      if (info.primitive === "hash" && /usedforsecurity\s*=\s*False/.test(raw)) continue;
      // MD5 and SHA-1 are mostly used for checksums, cache keys and ETags, which are fine.
      // Only flag them where the code around them is about passwords, signing, tokens and the like.
      if ((algorithm === "MD5" || algorithm === "SHA-1") && !weakHashForSecurity(raw, lines, idx)) continue;

      let keySize: number | undefined;
      if (rule.keySize) {
        const k = raw.match(rule.keySize);
        if (k) keySize = Number(k[1]);
      }
      let title = `${algorithm} is ${info.risk === "weak-now" ? "weak today" : "breakable by quantum computers"}`;
      let severity = info.severity;
      let risk = info.risk;
      let fix = info.fix;
      if (keySize !== undefined && algorithm.startsWith("RSA") && keySize < 2048) {
        title = `RSA-${keySize} is weak today and breakable by quantum computers`;
        severity = "high";
        risk = "weak-now";
        fix = "Use 3072-bit keys or larger now, then plan the move to post-quantum methods.";
      }
      findings.push({
        kind: "crypto",
        ruleId: rule.id,
        title,
        algorithm,
        primitive: info.primitive,
        risk,
        severity,
        file: path,
        line: lineNo,
        snippet: trimSnippet(raw),
        fix,
        keySize,
      });
    }
  }
  // Infrastructure config: test fixtures and examples are written to be wrong or to show options.
  if (!TEST_PATH.test(path) && !EXAMPLE_PATH.test(path)) findings.push(...scanInfra(path, lines));
  return dedupe(findings);
}

// Words that say a hash is not protecting anything.
const HASH_NOT_SECURITY = /nosec|NOSONAR|noqa|usedforsecurity|e-?tag|cache|checksum|\bcrc|dedup|uuid|gravatar|content[-_]?md5|shard|partition|consistent.?hash|file.?hash|hash.?file|filename|file.?name|\bgit\b|identicon|colou?r/i;
// Words that say it is.
const HASH_SECURITY = /passw|passwd|\bpwd|signature|\bsign(ed|er|ing)?\b|verif|hmac|authenti|\bauth\b|token|secret|credential|certificat|\bcert\b|salt|nonce|session|encrypt|decrypt|login|\bjwt\b|\botp\b|api.?key|private|\bkdf\b|pbkdf|derive|card|\bssn\b|integrity/i;

/** Whether an MD5 or SHA-1 call at lines[idx] looks like it protects something. */
function weakHashForSecurity(raw: string, lines: { no: number; text: string }[], idx: number): boolean {
  if (/hmac/i.test(raw)) return true;
  if (HASH_NOT_SECURITY.test(raw)) return false;
  if (HASH_SECURITY.test(raw)) return true;
  // The function or block around it: a few lines up (often the function name) and a couple down.
  const around = lines.slice(Math.max(0, idx - 6), idx + 3).map((l) => l.text).join("\n");
  if (HASH_NOT_SECURITY.test(around)) return false;
  return HASH_SECURITY.test(around);
}

const KEY_BODY = /^[A-Za-z0-9+/=]{40,}$/;
function hasKeyMaterial(line: string, next?: { no: number; text: string }): boolean {
  const after = line.split(/PRIVATE KEY(?: BLOCK)?-----/)[1] ?? "";
  if (after.split(/\\n|\s+/).some((part) => KEY_BODY.test(part))) return true;
  return next !== undefined && KEY_BODY.test(next.text.trim().replace(/^["']|["',]$/g, ""));
}

// Two rules can hit the same line for the same algorithm; keep one.
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const k = `${f.file}:${f.line}:${f.kind}:${f.algorithm}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

export function scanFiles(files: { path: string; content: string; onlyLines?: Set<number> }[]): ScanResult {
  const findings: Finding[] = [];
  const pqc: PqcSignal[] = [];
  const inventory: InventoryItem[] = [];
  let filesScanned = 0;
  for (const f of files) {
    if (!shouldScan(f.path)) continue;
    filesScanned++;
    findings.push(...scanFile(f.path, f.content, f.onlyLines));
    // Post-quantum use only counts in code that ships, like the problems do.
    if (!TEST_PATH.test(f.path) && !EXAMPLE_PATH.test(f.path)) {
      pqc.push(...findPqc(f.path, f.content));
      inventory.push(...findInventory(f.path, f.content).filter((i) => !f.onlyLines || f.onlyLines.has(i.line)));
    }
  }
  return { findings, filesScanned, pqc, inventory };
}

/** Parse a unified diff patch (GitHub's `patch` field) into the added lines of the new file. */
export function patchAddedLines(patch: string | undefined): { no: number; text: string }[] {
  const out: { no: number; text: string }[] = [];
  if (!patch) return out;
  let line = 0;
  for (const l of patch.split("\n")) {
    const h = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (h) {
      line = Number(h[1]);
      continue;
    }
    if (l.startsWith("+")) {
      out.push({ no: line, text: l.slice(1) });
      line++;
    } else if (l.startsWith("-")) {
      // removed line: new-file counter does not move
    } else if (!l.startsWith("\\")) {
      line++;
    }
  }
  return out;
}

export function addedLines(patch: string | undefined): Set<number> {
  return new Set(patchAddedLines(patch).map((l) => l.no));
}
