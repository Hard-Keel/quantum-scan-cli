// quantum-scan map: asks before each area, runs only what was approved, and writes the encryption map.
// Unattended runs use a scope file, which records what was approved. Nothing outside it is touched.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { applyIgnore, applyIgnoreTargets, IGNORE_FILE, parseIgnore } from "./ignore.ts";
import { buildCbom } from "./cbom.ts";
import { ActivityLog } from "./map-activity.ts";
import { CARDS, cardText } from "./map-areas.ts";
import { runHost, type HostIO } from "./map-host.ts";
import { fromCodeFinding, rank, toFinding } from "./map-rank.ts";
import { buildMapReport, mapHtml, mapText, type MapReport } from "./map-report.ts";
import { emptyResult, type AreaResult, type MapFinding } from "./map-types.ts";
import { proofRecord, runWeb, type WebOptions } from "./map-web.ts";
import { scanFiles } from "./scan.ts";
import type { AreaName, ErrorKind, RunFacts } from "./share.ts";
import { INDUSTRIES, SIZES, type Industry, type Settings, type Size } from "./share-config.ts";
import { walkFolder } from "./walk.ts";

export const SCOPE_FILE = "quantum-scan.scope.json";

export interface Scope {
  version: 1;
  created: string;
  ownershipToken?: string; // lets a team or a pipeline share one DNS record
  areas: {
    code?: { folders: string[] };
    web?: { targets: string[] };
    host?: Record<string, never>;
  };
}

export function parseScope(text: string): Scope | { error: string } {
  let v: any;
  try {
    v = JSON.parse(text);
  } catch {
    return { error: "the scope file isn't valid JSON" };
  }
  if (!v || v.version !== 1 || typeof v.areas !== "object") return { error: "the scope file needs version 1 and an areas object" };
  const s: Scope = { version: 1, created: String(v.created ?? ""), areas: {} };
  if (typeof v.ownershipToken === "string" && /^[a-f0-9]{24}$/.test(v.ownershipToken)) s.ownershipToken = v.ownershipToken;
  const strings = (x: unknown) => (Array.isArray(x) ? x.filter((y): y is string => typeof y === "string" && y.length > 0 && y.length < 300) : []);
  if (v.areas.code) s.areas.code = { folders: strings(v.areas.code.folders) };
  if (v.areas.web) s.areas.web = { targets: strings(v.areas.web.targets) };
  if (v.areas.host) s.areas.host = {};
  const known = new Set(["code", "web", "host"]);
  const unknown = Object.keys(v.areas).filter((k) => !known.has(k));
  if (unknown.length) return { error: `this version can't check: ${unknown.join(", ")}` };
  return s;
}

export interface Prompter {
  ask(q: string): Promise<string>;
  close(): void;
}

export function terminalPrompter(): Prompter {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return { ask: (q) => rl.question(q), close: () => rl.close() };
}

const yes = (a: string) => /^\s*y(es)?\s*$/i.test(a);

/** Walks through each area with its card. The answer is no unless the person types yes. */
export async function askScope(p: Prompter, cwd: string, write: (t: string) => void): Promise<Scope> {
  const scope: Scope = { version: 1, created: new Date().toISOString().slice(0, 10), areas: {} };
  write("\nI'll go through each area, say what it does, and ask first. Press Enter to skip any of them.\n\n");

  write(cardText(CARDS.code, [cwd]) + "\n");
  if (yes(await p.ask("Scan the code and config in this folder? (y/N) "))) scope.areas.code = { folders: ["."] };

  write("\n");
  const raw = await p.ask("Websites and public services: list addresses to check, separated by spaces (e.g. example.com api.example.com:8443 ssh://git.example.com), or press Enter to skip:\n> ");
  const targets = raw.split(/[\s,]+/).filter(Boolean);
  if (targets.length) {
    write("\n" + cardText(CARDS.web, targets) + "\n");
    if (yes(await p.ask("Check these addresses? (y/N) "))) scope.areas.web = { targets };
  }

  write("\n" + cardText(CARDS.host, []) + "\n");
  if (yes(await p.ask("Check this machine? (y/N) "))) scope.areas.host = {};
  return scope;
}

/** Optional, asked once: lets the anonymized counts be grouped by industry and size. */
export async function askProfile(p: Prompter, s: Settings, write: (t: string) => void): Promise<void> {
  write(`\nOptional: your industry and company size help us understand encryption trends. Press Enter to skip.\n  Industries: ${INDUSTRIES.join(", ")}\n`);
  const ind = (await p.ask("Industry: ")).trim().toLowerCase();
  if (INDUSTRIES.includes(ind as Industry)) s.industry = ind as Industry;
  const size = (await p.ask(`Company size (${SIZES.join(", ")}): `)).trim();
  if (SIZES.includes(size as Size)) s.size = size as Size;
  s.profileAsked = true;
}

export interface MapOptions {
  scopePath?: string;
  outDir: string;
  cwd: string;
  version: string;
  settings: Settings;
  sharingOn: boolean;
  interactive: boolean;
  prompter?: () => Prompter;
  write?: (t: string) => void;
  web?: Omit<WebOptions, "token">;
  hostIO?: HostIO;
}

export interface MapOutcome {
  code: number;
  report?: MapReport;
  facts?: RunFacts;
  stateKey?: string;
  state?: { rules: Record<string, number>; pqc: Record<string, number> };
}

export async function runMap(o: MapOptions): Promise<MapOutcome> {
  const write = o.write ?? ((t: string) => process.stderr.write(t));
  let scope: Scope;
  if (o.scopePath) {
    if (!existsSync(o.scopePath)) {
      write(`No scope file at ${o.scopePath}.\n`);
      return { code: 2 };
    }
    const parsed = parseScope(readFileSync(o.scopePath, "utf8"));
    if ("error" in parsed) {
      write(`Can't use ${o.scopePath}: ${parsed.error}.\n`);
      return { code: 2 };
    }
    scope = parsed;
  } else if (o.interactive) {
    const p = (o.prompter ?? terminalPrompter)();
    try {
      scope = await askScope(p, o.cwd, write);
      if (o.sharingOn && !o.settings.profileAsked) await askProfile(p, o.settings, write);
      if (Object.keys(scope.areas).length && yes(await p.ask(`\nSave these answers to ${SCOPE_FILE} so the next run (or a pipeline) can reuse them? (y/N) `))) {
        scope.ownershipToken = o.settings.ownershipToken;
        writeFileSync(join(o.cwd, SCOPE_FILE), JSON.stringify(scope, null, 2) + "\n");
        write(`Saved ${SCOPE_FILE}.\n`);
      }
    } finally {
      p.close();
    }
  } else {
    write(`quantum-scan map asks before each area. Run it in a terminal, or pass --scope ${SCOPE_FILE} for unattended runs.\n`);
    return { code: 2 };
  }

  const areas = Object.keys(scope.areas) as AreaName[];
  if (!areas.length) {
    write("Nothing approved, so nothing was checked.\n");
    return { code: 0 };
  }

  mkdirSync(o.outDir, { recursive: true });
  const logPath = join(o.outDir, "activity.log");
  writeFileSync(logPath, "");
  const log = new ActivityLog(logPath);
  const results: AreaResult[] = [];
  const ignored: Record<string, number> = {};
  const pqcCounts: Record<string, number> = {};

  if (scope.areas.code) {
    const res = emptyResult("code");
    for (const folder of scope.areas.code.folders.length ? scope.areas.code.folders : ["."]) {
      const dir = resolve(o.cwd, folder);
      log.record("code", dir, "read source and config files");
      try {
        const walked = walkFolder(dir);
        for (const u of walked.unreadable) res.errors.push({ area: "code", target: `${folder}/${u.path}`.replace(/^\.\//, ""), kind: u.reason === "permission denied" ? "permission" : "read", message: `couldn't read (${u.reason})` });
        const { findings, pqc, filesScanned } = scanFiles(walked.files);
        const ign = join(dir, IGNORE_FILE);
        const { kept, ignored: ig } = applyIgnore(findings, existsSync(ign) ? parseIgnore(readFileSync(ign, "utf8")) : []);
        for (const [k, n] of Object.entries(ig)) ignored[k] = (ignored[k] ?? 0) + n;
        res.findings.push(...kept.map(fromCodeFinding));
        for (const s of pqc) pqcCounts[s.algorithm] = (pqcCounts[s.algorithm] ?? 0) + 1;
        res.checked.push(`${folder} (${filesScanned} files)`);
      } catch (e) {
        res.errors.push({ area: "code", target: folder, kind: "read", message: e instanceof Error ? e.message : String(e) });
      }
    }
    results.push(res);
  }

  if (scope.areas.web) {
    const token = scope.ownershipToken ?? o.settings.ownershipToken;
    const res = await runWeb(scope.areas.web.targets, log, { ...o.web, token });
    results.push(res);
    if (res.unproved.length) {
      write("\nSome addresses were skipped because their domain isn't proved yet. To prove one, add this DNS record, then run again:\n");
      for (const d of res.unproved) {
        const r = proofRecord(d, token);
        write(`  ${r.name}  TXT  "${r.value}"\n`);
      }
      write("One record covers the domain and everything under it.\n");
    }
    if (res.dnsFailed.length) {
      write(`\nCouldn't look up the ownership record for ${res.dnsFailed.join(", ")} because DNS didn't answer, so ${res.dnsFailed.length === 1 ? "it was" : "they were"} skipped. Check this machine's DNS settings, then run again.\n`);
    }
  }

  if (scope.areas.host) results.push(runHost(log, o.hostIO));

  // Known leftovers the person accepted in .quantum-scan-ignore (websites and this machine; code was handled per folder).
  const ignorePath = join(o.cwd, IGNORE_FILE);
  const entries = existsSync(ignorePath) ? parseIgnore(readFileSync(ignorePath, "utf8")) : [];
  const accepted: MapFinding[] = [];
  for (const r of results) {
    if (r.area === "code" || !entries.length) continue;
    const a = applyIgnoreTargets(r.findings, entries);
    r.findings = a.kept;
    accepted.push(...a.accepted);
    for (const f of a.accepted) ignored[f.ruleId] = (ignored[f.ruleId] ?? 0) + 1;
  }
  const ranked = rank(results.flatMap((r) => r.findings));
  const report = buildMapReport(results, ranked, o.version, new Date(), accepted);
  writeFileSync(join(o.outDir, "map.json"), JSON.stringify(report, null, 2) + "\n");
  writeFileSync(join(o.outDir, "map.html"), mapHtml(report, log.entries));
  writeFileSync(join(o.outDir, "map.cbom.json"), JSON.stringify(buildCbom(ranked.map(toFinding), { repo: "encryption map", toolVersion: o.version }), null, 2) + "\n");
  process.stdout.write(mapText(report) + `\n\nWrote ${join(o.outDir, "map.html")}, map.json, map.cbom.json and activity.log. They stay on this machine.\n`);

  // Counts for the anonymized summary. Targets never leave this function.
  const rules: Record<string, number> = {};
  const algorithms: RunFacts["algorithms"] = {};
  for (const f of ranked) {
    rules[f.ruleId] = (rules[f.ruleId] ?? 0) + 1;
    const a = (algorithms[f.algorithm] ??= { count: 0, quantumVulnerable: 0 });
    a.count++;
    if (f.risk === "quantum-vulnerable") a.quantumVulnerable++;
  }
  for (const s of report.strengths) pqcCounts[s.algorithm] = (pqcCounts[s.algorithm] ?? 0) + 1;
  const errors = [...new Set(results.flatMap((r) => r.errors.map((e) => e.kind)))] as ErrorKind[];
  const facts: RunFacts = { command: "map", areas, rules, algorithms, quantumSafe: pqcCounts, fixed: {}, ignored, replacements: {}, errors };
  return { code: 0, report, facts, stateKey: `map:${resolve(o.cwd)}`, state: { rules, pqc: pqcCounts } };
}
