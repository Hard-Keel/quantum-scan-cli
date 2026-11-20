#!/usr/bin/env node
// Hard Keel Quantum Scan, command line.
// Finds encryption quantum computers will break, weak encryption, exposed infrastructure settings
// and leaked keys in a folder,
// and writes an encryption inventory (CycloneDX CBOM) and a migration report.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { walk } from "./walk.ts";
import { buildCbom } from "./cbom.ts";
import { migrationReportMarkdown, prSummaryLine, shortLabel, sortFindings } from "./report.ts";
import { buildSarif } from "./sarif.ts";
import { scanFiles, shouldScan } from "./scan.ts";
import { badgeSvg } from "./badge.ts";
import { gradeSentence, readinessScore, type ReadinessScore } from "./score.ts";
import type { Finding } from "./types.ts";
import { applyIgnore, IGNORE_FILE, parseIgnore } from "./ignore.ts";
import { ActivityLog } from "./map-activity.ts";
import { parseScope, runMap, SCOPE_FILE } from "./map-run.ts";
import { hasProof, parseTarget, proofRecord } from "./map-web.ts";
import { buildPayload, diffRuns, sendPayload, type Payload, type RunFacts } from "./share.ts";
import { folderKey, INDUSTRIES, loadSettings, saveSettings, settingsPath, sharingState, showNoticeIfNeeded, SIZES, type FolderState, type Industry, type SharingReason, type Settings, type Size } from "./share-config.ts";

export const VERSION = "0.2.0";
const APP_URL = "https://github.com/apps/hard-keel-quantum-scan";

const HELP = `Hard Keel Quantum Scan ${VERSION}

Finds encryption quantum computers will break, weak encryption, exposed settings and
leaked keys or passwords in your code and infrastructure config (Terraform, CloudFormation,
Kubernetes, Dockerfiles, nginx and Apache). Writes an encryption inventory and a
migration report.

Usage:
  quantum-scan [folder] [options]   Scan code and infrastructure config
  quantum-scan map [options]        Encryption map: code, websites and this machine,
                                    asking before each area
  quantum-scan prove <domain>       Show the DNS record that proves a domain is yours
  quantum-scan config <setting>     Sharing, offline mode, industry and size

Options:
  --format <text|json|sarif>   What to print (default: text)
  --output <file>              Write the --format output to a file instead
  --cbom <file>                Write the encryption inventory (CycloneDX 1.6 CBOM)
  --report <file>              Write the migration report (Markdown)
  --badge <file>               Write a quantum readiness badge (SVG) for your README
  --name <name>                Repository name to use in the inventory and report
  --fail-on <list>             Exit with 1 on these: secret, weak-now, exposed,
                               quantum-vulnerable, or none (default: secret,weak-now,exposed)
  --quiet                      Leave out the closing line about installing on GitHub
  --offline                    Send nothing to Hard Keel
  --version                    Print the version
  --help                       Print this help

Map options:
  --scope <file>               Use saved answers (quantum-scan.scope.json) instead of asking
  --out <folder>               Where to write the map (default: quantum-scan-map)
  --fail-on broken             Exit with 1 when anything is broken now

Config:
  quantum-scan config show                Current settings
  quantum-scan config show-shared         Exactly what the last run sent, or would have sent
  quantum-scan config sharing on|off      Anonymized sharing (on by default)
  quantum-scan config offline on|off      Send nothing at all, ever
  quantum-scan config industry <name>     Optional. ${INDUSTRIES.join(", ")}, or none
  quantum-scan config size <band>         Optional. ${SIZES.join(", ")}, or none

Sharing: unless you turn it off, each run sends an anonymized summary: rounded counts of
which checks fired and which encryption types were found. Never code, keys, server
names, IP addresses or company name. Details: https://hardkeel.com/privacy/
`;

function parseArgs(argv: string[]) {
  const flags = new Set(["quiet", "help", "version", "offline"]);
  const opts: Record<string, string | true> = {};
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      rest.push(a);
      continue;
    }
    const [k, v] = a.slice(2).split("=", 2);
    if (flags.has(k)) opts[k] = true;
    else if (v !== undefined) opts[k] = v;
    else opts[k] = argv[++i] ?? "";
  }
  return { opts, dir: rest[0] ?? "." };
}

function textReport(findings: Finding[], filesScanned: number, quiet: boolean, score: ReadinessScore): string {
  const out = [`Hard Keel Quantum Scan · ${filesScanned} file${filesScanned === 1 ? "" : "s"} scanned`, "", gradeSentence(score), ""];
  if (!findings.length) {
    out.push("Nothing found. No leaked keys, weak or quantum-breakable encryption, or exposed settings.");
  } else {
    out.push(prSummaryLine(findings).replace("This change adds", "Found"));
    const sorted = sortFindings(findings);
    const section = (title: string, list: Finding[], note?: string) => {
      if (!list.length) return;
      out.push("", title);
      if (note) out.push(`  ${note}`);
      for (const f of list) out.push(`  ${f.file}:${f.line}  ${shortLabel(f)}`, `    ${f.fix}`);
    };
    section("Fix now", sorted.filter((f) => f.risk !== "quantum-vulnerable"));
    section(
      "Plan for later",
      sorted.filter((f) => f.risk === "quantum-vulnerable"),
      "Safe today, but quantum computers will be able to break these. NIST plans to phase them out between 2030 and 2035.",
    );
  }
  if (!quiet) out.push("", `Check every pull request automatically: ${APP_URL}`);
  return out.join("\n");
}

export function main(argv: string[]): number {
  return scanCommand(argv).code;
}

/** The folder scan. Returns its exit code and the counts the anonymized summary may use. */
export function scanCommand(argv: string[]): { code: number; facts?: RunFacts; stateKey?: string; state?: FolderState } {
  const { opts, dir } = parseArgs(argv);
  if (opts.help) {
    process.stdout.write(HELP);
    return { code: 0 };
  }
  if (opts.version) {
    console.log(VERSION);
    return { code: 0 };
  }
  const str = (k: string) => (typeof opts[k] === "string" ? (opts[k] as string) : undefined);

  const scanned = scanFiles(walk(dir));
  const { filesScanned, pqc } = scanned;
  const ignorePath = join(dir, IGNORE_FILE);
  const { kept: findings, ignored } = applyIgnore(scanned.findings, existsSync(ignorePath) ? parseIgnore(readFileSync(ignorePath, "utf8")) : []);
  const score = readinessScore(findings, pqc);
  const repo = str("name") ?? dir;
  const badgePath = str("badge");
  if (badgePath) writeFileSync(badgePath, badgeSvg(score) + "\n");
  const cbomPath = str("cbom");
  if (cbomPath) writeFileSync(cbomPath, JSON.stringify(buildCbom(findings, { repo, toolVersion: VERSION }), null, 2) + "\n");
  const reportPath = str("report");
  if (reportPath) writeFileSync(reportPath, migrationReportMarkdown(repo, findings, new Date().toISOString().slice(0, 10), score) + "\n");

  const format = str("format") ?? "text";
  let body: string;
  if (format === "json") body = JSON.stringify({ tool: "hard-keel-quantum-scan", version: VERSION, filesScanned, score, findings }, null, 2);
  else if (format === "sarif") body = JSON.stringify(buildSarif(findings, VERSION), null, 2);
  else if (format === "text") body = textReport(findings, filesScanned, opts.quiet === true, score);
  else {
    console.error(`Unknown --format "${format}". Use text, json or sarif.`);
    return { code: 2 };
  }
  const outPath = str("output");
  if (outPath) {
    writeFileSync(outPath, body + "\n");
    console.log(`${filesScanned} files scanned, ${findings.length} finding${findings.length === 1 ? "" : "s"}. Wrote ${outPath}.`);
  } else console.log(body);

  const failOn = (str("fail-on") ?? "secret,weak-now,exposed").split(",").map((s) => s.trim());
  const code = findings.some((f) => failOn.includes(f.risk)) ? 1 : 0;

  const rules: Record<string, number> = {};
  const algorithms: RunFacts["algorithms"] = {};
  for (const f of findings) {
    rules[f.ruleId] = (rules[f.ruleId] ?? 0) + 1;
    if (f.kind === "secret") continue; // what kind of secret is a rule id already; no algorithm entry
    const a = (algorithms[f.algorithm] ??= { count: 0, quantumVulnerable: 0 });
    a.count++;
    if (f.risk === "quantum-vulnerable") a.quantumVulnerable++;
  }
  const pqcCounts: Record<string, number> = {};
  for (const p of pqc) pqcCounts[p.algorithm] = (pqcCounts[p.algorithm] ?? 0) + 1;
  const facts: RunFacts = { command: "scan", areas: ["code"], rules, algorithms, quantumSafe: pqcCounts, fixed: {}, ignored, replacements: {}, errors: [] };
  return { code, facts, stateKey: folderKey(dir), state: { rules, pqc: pqcCounts } };
}

/** Records this run, works out what was fixed since the last one, and sends the summary unless sharing is off. */
async function finishRun(facts: RunFacts | undefined, stateKey: string | undefined, state: FolderState | undefined, s: Settings, sharing: SharingReason, send: Sender): Promise<void> {
  if (!facts || !stateKey || !state) return;
  const key = stateKey.startsWith("map:") ? folderKey(stateKey) : stateKey;
  const diff = diffRuns(s.state[key], state);
  facts.fixed = diff.fixed;
  facts.replacements = diff.replacements;
  s.state[key] = state;
  const payload = buildPayload(facts, s, VERSION);
  s.lastShared = sharing === "on" ? payload : { notSent: sharing, wouldHaveSent: payload };
  // The notice comes before the first summary is sent, and only on runs that send one.
  showNoticeIfNeeded(s, sharing);
  saveSettings(s);
  if (sharing === "on") await send(payload);
}

export type Sender = (p: Payload) => Promise<boolean>;

function configCommand(args: string[], s: Settings): number {
  const [what, value] = args;
  const onOff = (v?: string) => (v === "on" || v === "off" ? v : null);
  if (!what || what === "show") {
    console.log(
      [
        `Settings file:  ${settingsPath()}`,
        `Sharing:        ${s.sharing}${sharingState(s, {}) !== s.sharing ? ` (overridden here: ${sharingState(s, {})})` : ""}`,
        `Offline mode:   ${s.offline ? "on" : "off"}`,
        `Industry:       ${s.industry ?? "not set"}`,
        `Size:           ${s.size ?? "not set"}`,
        `Random ID:      ${s.id}  (linked to nothing; quote it to ask us to delete your data)`,
      ].join("\n"),
    );
    return 0;
  }
  if (what === "show-shared") {
    console.log(s.lastShared ? JSON.stringify(s.lastShared, null, 2) : "Nothing yet. Run a scan first.");
    return 0;
  }
  if (what === "sharing" && onOff(value)) s.sharing = onOff(value)!;
  else if (what === "offline" && onOff(value)) s.offline = value === "on";
  else if (what === "industry" && value && (value === "none" || INDUSTRIES.includes(value as Industry))) s.industry = value === "none" ? undefined : (value as Industry);
  else if (what === "size" && value && (value === "none" || SIZES.includes(value as Size))) s.size = value === "none" ? undefined : (value as Size);
  else {
    console.error("Unknown setting. Run quantum-scan --help for the list.");
    return 2;
  }
  s.profileAsked = true;
  saveSettings(s);
  console.log(`Saved: ${what} ${value}.`);
  return 0;
}

async function proveCommand(domain: string | undefined, s: Settings): Promise<number> {
  const p = domain ? parseTarget(domain) : { error: "missing domain" };
  if ("error" in p) {
    console.error("Usage: quantum-scan prove <domain>, for example quantum-scan prove example.com");
    return 2;
  }
  const scope = existsSync(SCOPE_FILE) ? parseScope(readFileSync(SCOPE_FILE, "utf8")) : null;
  const token = scope && !("error" in scope) && scope.ownershipToken ? scope.ownershipToken : s.ownershipToken;
  const r = proofRecord(p.host, token);
  console.log(`To prove you own ${p.host}, add this DNS record:\n\n  Name:  ${r.name}\n  Type:  TXT\n  Value: ${r.value}\n\nIt covers ${p.host} and everything under it. It only allows look-only checks from this machine${scope && !("error" in scope) && scope.ownershipToken ? " and anyone using this scope file" : ""}.`);
  const ok = await hasProof(p.host, token, new ActivityLog());
  console.log(ok ? `\nFound it. ${p.host} is proved.` : "\nNot found yet. DNS changes can take a few minutes; run this again to check.");
  return ok ? 0 : 1;
}

/** Entry point: subcommands, the first-run notice and the anonymized summary. */
export async function run(argv: string[], deps: { send?: Sender; interactive?: boolean } = {}): Promise<number> {
  const send = deps.send ?? ((p: Payload) => sendPayload(p));
  const s = loadSettings();
  const [cmd, ...rest] = argv;
  if (cmd === "config") return configCommand(rest, s);
  if (cmd === "prove") return proveCommand(rest[0], s);

  const offline = argv.includes("--offline");
  const sharing = sharingState(s, { offline });
  if (cmd === "map") {
    const { opts } = parseArgs(rest);
    const str = (k: string) => (typeof opts[k] === "string" ? (opts[k] as string) : undefined);
    if (opts.help) {
      process.stdout.write(HELP);
      return 0;
    }
    const out = await runMap({
      scopePath: str("scope"),
      outDir: str("out") ?? "quantum-scan-map",
      cwd: process.cwd(),
      version: VERSION,
      settings: s,
      sharingOn: sharing === "on",
      interactive: deps.interactive ?? Boolean(process.stdin.isTTY),
    });
    await finishRun(out.facts, out.stateKey, out.state, s, sharing, send);
    if (str("fail-on") === "broken" && out.report && out.report.counts[1] > 0) return 1;
    return out.code;
  }

  const r = scanCommand(argv);
  await finishRun(r.facts, r.stateKey, r.state, s, sharing, send);
  return r.code;
}

const invoked = process.argv[1] ?? "";
if (/cli\.(ts|js)$/.test(invoked) || invoked.endsWith("quantum-scan")) {
  run(process.argv.slice(2)).then(
    (code) => (process.exitCode = code),
    (e) => {
      console.error(e instanceof Error ? e.message : e);
      process.exitCode = 2;
    },
  );
}
