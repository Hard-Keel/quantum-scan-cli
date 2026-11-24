// SARIF 2.1.0 output, so GitHub code scanning (and other tools) can show findings.

import type { Finding } from "./types.ts";
import { shortLabel } from "./report.ts";
import { HELP_URI, fingerprints, securitySeverity, worstOf, type Sev } from "./sarif-common.ts";

const LEVEL: Record<Finding["risk"], "error" | "warning"> = {
  secret: "error",
  "weak-now": "error",
  "quantum-vulnerable": "warning",
  exposed: "error",
};

const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

/**
 * One SARIF rule per kind of problem, like "weak-now/md5-hash" or "secret/aws-access-key". A setting
 * is named by the setting itself, not by a label that can carry its value (such as the ports open),
 * so the id stays the same from run to run.
 */
export function ruleId(f: Finding): string {
  return `${f.risk}/${slug(f.kind === "config" ? f.algorithm : shortLabel(f))}`;
}

function tags(f: Finding): string[] {
  const kind = f.kind === "secret" ? "secret" : f.kind === "config" ? "configuration" : "encryption";
  return ["security", kind, f.risk, ...(f.risk === "quantum-vulnerable" ? ["post-quantum"] : [])];
}

function whenText(f: Finding): string {
  if (f.risk === "quantum-vulnerable") return "Safe today, but a large quantum computer will be able to break it. NIST plans to phase it out between 2030 and 2035.";
  if (f.risk === "secret") return "Anyone who can read the repository can use it.";
  return "Fix this now. It doesn't take a quantum computer to break.";
}

/** A scanner path as a URI from the repository root, when the scan ran on a folder inside the repository. */
export function toUri(path: string, prefix = ""): string {
  const clean = (s: string) => s.replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/\/+$/, "");
  const pre = clean(prefix);
  const p = clean(path);
  return encodeURI(pre && pre !== "." ? `${pre}/${p}` : p);
}

export interface SarifOptions {
  /** Folder the scanned paths sit in, relative to the repository root, so code scanning can find the files. */
  uriPrefix?: string;
}

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  helpUri: string;
  defaultConfiguration: { level: "error" | "warning" };
  properties: { tags: string[]; "security-severity": string };
}

export function buildSarif(findings: Finding[], toolVersion: string, opts: SarifOptions = {}) {
  const worst = new Map<string, Sev>();
  for (const f of findings) worst.set(ruleId(f), worstOf(worst.get(ruleId(f)), f.severity as Sev));
  const rules = new Map<string, SarifRule>();
  for (const f of findings) {
    const id = ruleId(f);
    if (rules.has(id)) continue;
    const name = shortLabel(f);
    const when = whenText(f);
    rules.set(id, {
      id,
      name,
      shortDescription: { text: f.title },
      fullDescription: { text: `${f.title}. ${when}` },
      help: { text: `${when} Fix: ${f.fix}`, markdown: `**${name}**\n\n${when}\n\n**Fix:** ${f.fix}\n\n[About Hard Keel Quantum Scan](${HELP_URI})` },
      helpUri: HELP_URI,
      defaultConfiguration: { level: LEVEL[f.risk] },
      properties: { tags: tags(f), "security-severity": securitySeverity(f.risk, worst.get(id)!) },
    });
  }
  const uri = (f: Finding) => toUri(f.file, opts.uriPrefix);
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));
  const prints = fingerprints(findings, (f) => `${ruleId(f)}|${uri(f)}`);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Hard Keel Quantum Scan",
            version: toolVersion,
            informationUri: HELP_URI,
            rules: [...rules.values()],
          },
        },
        results: findings.map((f, i) => ({
          ruleId: ruleId(f),
          ruleIndex: ruleIndex.get(ruleId(f)),
          level: LEVEL[f.risk],
          message: { text: `${f.title}. ${f.fix}` },
          // SARIF lines start at 1; a finding about a whole file (line 0) points at the file alone.
          locations: [{ physicalLocation: { artifactLocation: { uri: uri(f), uriBaseId: "%SRCROOT%" }, ...(f.line > 0 ? { region: { startLine: f.line } } : {}) } }],
          partialFingerprints: prints[i],
        })),
      },
    ],
  };
}
