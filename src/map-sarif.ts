// SARIF 2.1.0 for the security map, so the map's findings can go into security tools that read SARIF.
// Code findings point at their file and line. Websites, network, equipment and this machine have no
// file, so they carry the place they were found as a logical location. GitHub code scanning only
// shows results with a file, so for GitHub upload the code scan's own --format sarif output.

import type { MapFinding } from "./map-types.ts";
import { HELP_URI, fingerprints, securitySeverity, worstOf, type Sev } from "./sarif-common.ts";

const BY_RATING = { high: "error", medium: "warning", low: "note" } as const;
const BY_RISK = { secret: "error", "weak-now": "error", exposed: "error", "quantum-vulnerable": "warning" } as const;

function location(f: MapFinding) {
  const m = f.area === "code" ? /^(.*):(\d+)$/.exec(f.target) : null;
  if (m) {
    const line = Number(m[2]);
    return { physicalLocation: { artifactLocation: { uri: m[1], uriBaseId: "%SRCROOT%" }, ...(line > 0 ? { region: { startLine: line } } : {}) } };
  }
  return { logicalLocations: [{ fullyQualifiedName: f.target, kind: "resource" }] };
}

/** What to do, in the finding's own steps when a closer look wrote them, else the scanner's fix. */
const todo = (f: MapFinding & { why?: string; steps?: string[] }) => [f.why, ...(f.steps?.length ? f.steps : [f.fix])].filter(Boolean).join(" ");

// One rule per kind of check ("net-admin-http"), so a router and a printer with the same problem share a rule.
// How much each one matters (its risk and rating) is on the result, where it can differ by device.
export function buildMapSarif(findings: (MapFinding & { why?: string; steps?: string[] })[], toolVersion: string) {
  const worst = new Map<string, Sev>();
  const risk = new Map<string, string>();
  for (const f of findings) {
    worst.set(f.ruleId, worstOf(worst.get(f.ruleId), f.severity as Sev));
    // A rule is capped as quantum-only when every finding under it is.
    risk.set(f.ruleId, risk.get(f.ruleId) && risk.get(f.ruleId) !== f.risk ? "mixed" : f.risk);
  }
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; help: { text: string }; helpUri: string; properties: { tags: string[]; "security-severity": string } }>();
  for (const f of findings)
    if (!rules.has(f.ruleId))
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.algorithm,
        shortDescription: { text: f.algorithm },
        help: { text: f.fix },
        helpUri: HELP_URI,
        properties: { tags: ["security", f.area], "security-severity": securitySeverity(risk.get(f.ruleId)!, worst.get(f.ruleId)!) },
      });
  const ruleIndex = new Map([...rules.keys()].map((id, i) => [id, i]));
  const prints = fingerprints(findings, (f) => `${f.ruleId}|${f.target}`);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "Hard Keel Quantum Scan map", version: toolVersion, informationUri: HELP_URI, rules: [...rules.values()] } },
        results: findings.map((f, i) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIndex.get(f.ruleId),
          level: f.rating ? BY_RATING[f.rating] : BY_RISK[f.risk as keyof typeof BY_RISK] ?? "note",
          message: { text: `${f.title}. ${todo(f)}` },
          locations: [location(f)],
          partialFingerprints: prints[i],
          properties: { area: f.area, risk: f.risk, "security-severity": securitySeverity(f.risk, f.severity as Sev), ...(f.rating ? { rating: f.rating } : {}), ...(f.tier ? { tier: f.tier } : {}), internetFacing: f.internetFacing },
        })),
      },
    ],
  };
}
