// SARIF 2.1.0 output, so GitHub code scanning (and other security tools) can show findings.
import { createHash } from "node:crypto";
import { shortLabel } from "./report.js";
export const HELP_URI = "https://hardkeel.com/quantum-scan/";
/**
 * GitHub code scanning reads `security-severity` (0.0 to 10.0) to sort alerts into Critical, High,
 * Medium and Low. Encryption quantum computers will break is safe today, so it stays at Medium or
 * below: it belongs in the plan, not ahead of what is broken now.
 */
const SCORE = {
    now: { critical: 9.5, high: 8.0, medium: 5.5, low: 3.0 },
    later: { critical: 6.5, high: 6.0, medium: 5.0, low: 3.0 },
};
export function securitySeverity(risk, severity) {
    return SCORE[risk === "quantum-vulnerable" ? "later" : "now"][severity];
}
const RANK = { critical: 0, high: 1, medium: 2, low: 3 };
/** Fix-now problems are errors, matching the default --fail-on; quantum-breakable encryption is a warning. */
function level(risk) {
    return risk === "quantum-vulnerable" ? "warning" : "error";
}
const slug = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
/**
 * One SARIF rule per kind of problem, like "weak-now/md5-hash" or "secret/aws-access-key".
 * Built from the algorithm or setting, never from a message, so ids stay the same from run to run.
 */
export function sarifRuleId(f) {
    return `${f.risk}/${slug(f.kind === "config" ? f.algorithm : shortLabel(f))}`;
}
function tags(f) {
    const t = ["security"];
    if (f.risk === "secret")
        t.push("secret");
    else if (f.kind === "config")
        t.push("configuration");
    else
        t.push("encryption");
    if (f.risk === "quantum-vulnerable")
        t.push("post-quantum");
    return t;
}
/** A scanner path as a URI relative to the repository root. */
export function toUri(path, prefix = "") {
    const clean = (s) => s.replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/\/+$/, "");
    const pre = clean(prefix);
    const p = clean(path);
    return encodeURI(pre && pre !== "." ? `${pre}/${p}` : p);
}
export function buildSarif(findings, toolVersion, opts = {}) {
    return sarifFor(findings.map((finding) => ({ finding })), toolVersion, opts);
}
/** SARIF for the encryption map: code findings point to files, everything else to the site, device or setting it was found on. */
export function buildMapSarif(items, toolVersion, opts = {}) {
    return sarifFor(items, toolVersion, opts);
}
function whenText(f) {
    if (f.risk === "quantum-vulnerable")
        return "Safe today, but a large quantum computer will be able to break it. NIST plans to phase it out between 2030 and 2035.";
    if (f.risk === "secret")
        return "Anyone who can read the repository can use it.";
    return "Fix this now. It doesn't take a quantum computer to break.";
}
function sarifFor(items, toolVersion, opts) {
    const rules = new Map();
    for (const { finding: f } of items) {
        const id = sarifRuleId(f);
        const existing = rules.get(id);
        if (existing && RANK[existing.worst] <= RANK[f.severity])
            continue;
        const lvl = level(f.risk);
        const name = shortLabel(f);
        const when = whenText(f);
        rules.set(id, {
            worst: f.severity,
            rule: {
                id,
                name,
                shortDescription: { text: f.title },
                fullDescription: { text: `${f.title}. ${when}` },
                help: { text: `${when} Fix: ${f.fix}`, markdown: `**${name}**\n\n${when}\n\n**Fix:** ${f.fix}\n\n[About Hard Keel Quantum Scan](${HELP_URI})` },
                helpUri: HELP_URI,
                defaultConfiguration: { level: lvl },
                properties: {
                    tags: tags(f),
                    precision: f.kind === "crypto" ? "medium" : "high",
                    "problem.severity": lvl === "note" ? "recommendation" : lvl,
                    "security-severity": securitySeverity(f.risk, f.severity).toFixed(1),
                },
            },
        });
    }
    const seen = new Map();
    const results = items.map(({ finding: f, target }) => {
        const ruleId = sarifRuleId(f);
        const isFile = !target || target.area === "code";
        const where = isFile ? toUri(f.file, opts.uriPrefix) : target.name;
        // Same rule, same place, same text: a fingerprint that survives lines moving up or down.
        const key = `${ruleId}|${where}|${f.snippet.trim()}`;
        const n = (seen.get(key) ?? 0) + 1;
        seen.set(key, n);
        const fingerprint = createHash("sha256").update(`${key}|${n}`).digest("hex").slice(0, 32);
        const location = isFile
            ? { physicalLocation: { artifactLocation: { uri: where, uriBaseId: "%SRCROOT%" }, ...(f.line >= 1 ? { region: { startLine: f.line } } : {}) } }
            : { logicalLocations: [{ name: target.name, fullyQualifiedName: `${target.area}:${target.name}`, kind: "resource" }] };
        return {
            ruleId,
            level: level(f.risk),
            message: { text: `${f.title}. ${f.fix}` },
            locations: [location],
            partialFingerprints: { "hardkeelFinding/v1": fingerprint },
            properties: {
                risk: f.risk,
                severity: f.severity,
                algorithm: f.algorithm,
                ...(f.keySize ? { keySize: f.keySize } : {}),
                scannerRule: f.ruleId,
                ...(target && target.area !== "code" ? { area: target.area } : {}),
            },
        };
    });
    return {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "Hard Keel Quantum Scan",
                        organization: "Hard Keel",
                        version: toolVersion,
                        semanticVersion: toolVersion,
                        informationUri: HELP_URI,
                        rules: [...rules.values()].map((r) => r.rule),
                    },
                },
                columnKind: "utf16CodeUnits",
                results,
                ...(opts.score ? { properties: { readinessGrade: opts.score.grade, readinessScore: opts.score.score } } : {}),
            },
        ],
    };
}
