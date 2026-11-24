// Human-readable output: pull request comment, check-run annotations, migration report.
import { gradeSentence } from "./score.js";
export const COMMENT_MARKER = "<!-- hardkeel-quantum-scan -->";
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
export function sortFindings(fs) {
    return [...fs].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.file.localeCompare(b.file) || a.line - b.line);
}
function counts(fs) {
    return {
        secrets: fs.filter((f) => f.risk === "secret").length,
        weak: fs.filter((f) => f.risk === "weak-now").length,
        quantum: fs.filter((f) => f.risk === "quantum-vulnerable").length,
        exposed: fs.filter((f) => f.risk === "exposed").length,
    };
}
function riskLabel(f) {
    if (f.risk === "secret")
        return "Leaked key or password";
    if (f.risk === "weak-now")
        return "Weak today";
    if (f.risk === "exposed")
        return "Exposed setting";
    return "Quantum-vulnerable";
}
function esc(s) {
    return s.replace(/\|/g, "\\|").replace(/`/g, "'");
}
/** Conclusion for the GitHub check run. Secrets and weak crypto fail; quantum-only is neutral. */
export function checkConclusion(fs, blockOnQuantum = false) {
    const c = counts(fs);
    if (c.secrets || c.weak || c.exposed)
        return "failure";
    if (c.quantum)
        return blockOnQuantum ? "failure" : "neutral";
    return "success";
}
export function prSummaryLine(fs) {
    const c = counts(fs);
    if (!fs.length)
        return "No leaked keys or passwords, weak encryption, exposed infrastructure settings, or encryption quantum computers will break in this change.";
    const parts = [];
    if (c.secrets)
        parts.push(`${c.secrets} leaked key${c.secrets > 1 ? "s or passwords" : " or password"}`);
    if (c.weak)
        parts.push(`${c.weak} use${c.weak > 1 ? "s" : ""} of weak encryption`);
    if (c.exposed)
        parts.push(`${c.exposed} exposed infrastructure setting${c.exposed > 1 ? "s" : ""}`);
    if (c.quantum)
        parts.push(`${c.quantum} use${c.quantum > 1 ? "s" : ""} of encryption quantum computers will break`);
    return `This change adds ${parts.length > 1 ? parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1] : parts[0]}.`;
}
const LOGO = "https://avatars.githubusercontent.com/in/5838578?s=64";
/** Short name for a finding, like "MD5 hash" or "RSA-1024 key". */
export function shortLabel(f) {
    const a = f.algorithm;
    if (f.kind === "config" && a === "Open to the internet")
        return f.title; // names the ports, like "SSH (22) open to the whole internet"
    if (f.risk === "secret" || f.kind === "config")
        return a;
    if (a.startsWith("RSA") && f.keySize !== undefined && f.keySize < 2048)
        return `RSA-${f.keySize} key`;
    if (a === "RSA")
        return "RSA key";
    if (a === "EC")
        return "Elliptic-curve key";
    if (/(mode|signature|encryption|exchange)$/.test(a) || a.startsWith("TLS"))
        return a;
    const noun = {
        hash: "hash",
        "block-cipher": "cipher",
        "stream-cipher": "cipher",
        signature: "signature",
        "key-agreement": "key exchange",
        "public-key-encryption": "encryption",
    };
    return noun[f.primitive] ? `${a} ${noun[f.primitive]}` : a;
}
function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
}
/** The comment's bold first line. */
export function prHeadline(fs) {
    const now = fs.filter((f) => f.risk !== "quantum-vulnerable").length;
    const later = fs.length - now;
    if (!fs.length)
        return "**Nothing to fix.** No leaked keys, weak or quantum-breakable encryption, or exposed infrastructure settings in this change.";
    if (!now)
        return `**Nothing blocks this merge.** ${plural(later, "item", "items")} to plan for, below.`;
    return `**${plural(now, "problem", "problems")} to fix before merging.**` + (later ? ` ${plural(later, "more item", "more items")} to plan for.` : "");
}
export function prComment(fs, opts = {}) {
    const max = opts.maxRows ?? 25;
    const sorted = sortFindings(fs).slice(0, max);
    const where = (f) => {
        const label = `\`${esc(f.file)}:${f.line}\``;
        return opts.repo && opts.sha ? `[${label}](https://github.com/${opts.repo}/blob/${opts.sha}/${encodeURI(f.file)}#L${f.line})` : label;
    };
    const table = (rows) => [
        "| Where | Issue | Fix |",
        "| --- | --- | --- |",
        ...rows.map((f) => `| ${where(f)} | ${esc(shortLabel(f))} | ${esc(f.fix)} |`),
    ];
    const now = sorted.filter((f) => f.risk !== "quantum-vulnerable");
    const later = sorted.filter((f) => f.risk === "quantum-vulnerable");
    const lines = [
        COMMENT_MARKER,
        `### <img src="${LOGO}" width="20" height="20" alt=""> Hard Keel Quantum Scan`,
        "",
        prHeadline(fs),
    ];
    if (now.length)
        lines.push("", "#### Fix before merging", "", ...table(now));
    if (later.length) {
        lines.push("", "#### Plan for later", "", "Safe today, but quantum computers will be able to break these. NIST plans to phase them out between 2030 and 2035.", "", ...table(later));
    }
    if (fs.length > max)
        lines.push("", `${fs.length - max} more are listed in the check results.`);
    if (opts.reportUrl) {
        lines.push("", `**[Open the full report](${opts.reportUrl})** to see every use of encryption in this repository and the order to fix them in.`);
    }
    lines.push("", "<sub>Hard Keel · hardkeel.com · Questions: contact@hardkeel.com</sub>");
    return lines.join("\n");
}
export function annotations(fs) {
    return sortFindings(fs).map((f) => ({
        path: f.file,
        start_line: f.line,
        end_line: f.line,
        annotation_level: f.risk === "quantum-vulnerable" ? "warning" : "failure",
        title: `${riskLabel(f)}: ${f.title}`,
        message: f.fix,
    }));
}
/** Group a full-repo scan by algorithm and rank by what to migrate first. */
export function migrationPlan(fs) {
    const map = new Map();
    for (const f of fs)
        map.set(`${f.risk}|${f.algorithm}`, [...(map.get(`${f.risk}|${f.algorithm}`) ?? []), f]);
    const groups = [...map.values()].map((g) => {
        const f = g[0];
        let priority = 4;
        let when = "Before 2035";
        if (f.risk === "secret")
            [priority, when] = [0, "Now"];
        else if (f.risk === "exposed")
            [priority, when] = [1, "Now"];
        else if (f.risk === "weak-now")
            [priority, when] = [1, "Now"];
        else if (f.primitive === "key-agreement" || f.primitive === "public-key-encryption")
            [priority, when] = [2, "By 2030"];
        else
            [priority, when] = [3, "By 2030 to 2035"];
        return { algorithm: f.algorithm, risk: f.risk, count: g.length, files: [...new Set(g.map((x) => x.file))], fix: f.fix, priority, when };
    });
    return groups.sort((a, b) => a.priority - b.priority || b.count - a.count);
}
export function migrationReportMarkdown(repo, fs, scannedAt, score) {
    const plan = migrationPlan(fs);
    const c = counts(fs);
    const out = [
        `# Quantum readiness report: ${repo}`,
        "",
        ...(score ? [`**${gradeSentence(score)}** How the score works: https://hardkeel.com/learn/quantum-readiness-score/`, ""] : []),
        `Scanned ${scannedAt}. ${c.quantum} use${c.quantum === 1 ? "" : "s"} of encryption quantum computers will break, ${c.weak} of weak encryption, ${c.exposed} exposed infrastructure setting${c.exposed === 1 ? "" : "s"}, and ${c.secrets} leaked key${c.secrets === 1 ? "" : "s"} or password${c.secrets === 1 ? "" : "s"}.`,
        "",
        "NIST's final transition plan (IR 8547, October 2026) deprecates today's public-key algorithms (RSA, elliptic curve, Diffie-Hellman) after 2030 and disallows them after 2035. Key exchange comes first, because encrypted traffic recorded today can be decrypted once a large quantum computer exists.",
        "",
        "| Order | What | Uses | Files | When | Move to |",
        "| --- | --- | --- | --- | --- | --- |",
    ];
    plan.forEach((g, i) => {
        const files = g.files.slice(0, 3).map((f) => `\`${esc(f)}\``).join(", ") + (g.files.length > 3 ? ` +${g.files.length - 3}` : "");
        out.push(`| ${i + 1} | ${esc(g.algorithm)} | ${g.count} | ${files} | ${g.when} | ${esc(g.fix)} |`);
    });
    if (!plan.length)
        out.push("| | Nothing found | | | | |");
    out.push("", "This report lists what the scanner found in source code and infrastructure config in the repository. It does not cover compiled dependencies, running services or certificates in use. Hard Keel can assess those separately.");
    return out.join("\n");
}
