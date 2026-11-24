// Pieces both SARIF outputs share, so GitHub code scanning and other tools rate and track findings the same way.
import { createHash } from "node:crypto";
/** GitHub reads properties["security-severity"] (0-10) to show Critical, High, Medium or Low. */
export const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0" };
/** Where each rule's help links to. */
export const HELP_URI = "https://hardkeel.com/quantum-scan/";
/**
 * Encryption quantum computers will break is safe today, so on GitHub it stays at Medium or below:
 * it belongs in the plan, not ahead of what is broken now.
 */
const QUANTUM_SEVERITY = { critical: "6.5", high: "6.0", medium: "5.0", low: "3.0" };
/** The 0-10 score for a finding: the usual scale, or the capped one for quantum-breakable encryption. */
export const securitySeverity = (risk, sev) => (risk === "quantum-vulnerable" ? QUANTUM_SEVERITY : SECURITY_SEVERITY)[sev];
const ORDER = ["critical", "high", "medium", "low"];
export const worstOf = (a, b) => (a && ORDER.indexOf(a) <= ORDER.indexOf(b) ? a : b);
/**
 * A fingerprint that stays the same when lines move, so a finding isn't reported as new after an
 * unrelated edit: rule, place, and which occurrence of that rule in that place it is. No code text goes in.
 */
export function fingerprints(items, key) {
    const seen = new Map();
    return items.map((t) => {
        const k = key(t);
        const n = (seen.get(k) ?? 0) + 1;
        seen.set(k, n);
        return { "hardkeel/v1": createHash("sha256").update(`${k}|${n}`).digest("hex").slice(0, 32) };
    });
}
