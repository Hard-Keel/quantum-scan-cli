// Community detection rules: plain JSON files in rules/community/, checked and bundled into
// src/community-rules.ts by scripts/build-rules.mjs. Contributors never touch TypeScript.
import { COMMUNITY_RULES } from "./community-rules.js";
export function compileRule(spec) {
    const a = spec.algorithm;
    return {
        id: spec.id,
        langs: ["any"],
        extensions: spec.extensions.map((e) => e.toLowerCase()),
        pattern: new RegExp(spec.pattern, spec.flags ?? ""),
        keySize: spec.keySize ? new RegExp(spec.keySize) : undefined,
        algorithm: typeof a === "string"
            ? a
            : (m) => {
                for (const g of a.groups)
                    if (m[g] !== undefined)
                        return a.map[m[g].toLowerCase()] ?? null;
                return null;
            },
    };
}
const COMPILED = COMMUNITY_RULES.map(compileRule);
/** Community rules that apply to this file, by extension. */
export function communityRulesFor(path) {
    const p = path.toLowerCase();
    return COMPILED.filter((r) => r.extensions.some((e) => p.endsWith(e)));
}
export const COMMUNITY_RULE_COUNT = COMPILED.length;
