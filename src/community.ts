// Community detection rules: plain JSON files in rules/community/, checked and bundled into
// src/community-rules.ts by scripts/build-rules.mjs. Contributors never touch TypeScript.

import type { CryptoRule } from "./rules.ts";
import { COMMUNITY_RULES } from "./community-rules.ts";

export interface AlgorithmMap {
  groups: number[]; // regex groups to read, first one that matched wins
  map: Record<string, string>; // lowercased group text -> algorithm name in ALGORITHMS
}

export interface CommunityRuleSpec {
  id: string;
  title: string;
  extensions: string[]; // like [".rs"]
  pattern: string; // regular expression source
  flags?: string; // only "i" is allowed
  algorithm: string | AlgorithmMap;
  keySize?: string; // regex whose first group is a key size in bits
}

export function compileRule(spec: CommunityRuleSpec): CryptoRule & { extensions: string[] } {
  const a = spec.algorithm;
  return {
    id: spec.id,
    langs: ["any"],
    extensions: spec.extensions.map((e) => e.toLowerCase()),
    pattern: new RegExp(spec.pattern, spec.flags ?? ""),
    keySize: spec.keySize ? new RegExp(spec.keySize) : undefined,
    algorithm:
      typeof a === "string"
        ? a
        : (m: RegExpMatchArray) => {
            for (const g of a.groups) if (m[g] !== undefined) return a.map[m[g].toLowerCase()] ?? null;
            return null;
          },
  };
}

const COMPILED = COMMUNITY_RULES.map(compileRule);

/** Community rules that apply to this file, by extension. */
export function communityRulesFor(path: string): CryptoRule[] {
  const p = path.toLowerCase();
  return COMPILED.filter((r) => r.extensions.some((e) => p.endsWith(e)));
}

export const COMMUNITY_RULE_COUNT = COMPILED.length;
