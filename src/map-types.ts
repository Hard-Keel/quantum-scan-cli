// Types for the encryption map: one picture of encryption across code, websites and machines.

import type { AreaName, ErrorKind } from "./share.ts";
import type { Primitive, Risk, Severity } from "./types.ts";

/**
 * What breaks first.
 * 1 broken now: fix now.
 * 2 recorded now, read later: internet-facing key exchange, captured today and decrypted once quantum computers arrive.
 * 3 long-lived signatures: certificate authorities and other keys that must stay trusted for years. Plan by 2030.
 * 4 everything else that uses RSA or elliptic curves. Move by 2035.
 */
export type Tier = 1 | 2 | 3 | 4;

export const TIER_TITLES: Record<Tier, string> = {
  1: "Broken now",
  2: "Recorded now, read later",
  3: "Long-lived signatures",
  4: "Everything else",
};

export const TIER_NOTES: Record<Tier, string> = {
  1: "Weak today, without any quantum computer. Fix these first.",
  2: "Internet-facing key exchange with no quantum-safe option. Traffic recorded today can be decrypted once quantum computers arrive.",
  3: "Signatures that must stay trusted for years. NIST deprecates these methods after 2030.",
  4: "Uses RSA or elliptic-curve encryption. NIST disallows these after 2035.",
};

/**
 * How urgent one finding is, inside its tier, for people who want a plain rating.
 * High: broken now (unless minor), internet-facing key exchange, and signatures that must stay trusted for years.
 * Medium: other quantum-breakable encryption that faces the internet, lasts for years, or protects data that can be recorded or stored.
 * Low: the rest, mostly short-lived signatures inside your own systems.
 */
export type Rating = "high" | "medium" | "low";

export const RATING_TITLES: Record<Rating, string> = { high: "High", medium: "Medium", low: "Low" };

export interface MapFinding {
  area: AreaName;
  target: string; // where it was found. Stays on this machine; never shared.
  ruleId: string; // fixed identifier, safe to count
  title: string;
  algorithm: string;
  primitive: Primitive;
  risk: Risk;
  severity: Severity;
  fix: string;
  internetFacing: boolean;
  longLived?: boolean;
  keySize?: number;
  tier?: Tier;
  rating?: Rating;
}

/** Something already quantum-safe, so customers see progress, not only problems. */
export interface MapStrength {
  area: AreaName;
  target: string;
  algorithm: string; // one of share.ts PQC_NAMES
  title: string;
}

export interface MapError {
  area: AreaName;
  target: string;
  kind: ErrorKind;
  message: string; // local report only
}

export interface AreaResult {
  area: AreaName;
  findings: MapFinding[];
  strengths: MapStrength[];
  errors: MapError[];
  checked: string[]; // targets looked at
  skipped: { target: string; reason: string }[];
}

export function emptyResult(area: AreaName): AreaResult {
  return { area, findings: [], strengths: [], errors: [], checked: [], skipped: [] };
}
