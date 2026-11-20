// README badge for the quantum readiness score, in the familiar flat badge style.
// Self-contained SVG: no fonts, scripts or outside requests.

import type { Grade, ReadinessScore } from "./score.ts";

export const BADGE_LABEL = "quantum readiness";
const LABEL_BG = "#0b1726"; // Hard Keel navy

export const GRADE_COLOR: Record<Grade | "none", string> = {
  "A+": "#2e9e6a",
  A: "#44cc11",
  B: "#97ca00",
  C: "#dfb317",
  D: "#fe7d37",
  F: "#e05d44",
  none: "#9f9f9f",
};

// Rough Verdana 11px advance widths, enough to size the badge without loading a font.
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) {
    if ("iljI.,:;|!'".includes(ch)) w += 3.5;
    else if ("ftr( )".includes(ch)) w += ch === " " ? 3.9 : 4.6;
    else if ("mwMW".includes(ch)) w += 10.5;
    else if (/[A-Z+]/.test(ch)) w += 7.6;
    else if (/[0-9]/.test(ch)) w += 7;
    else if (ch === "·") w += 4.5;
    else w += 6.6;
  }
  return w;
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function badgeMessage(s: ReadinessScore | null): string {
  return s ? `${s.grade} · ${s.score}` : "not scanned";
}

export function badgeSvg(s: ReadinessScore | null, label = BADGE_LABEL): string {
  const message = badgeMessage(s);
  const color = s ? GRADE_COLOR[s.grade] : GRADE_COLOR.none;
  const lw = Math.round(textWidth(label) + 12);
  const mw = Math.round(textWidth(message) + 12);
  const w = lw + mw;
  const lx = lw / 2;
  const mx = lw + mw / 2;
  const title = `${label}: ${message}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(title)}"><title>${esc(title)}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="${lw}" height="20" fill="${LABEL_BG}"/><rect x="${lw}" width="${mw}" height="20" fill="${color}"/><rect width="${w}" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11"><text x="${lx}" y="15" fill="#010101" fill-opacity=".3">${esc(label)}</text><text x="${lx}" y="14">${esc(label)}</text><text x="${mx}" y="15" fill="#010101" fill-opacity=".3">${esc(message)}</text><text x="${mx}" y="14">${esc(message)}</text></g></svg>`;
}

/** The shields.io "endpoint" format, for people who prefer to style the badge themselves. */
export function shieldsEndpoint(s: ReadinessScore | null) {
  return { schemaVersion: 1, label: BADGE_LABEL, message: badgeMessage(s), color: s ? GRADE_COLOR[s.grade].slice(1) : "9f9f9f" };
}

export const METHOD_URL = "https://hardkeel.com/learn/quantum-readiness-score/";

/** Markdown a repository owner pastes into their README. */
export function badgeMarkdown(badgeUrl: string): string {
  return `[![Quantum readiness](${badgeUrl})](${METHOD_URL})`;
}
