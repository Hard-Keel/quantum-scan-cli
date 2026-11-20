// The encryption map report: text for the terminal, one self-contained HTML page, and JSON.
// Written to the customer's own disk. Nothing here is sent anywhere.

import { TIER_NOTES, TIER_TITLES, type AreaResult, type MapFinding, type MapStrength, type Tier } from "./map-types.ts";

export interface MapReport {
  tool: "hard-keel-quantum-scan";
  version: string;
  createdAt: string;
  areas: { area: string; checked: number; skipped: { target: string; reason: string }[]; errors: { target: string; kind: string; message: string }[] }[];
  counts: Record<Tier, number>;
  findings: MapFinding[];
  strengths: MapStrength[];
}

const AREA_TITLES: Record<string, string> = { code: "Code and config", web: "Websites and public services", host: "This machine", network: "Internal network", vpn: "VPNs", cloud: "Cloud" };

export function buildMapReport(results: AreaResult[], ranked: MapFinding[], version: string, now = new Date()): MapReport {
  const counts = { 1: 0, 2: 0, 3: 0, 4: 0 } as Record<Tier, number>;
  for (const f of ranked) counts[f.tier!]++;
  return {
    tool: "hard-keel-quantum-scan",
    version,
    createdAt: now.toISOString(),
    areas: results.map((r) => ({ area: r.area, checked: r.checked.length, skipped: r.skipped, errors: r.errors.map(({ target, kind, message }) => ({ target, kind, message })) })),
    counts,
    findings: ranked,
    strengths: results.flatMap((r) => r.strengths),
  };
}

export function mapText(r: MapReport): string {
  const out = ["Hard Keel Quantum Scan · encryption map", ""];
  for (const a of r.areas) {
    const bits = [`${a.checked} checked`];
    if (a.skipped.length) bits.push(`${a.skipped.length} skipped`);
    if (a.errors.length) bits.push(`${a.errors.length} couldn't be reached`);
    out.push(`  ${AREA_TITLES[a.area] ?? a.area}: ${bits.join(", ")}`);
  }
  const total = r.findings.length;
  out.push("", total ? `${total} finding${total === 1 ? "" : "s"}, ranked by what breaks first.` : "Nothing found in the areas checked.");
  for (const t of [1, 2, 3, 4] as Tier[]) {
    const list = r.findings.filter((f) => f.tier === t);
    if (!list.length) continue;
    out.push("", `${t}. ${TIER_TITLES[t]} (${list.length})`, `   ${TIER_NOTES[t]}`);
    for (const f of list.slice(0, 25)) out.push(`   ${f.target}  ${f.title}`, `      ${f.fix}`);
    if (list.length > 25) out.push(`   ...and ${list.length - 25} more in the report.`);
  }
  if (r.strengths.length) {
    out.push("", `Already quantum-safe (${r.strengths.length})`);
    for (const s of r.strengths.slice(0, 10)) out.push(`   ${s.target}  ${s.title}`);
  }
  const skipped = r.areas.flatMap((a) => a.skipped);
  if (skipped.length) {
    out.push("", "Skipped");
    for (const s of skipped.slice(0, 10)) out.push(`   ${s.target}: ${s.reason}`);
  }
  return out.join("\n");
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export function mapHtml(r: MapReport, activity: string[]): string {
  const tiers = ([1, 2, 3, 4] as Tier[])
    .map((t) => {
      const list = r.findings.filter((f) => f.tier === t);
      if (!list.length) return "";
      const rows = list.map((f) => `<tr><td>${esc(AREA_TITLES[f.area] ?? f.area)}</td><td class="mono">${esc(f.target)}</td><td>${esc(f.title)}<div class="fix">${esc(f.fix)}</div></td></tr>`).join("");
      return `<section><h2><span class="n">${t}</span>${esc(TIER_TITLES[t])} <span class="count">${list.length}</span></h2><p class="note">${esc(TIER_NOTES[t])}</p><table><thead><tr><th>Area</th><th>Where</th><th>What and how to fix it</th></tr></thead><tbody>${rows}</tbody></table></section>`;
    })
    .join("");
  const strengths = r.strengths.length
    ? `<section><h2>Already quantum-safe <span class="count">${r.strengths.length}</span></h2><ul>${r.strengths.map((s) => `<li><span class="mono">${esc(s.target)}</span> ${esc(s.title)}</li>`).join("")}</ul></section>`
    : "";
  const areas = r.areas
    .map((a) => {
      const extra = [...a.skipped.map((s) => `${s.target}: ${s.reason}`), ...a.errors.map((e) => `${e.target}: couldn't check (${e.message})`)];
      return `<li><strong>${esc(AREA_TITLES[a.area] ?? a.area)}</strong>: ${a.checked} checked${extra.length ? `<ul>${extra.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</li>`;
    })
    .join("");
  const summary = ([1, 2, 3, 4] as Tier[]).map((t) => `<div class="tile t${t}"><div class="big">${r.counts[t]}</div><div>${esc(TIER_TITLES[t])}</div></div>`).join("");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Encryption map · Hard Keel Quantum Scan</title>
<style>
:root{--bg:#0a0e12;--fg:#eef2f5;--muted:#8f9da9;--accent:#5aa99d;--line:rgba(255,255,255,.09);--bad:#e07a6a;--warn:#e0b25a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 Inter,system-ui,-apple-system,sans-serif}
main{max-width:1000px;margin:0 auto;padding:40px 20px 80px}h1{font-size:28px;margin:0}h2{font-size:18px;margin:40px 0 4px;display:flex;align-items:center;gap:10px}
.eyebrow{font:12px "IBM Plex Mono",ui-monospace,monospace;letter-spacing:.3em;color:var(--accent);text-transform:uppercase}
.muted,.note{color:var(--muted)}.note{margin:0 0 12px}.n{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;border:1px solid var(--accent);color:var(--accent);font-size:13px}
.count{color:var(--muted);font-weight:400}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin:28px 0}
.tile{border:1px solid var(--line);border-radius:10px;padding:14px}.big{font-size:28px;font-weight:600}.t1 .big{color:var(--bad)}.t2 .big{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;padding:9px 8px;border-top:1px solid var(--line)}th{color:var(--muted);font-weight:500}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12.5px;word-break:break-all}.fix{color:var(--muted);margin-top:2px}
details{margin-top:40px}pre{white-space:pre-wrap;font-size:12px;color:var(--muted)}a{color:var(--accent)}
</style></head><body><main>
<div class="eyebrow">Hard Keel Quantum Scan</div><h1>Encryption map</h1>
<p class="muted">Created ${esc(r.createdAt.slice(0, 16).replace("T", " "))} UTC on this machine. This report stays on your computer unless you share it.</p>
<div class="tiles">${summary}</div>
${tiers || "<p>Nothing found in the areas checked.</p>"}
${strengths}
<section><h2>What was checked</h2><ul>${areas}</ul></section>
<details><summary>Activity log (${activity.length} entries)</summary><pre>${esc(activity.join("\n"))}</pre></details>
<p class="muted" style="margin-top:40px">Look-only checks: normal connections and local settings. No logins, changes or attack traffic. <a href="https://hardkeel.com/quantum-scan/">hardkeel.com</a></p>
</main></body></html>
`;
}
