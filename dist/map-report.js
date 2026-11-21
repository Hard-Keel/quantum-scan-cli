// The encryption map report: text for the terminal, one self-contained HTML page, and JSON.
// Written to the customer's own disk. Nothing here is sent anywhere.
import { TIER_NOTES, TIER_TITLES } from "./map-types.js";
import { toFinding } from "./map-rank.js";
import { gradeSentence, readinessScore } from "./score.js";
/** Post-quantum methods already in use count toward the score the same way they do in a code scan. */
function strengthSignals(strengths) {
    return strengths.map((s) => ({ algorithm: s.algorithm, use: /DSA/.test(s.algorithm) ? "signature" : "key-establishment", file: s.target, line: 0 }));
}
const AREA_TITLES = { code: "Code and config", web: "Websites and public services", host: "This machine", network: "Network and equipment", vpn: "VPNs", cloud: "Cloud" };
export function buildMapReport(results, ranked, version, now = new Date(), accepted = [], extras = { cloudKeys: [], people: null }) {
    const strengths = results.flatMap((r) => r.strengths);
    const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
    for (const f of ranked)
        counts[f.tier]++;
    return {
        tool: "hard-keel-quantum-scan",
        version,
        createdAt: now.toISOString(),
        areas: results.map((r) => ({ area: r.area, checked: r.checked.length, skipped: r.skipped, errors: r.errors.map(({ target, kind, message }) => ({ target, kind, message })) })),
        score: readinessScore(ranked.map(toFinding), strengthSignals(strengths)),
        counts,
        findings: ranked,
        strengths,
        accepted,
        cloudKeys: extras.cloudKeys,
        people: extras.people,
    };
}
export function peopleSentence(p) {
    return `People and process: ${p.inPlace} of ${p.answered} in place (${p.score}/100), answered ${p.answeredAt}.`;
}
const custodyCount = (r, c) => r.cloudKeys.filter((a) => a.custody === c).length;
/** A grade only means something when at least one place was actually checked. */
export const nothingChecked = (r) => !r.areas.some((a) => a.checked > 0) && !r.findings.length && !r.strengths.length;
const NOT_GRADED = "Quantum readiness: not graded, because nothing was checked.";
export function mapText(r) {
    const out = ["Hard Keel Quantum Scan · encryption map", "", nothingChecked(r) ? NOT_GRADED : gradeSentence(r.score)];
    if (r.people)
        out.push(peopleSentence(r.people));
    if (r.areas.length)
        out.push("");
    for (const a of r.areas) {
        const bits = [`${a.checked} checked`];
        if (a.skipped.length)
            bits.push(`${a.skipped.length} skipped`);
        if (a.errors.length)
            bits.push(`${a.errors.length} couldn't be checked`);
        out.push(`  ${AREA_TITLES[a.area] ?? a.area}: ${bits.join(", ")}`);
    }
    const total = r.findings.length;
    out.push("", total ? `${total} finding${total === 1 ? "" : "s"}, ranked by what breaks first.` : nothingChecked(r) ? "No scan areas were checked this time." : "Nothing found in the areas checked.");
    for (const t of [1, 2, 3, 4]) {
        const list = r.findings.filter((f) => f.tier === t);
        if (!list.length)
            continue;
        out.push("", `${t}. ${TIER_TITLES[t]} (${list.length})`, `   ${TIER_NOTES[t]}`);
        for (const f of list.slice(0, 25))
            out.push(`   ${f.target}  ${f.title}`, `      ${f.fix}`);
        if (list.length > 25)
            out.push(`   ...and ${list.length - 25} more in the report.`);
    }
    if (r.strengths.length) {
        out.push("", `Already quantum-safe (${r.strengths.length})`);
        for (const s of r.strengths.slice(0, 10))
            out.push(`   ${s.target}  ${s.title}`);
    }
    if (r.cloudKeys.length) {
        const prov = custodyCount(r, "provider");
        out.push("", `Who can read your cloud data (${r.cloudKeys.length}), advice, not scored`);
        out.push(`   ${prov} with keys the provider holds, ${r.cloudKeys.length - prov} with keys in the provider's key service.`);
        for (const a of r.cloudKeys.slice(0, 10))
            out.push(`   ${a.target}  ${a.resource}: ${a.title}`);
        if (r.cloudKeys.length > 10)
            out.push(`   ...and ${r.cloudKeys.length - 10} more in the report.`);
        out.push(`   ${r.cloudKeys.find((a) => a.custody === "provider")?.fix ?? r.cloudKeys[0].fix}`);
    }
    if (r.people?.gaps.length) {
        out.push("", `People and process gaps (${r.people.gaps.length})`);
        for (const g of r.people.gaps.slice(0, 12))
            out.push(`   ${g.answer === "no" ? "No" : "Not sure"}: ${g.question}`, `      ${g.fix}`);
    }
    if (r.accepted.length) {
        out.push("", `Accepted as known leftovers (${r.accepted.length}), from ${".quantum-scan-ignore"}; not counted in the score`);
        for (const f of r.accepted.slice(0, 10))
            out.push(`   ${f.target}  ${f.title}`);
    }
    const errors = r.areas.flatMap((a) => a.errors);
    if (errors.length) {
        out.push("", "Couldn't check");
        for (const e of errors.slice(0, 10))
            out.push(`   ${e.target}: ${e.message}`);
        if (errors.length > 10)
            out.push(`   ...and ${errors.length - 10} more in the report.`);
    }
    const skipped = r.areas.flatMap((a) => a.skipped);
    if (skipped.length) {
        out.push("", "Skipped");
        for (const s of skipped.slice(0, 10))
            out.push(`   ${s.target}: ${s.reason}`);
        if (skipped.length > 10)
            out.push(`   ...and ${skipped.length - 10} more in the report.`);
    }
    return out.join("\n");
}
const esc = (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
export function mapHtml(r, activity) {
    const row = (f) => `<tr><td class="area">${esc(AREA_TITLES[f.area] ?? f.area)}</td><td class="mono">${esc(f.target)}</td><td>${esc(f.title)}<div class="fix">${esc(f.fix)}</div></td></tr>`;
    const table = (list) => `<table><thead><tr><th class="area">Area</th><th>Where</th><th>What and how to fix it</th></tr></thead><tbody>${list.map(row).join("")}</tbody></table>`;
    const tiers = [1, 2, 3, 4]
        .map((t) => {
        const list = r.findings.filter((f) => f.tier === t);
        if (!list.length)
            return "";
        return `<section><h2><span class="n">${t}</span>${esc(TIER_TITLES[t])} <span class="count">${list.length}</span></h2><p class="note">${esc(TIER_NOTES[t])}</p>${table(list)}</section>`;
    })
        .join("");
    const strengths = r.strengths.length
        ? `<section><h2>Already quantum-safe <span class="count">${r.strengths.length}</span></h2><ul>${r.strengths.map((s) => `<li><span class="mono">${esc(s.target)}</span> ${esc(s.title)}</li>`).join("")}</ul></section>`
        : "";
    const accepted = r.accepted.length
        ? `<section><h2>Accepted as known leftovers <span class="count">${r.accepted.length}</span></h2><p class="note">Marked in .quantum-scan-ignore. Listed here so nothing is hidden, but left out of the counts and the score.</p>${table(r.accepted)}</section>`
        : "";
    const cloud = r.cloudKeys.length
        ? `<section><h2>Who can read your cloud data <span class="count">${r.cloudKeys.length}</span></h2><p class="note">Advice, not scored. Keys held by a cloud provider protect against a stolen disk, not against the provider, someone working there, or a legal demand made to them. ${custodyCount(r, "provider")} ${custodyCount(r, "provider") === 1 ? "uses" : "use"} keys the provider holds; ${custodyCount(r, "provider-kms")} ${custodyCount(r, "provider-kms") === 1 ? "uses" : "use"} keys in the provider's key service.</p><table><thead><tr><th>Where</th><th>What and how to fix it</th></tr></thead><tbody>${r.cloudKeys.map((a) => `<tr><td class="mono">${esc(a.target)}<div class="fix">${esc(a.resource)}</div></td><td>${esc(a.title)}<div class="fix">${esc(a.fix)}</div></td></tr>`).join("")}</tbody></table></section>`
        : "";
    const p = r.people;
    const people = p
        ? `<section><h2>People and process <span class="count">${p.inPlace} of ${p.answered} in place</span></h2><p class="note">Your own answers from ${esc(p.answeredAt)}, scored on their own. They stay on this machine and are never shared.</p>${p.gaps.length
            ? `<table><thead><tr><th class="area">Group</th><th>Answer</th><th>Question and what to do</th></tr></thead><tbody>${p.gaps.map((g) => `<tr><td class="area">${esc(g.group)}</td><td>${g.answer === "no" ? "No" : "Not sure"}</td><td>${esc(g.question)}<div class="fix">${esc(g.fix)}</div></td></tr>`).join("")}</tbody></table>`
            : "<p>Everything you answered is in place.</p>"}</section>`
        : "";
    const areas = r.areas
        .map((a) => {
        const extra = [...a.skipped.map((s) => `${s.target}: ${s.reason}`), ...a.errors.map((e) => `${e.target}: couldn't check (${e.message})`)];
        return `<li><strong>${esc(AREA_TITLES[a.area] ?? a.area)}</strong>: ${a.checked} checked${extra.length ? `<ul>${extra.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</li>`;
    })
        .join("");
    const summary = [1, 2, 3, 4].map((t) => `<div class="tile t${t}"><div class="big">${r.counts[t]}</div><div>${esc(TIER_TITLES[t])}</div></div>`).join("");
    const g = r.score;
    const gradeClass = g.grade.startsWith("A") ? "good" : g.grade === "B" ? "ok" : "bad";
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Encryption map · Hard Keel Quantum Scan</title>
<style>
:root{--bg:#ffffff;--fg:#111a21;--muted:#5b6873;--accent:#2f7d71;--line:rgba(0,0,0,.1);--bad:#b4412f;--warn:#93630f;--good:#2f7d71}
@media (prefers-color-scheme:dark){:root{--bg:#0a0e12;--fg:#eef2f5;--muted:#8f9da9;--accent:#5aa99d;--line:rgba(255,255,255,.09);--bad:#e07a6a;--warn:#e0b25a;--good:#5aa99d}}
@media print{:root{--bg:#fff;--fg:#000;--muted:#444;--accent:#2f7d71;--line:#ccc;--bad:#a0301f;--warn:#7a520c;--good:#2f7d71}details{display:none}section{break-inside:auto}tr{break-inside:avoid}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 Inter,system-ui,-apple-system,sans-serif}
main{max-width:1000px;margin:0 auto;padding:40px 20px 80px}h1{font-size:28px;margin:0}h2{font-size:18px;margin:40px 0 4px;display:flex;align-items:center;gap:10px}
.eyebrow{font:12px "IBM Plex Mono",ui-monospace,monospace;letter-spacing:.3em;color:var(--accent);text-transform:uppercase}
.muted,.note{color:var(--muted)}.note{margin:0 0 12px}.n{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;border:1px solid var(--accent);color:var(--accent);font-size:13px;flex:none}
.count{color:var(--muted);font-weight:400}.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:20px 0 28px}
.tile{border:1px solid var(--line);border-radius:10px;padding:14px}.big{font-size:28px;font-weight:600}.t1 .big{color:var(--bad)}.t2 .big{color:var(--warn)}
.score{display:flex;gap:18px;align-items:center;border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin-top:28px}
.grade{font-size:40px;font-weight:700;line-height:1;min-width:64px;text-align:center}.grade.good{color:var(--good)}.grade.ok{color:var(--warn)}.grade.bad{color:var(--bad)}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;vertical-align:top;padding:9px 8px;border-top:1px solid var(--line)}th{color:var(--muted);font-weight:500}
.mono{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:12.5px;word-break:break-all}.fix{color:var(--muted);margin-top:2px}
details{margin-top:40px}pre{white-space:pre-wrap;font-size:12px;color:var(--muted)}a{color:var(--accent)}
@media (max-width:640px){.area{display:none}td.mono{width:38%}h1{font-size:24px}.grade{font-size:32px;min-width:48px}}
</style></head><body><main>
<div class="eyebrow">Hard Keel Quantum Scan</div><h1>Encryption map</h1>
<p class="muted">Created ${esc(r.createdAt.slice(0, 16).replace("T", " "))} UTC on this machine. This report stays on your computer unless you share it.</p>
${nothingChecked(r) ? `<div class="score"><div class="grade">–</div><div><strong>Quantum readiness not graded</strong><div class="muted">Nothing was checked, so there is nothing to grade.</div></div></div>` : `<div class="score"><div class="grade ${gradeClass}">${esc(g.grade)}</div><div><strong>Quantum readiness ${g.score}/100</strong><div class="muted">${esc(gradeSentence(g).replace(/^Quantum readiness: [^.]+\.\s*/, ""))} Hard Keel method v${esc(g.method)}, the same as a code scan, across every area checked.</div></div></div>`}
${p ? `<div class="score"><div class="grade ${p.score >= 90 ? "good" : p.score >= 60 ? "ok" : "bad"}">${p.score}</div><div><strong>People and process ${p.inPlace} of ${p.answered} in place</strong><div class="muted">From your answers to the checklist, scored on their own. Phishing, accounts, equipment, separation, data and what happens on a bad day.</div></div></div>` : ""}
<div class="tiles">${summary}</div>
${tiers || "<p>Nothing found in the areas checked.</p>"}
${strengths}
${cloud}
${people}
${accepted}
<section><h2>What was checked</h2><ul>${areas}</ul></section>
<details><summary>Activity log (${activity.length} entries)</summary><pre>${esc(activity.join("\n"))}</pre></details>
<p class="muted" style="margin-top:40px">Look-only checks: normal connections and local settings. No logins, changes or attack traffic. <a href="https://hardkeel.com/quantum-scan/">hardkeel.com</a></p>
</main></body></html>
`;
}
