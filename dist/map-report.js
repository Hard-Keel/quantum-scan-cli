// The encryption map report: text for the terminal, one self-contained HTML page, and JSON.
// Written to the customer's own disk. Nothing here is sent anywhere.
import { RATING_TITLES, TIER_NOTES, TIER_TITLES } from "./map-types.js";
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
    const ratings = { high: 0, medium: 0, low: 0 };
    for (const f of ranked)
        ratings[f.rating ?? "low"]++;
    return {
        tool: "hard-keel-quantum-scan",
        version,
        createdAt: now.toISOString(),
        areas: results.map((r) => ({ area: r.area, checked: r.checked.length, skipped: r.skipped, errors: r.errors.map(({ target, kind, message }) => ({ target, kind, message })) })),
        score: readinessScore(ranked.map(toFinding), strengthSignals(strengths)),
        counts,
        ratings,
        findings: ranked,
        strengths,
        accepted,
        cloudKeys: extras.cloudKeys,
        people: extras.people,
    };
}
/** "3 high, 2 medium, 1 low", leaving out any that are zero. */
export function ratingsLine(r) {
    return ["high", "medium", "low"].filter((k) => r.ratings[k]).map((k) => `${r.ratings[k]} ${k}`).join(", ");
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
    out.push("", total ? `${total} finding${total === 1 ? "" : "s"} (${ratingsLine(r)}), ranked by what breaks first.` : nothingChecked(r) ? "No scan areas were checked this time." : "Nothing found in the areas checked.");
    for (const t of [1, 2, 3, 4]) {
        const list = r.findings.filter((f) => f.tier === t);
        if (!list.length)
            continue;
        out.push("", `${t}. ${TIER_TITLES[t]} (${list.length})`, `   ${TIER_NOTES[t]}`);
        for (const f of list.slice(0, 25))
            out.push(`   [${RATING_TITLES[f.rating ?? "low"]}] ${f.target}  ${f.title}`, `      ${f.fix}`);
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
/** The locked Hard Keel lockup: teal rings and the Inter wordmark, outlined to shapes so it renders the same offline, with no font.
 * Colors are plain attributes (CSS variables don't work in SVG attributes). The wordmark takes the text color, as on hardkeel.com. */
const LOGO = `<svg class="logo" viewBox="0 0 472 72" role="img" aria-label="Hard Keel"><g class="rings" transform="scale(1.125)" fill="none" stroke="#5aa99d" stroke-width="2.2" stroke-linecap="round"><path d="M 53.01 41.35 A 23 23 0 1 1 24.13 10.39"/><path d="M 17.43 26.70 A 15.5 15.5 0 1 1 40.89 44.70"/><path d="M 29.37 40.08 A 8.5 8.5 0 1 1 36.25 24.64"/></g><g class="dots" transform="scale(1.125)" fill="#5aa99d"><circle cx="32" cy="32" r="2.2"/><circle cx="53.01" cy="41.35" r="1.8"/><circle cx="17.43" cy="26.70" r="1.6"/><circle cx="29.37" cy="40.08" r="1.4"/></g><g class="wm" transform="translate(100,56) scale(0.02685,-0.02685)" fill="currentColor"><path d="M150 0H417V649H1110V0H1377V1490H1110V874H417V1490H150ZM1863 0H2155L2277 369H2834L2961 0H3254L2722 1490H2383ZM2348 584 2411 774C2452 907 2497 1074 2550 1282C2605 1076 2652 911 2696 774L2761 584ZM3739 0H4006V547H4284L4577 0H4876L4553 592C4729 662 4821 811 4821 1013C4821 1297 4639 1490 4296 1490H3739ZM4006 768V1266H4255C4458 1266 4548 1172 4548 1013C4548 855 4458 768 4257 768ZM5865 0C6319 0 6586 281 6586 747C6586 1210 6319 1490 5875 1490H5361V0ZM5628 231V1259H5859C6164 1259 6323 1088 6323 747C6323 403 6164 231 5852 231ZM8053 0H8320V447L8523 668L8975 0H9290L8708 845L9280 1490H8948L8557 1044C8459 930 8386 836 8316 729L8320 1048V1490H8053ZM9779 0H10751V225H10046V641H10695V863H10046V1265H10747V1490H9779ZM11305 0H12277V225H11572V641H12221V863H11572V1265H12273V1490H11305ZM12831 0H13756V225H13098V1490H12831Z"/></g></svg>`;
const ORDER = { high: 0, medium: 1, low: 2 };
const pill = (r) => (r ? `<span class="rate ${r}">${RATING_TITLES[r]}</span>` : "");
export function groupFindings(list) {
    const groups = new Map();
    for (const f of list) {
        const key = `${f.area}\u0000${f.ruleId}\u0000${f.title}\u0000${f.fix}`;
        const g = groups.get(key) ?? { area: AREA_TITLES[f.area] ?? f.area, title: f.title, fix: f.fix, targets: [], rating: f.rating };
        g.targets.push(f.target);
        if (f.rating && (!g.rating || ORDER[f.rating] < ORDER[g.rating]))
            g.rating = f.rating; // a group is as urgent as its most urgent place
        groups.set(key, g);
    }
    return [...groups.values()];
}
const MAX_PLACES = 40;
const places = (targets) => {
    const shown = targets.slice(0, MAX_PLACES).map((t) => `<span>${esc(t)}</span>`).join("");
    const more = targets.length > MAX_PLACES ? `<span class="more">and ${targets.length - MAX_PLACES} more, listed in map.json</span>` : "";
    return `<div class="places">${shown}${more}</div>`;
};
const item = (g, num) => `<article class="item"><div class="num">${num}</div><div class="body"><h3>${esc(g.title)}</h3><div class="meta">${pill(g.rating)}${esc(g.area)}${g.targets.length > 1 ? ` · ${g.targets.length} places` : ""}</div>${places(g.targets)}<p class="fix"><span class="label">How to fix</span>${esc(g.fix)}</p></div></article>`;
const plural = (n, one, many = one + "s") => `${n} ${n === 1 ? one : many}`;
const longDate = (iso) => new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
export function mapHtml(r, activity) {
    const g = r.score;
    const graded = !nothingChecked(r);
    const tone = (grade) => (grade.startsWith("A") ? "good" : grade === "B" ? "ok" : "bad");
    const byTier = [1, 2, 3, 4].map((t) => ({ t, groups: groupFindings(r.findings.filter((f) => f.tier === t)) }));
    const total = r.findings.length;
    const issues = byTier.reduce((n, x) => n + x.groups.length, 0);
    const verdict = graded
        ? `<div class="verdict"><div class="badge ${tone(g.grade)}">${esc(g.grade)}</div><div><div class="score">Quantum readiness <strong>${g.score}</strong><span class="of">/100</span></div><p>${esc(gradeSentence(g).replace(/^Quantum readiness: [^.]+\.\s*/, ""))}</p></div></div>`
        : `<div class="verdict"><div class="badge">–</div><div><div class="score">Quantum readiness not graded</div><p>Nothing was checked, so there is nothing to grade.</p></div></div>`;
    const p = r.people;
    const peopleVerdict = p
        ? `<div class="verdict small"><div class="badge ${p.score >= 90 ? "good" : p.score >= 60 ? "ok" : "bad"}">${p.score}</div><div><div class="score">People and process <strong>${p.inPlace}</strong><span class="of"> of ${p.answered} in place</span></div><p>From your own answers to the checklist, scored on their own.</p></div></div>`
        : "";
    const stats = `<div class="stats">${byTier.map(({ t }) => `<div class="stat t${t}"><div class="n">${r.counts[t]}</div><div class="k">${esc(TIER_TITLES[t])}</div></div>`).join("")}</div>`;
    const ratingLine = total ? `<p class="scope"><span class="label">Rated</span>${["high", "medium", "low"].map((k) => `${pill(k)} ${r.ratings[k]}`).join(" &nbsp; ")}</p>` : "";
    const checkedLine = r.areas.length
        ? `<p class="scope"><span class="label">Checked</span>${r.areas.map((a) => `${esc(AREA_TITLES[a.area] ?? a.area)} (${a.checked})`).join(" · ")}</p>`
        : "";
    const first = byTier.flatMap(({ t, groups }) => groups.map((x, i) => ({ x, num: `${t}.${i + 1}` }))).slice(0, 3);
    const firstSection = first.length
        ? `<section class="first"><h2>Start here</h2><p class="note">The ${first.length === 1 ? "most urgent item" : `${first.length} most urgent items`}. Everything else is ranked below.</p><ol>${first.map(({ x, num }) => `<li><span class="num">${num}</span><div>${pill(x.rating)}<strong>${esc(x.title)}</strong>${x.targets.length > 1 ? ` <span class="muted">(${x.targets.length} places)</span>` : ` <span class="muted">${esc(x.targets[0])}</span>`}<div class="fix">${esc(x.fix)}</div></div></li>`).join("")}</ol></section>`
        : "";
    const tiers = byTier
        .filter(({ groups }) => groups.length)
        .map(({ t, groups }) => `<section class="tier t${t}"><h2><span class="dot"></span>${t}. ${esc(TIER_TITLES[t])} <span class="count">${plural(r.counts[t], "finding")}</span></h2><p class="note">${esc(TIER_NOTES[t])}</p>${groups.map((x, i) => item(x, `${t}.${i + 1}`)).join("")}</section>`)
        .join("");
    const strengths = r.strengths.length
        ? `<section><h2>Already quantum-safe <span class="count">${r.strengths.length}</span></h2><p class="note">Post-quantum methods already in use. These count toward the score.</p><ul class="plain">${r.strengths.map((s) => `<li><strong>${esc(s.title)}</strong><span class="where">${esc(s.target)}</span></li>`).join("")}</ul></section>`
        : "";
    const prov = custodyCount(r, "provider");
    const kms = custodyCount(r, "provider-kms");
    const cloud = r.cloudKeys.length
        ? `<section><h2>Who can read your cloud data <span class="count">${r.cloudKeys.length}</span></h2><p class="note">Advice, not scored. Keys held by a cloud provider protect against a stolen disk, not against the provider, someone working there, or a legal demand made to them. ${prov} ${prov === 1 ? "uses" : "use"} keys the provider holds; ${kms} ${kms === 1 ? "uses" : "use"} keys in the provider's key service.</p>${r.cloudKeys.map((a, i) => `<article class="item"><div class="num">C.${i + 1}</div><div class="body"><h3>${esc(a.title)}</h3><div class="meta">${esc(a.resource)}</div>${places([a.target])}<p class="fix"><span class="label">What to do</span>${esc(a.fix)}</p></div></article>`).join("")}</section>`
        : "";
    const people = p
        ? `<section><h2>People and process <span class="count">${p.inPlace} of ${p.answered} in place</span></h2><p class="note">Your own answers from ${esc(p.answeredAt)}. They stay on this machine and are never shared.</p>${p.gaps.length
            ? p.gaps.map((q, i) => `<article class="item"><div class="num">P.${i + 1}</div><div class="body"><h3>${esc(q.question)}</h3><div class="meta">${esc(q.group)} · answered ${q.answer === "no" ? "no" : "not sure"}</div><p class="fix"><span class="label">What to do</span>${esc(q.fix)}</p></div></article>`).join("")
            : "<p>Everything you answered is in place.</p>"}</section>`
        : "";
    const accepted = r.accepted.length
        ? `<section><h2>Accepted as known leftovers <span class="count">${r.accepted.length}</span></h2><p class="note">Marked in .quantum-scan-ignore. Listed so nothing is hidden, but left out of the counts and the score.</p>${groupFindings(r.accepted).map((x, i) => item(x, `A.${i + 1}`)).join("")}</section>`
        : "";
    const areas = r.areas
        .map((a) => {
        const extra = [...a.skipped.map((s) => `${s.target}: ${s.reason}`), ...a.errors.map((e) => `${e.target}: couldn't check (${e.message})`)];
        return `<li><strong>${esc(AREA_TITLES[a.area] ?? a.area)}</strong><span class="sub2">${plural(a.checked, a.area === "code" ? "file" : "place")} checked${a.skipped.length ? `, ${a.skipped.length} skipped` : ""}${a.errors.length ? `, ${a.errors.length} couldn't be checked` : ""}</span>${extra.length ? `<ul>${extra.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</li>`;
    })
        .join("");
    const findingsIntro = total
        ? `<p class="lead">${plural(total, "finding")}${issues < total ? `, grouped into ${plural(issues, "issue")}` : ""}, ranked by what breaks first.</p>`
        : `<p class="lead">${graded ? "Nothing to fix in the areas checked." : "No scan areas were checked this time."}</p>`;
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>Encryption map · Hard Keel</title>
<style>
:root{--bg:#fff;--fg:#121a1f;--muted:#5b6873;--faint:#8a96a0;--line:#e3e8ec;--panel:#f6f8f9;--teal:#5aa99d;--accent:#2f7d71;--bad:#b4412f;--warn:#93630f;--good:#2f7d71;--t3:#4f6b8a}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0a0e12;--fg:#eef2f5;--muted:#9aa7b2;--faint:#6f7c87;--line:#1e262d;--panel:#10161b;--accent:#5aa99d;--bad:#e07a6a;--warn:#e0b25a;--good:#5aa99d;--t3:#8fb0d1}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 Inter,"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:820px;margin:0 auto;padding:40px 24px 72px}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-bottom:18px;border-bottom:1px solid var(--line)}
.logo{height:26px;width:auto;display:block;color:var(--fg);-webkit-print-color-adjust:exact;print-color-adjust:exact}.logo .rings{stroke:#5aa99d}.logo .dots{fill:#5aa99d}
.top .tag{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);text-align:right}
.cover{padding:56px 0 8px}
.eyebrow{font-size:12px;letter-spacing:.18em;text-transform:uppercase;color:var(--accent);font-weight:600}
h1{font-size:40px;line-height:1.15;letter-spacing:-.02em;margin:10px 0 6px;font-weight:700}
.sub{color:var(--muted);margin:0}
.verdict{display:flex;gap:22px;align-items:center;margin:40px 0 0}
.verdict.small{margin-top:22px}
.badge{flex:none;width:84px;height:84px;border-radius:50%;display:block;text-align:center;line-height:78px;font-size:36px;font-weight:700;border:3px solid var(--muted);color:var(--muted)}
.verdict.small .badge{width:60px;height:60px;line-height:56px;font-size:20px;border-width:2px}
.badge.good{color:var(--good);border-color:var(--good)}.badge.ok{color:var(--warn);border-color:var(--warn)}.badge.bad{color:var(--bad);border-color:var(--bad)}
.score{font-size:20px;font-weight:500}.score strong{font-size:26px;font-weight:700}.of{color:var(--muted);font-weight:400}
.verdict p{margin:4px 0 0;color:var(--muted);max-width:56ch}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin:44px 0 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.stat{padding:18px 16px 16px 0}.stat+.stat{padding-left:16px;border-left:1px solid var(--line)}
.stat .n{font-size:30px;font-weight:700;line-height:1.1}.stat .k{font-size:13px;color:var(--muted);margin-top:4px}
.stat.t1 .n{color:var(--bad)}.stat.t2 .n{color:var(--warn)}
.scope{font-size:13px;color:var(--muted);margin:16px 0 0}
.label{display:block;font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);font-weight:600;margin-bottom:2px}
.scope .label{display:inline;margin-right:10px}
section{margin-top:64px}
h2{font-size:22px;letter-spacing:-.01em;margin:0 0 6px;font-weight:650}
.count{font-size:14px;color:var(--muted);font-weight:400;margin-left:8px;white-space:nowrap}
.note{color:var(--muted);margin:0 0 20px;max-width:62ch}
.lead{font-size:18px;margin:64px 0 0;color:var(--muted)}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--faint);margin-right:10px;vertical-align:.15em}
.t1 .dot{background:var(--bad)}.t2 .dot{background:var(--warn)}.t3 .dot{background:var(--t3)}
.first{background:var(--panel);border-radius:14px;padding:28px 28px 8px;border-left:4px solid var(--teal)}
.first ol{list-style:none;margin:0;padding:0}
.first li{display:flex;gap:16px;padding:0 0 20px}
.first .num{font-weight:700;color:var(--accent);min-width:28px}
.fix{color:var(--muted);margin-top:2px}
.item{display:flex;gap:18px;padding:20px 0;border-top:1px solid var(--line);break-inside:avoid}
.item .num{flex:none;width:36px;font-weight:600;color:var(--faint);font-size:14px;padding-top:2px;font-variant-numeric:tabular-nums}
.item .body{min-width:0;flex:1}
h3{font-size:17px;margin:0;font-weight:600;line-height:1.4}
.meta{font-size:13px;color:var(--faint);margin-top:2px}
.rate{display:inline-block;font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;padding:1px 7px;border:1px solid currentColor;border-radius:999px;margin-right:8px;line-height:1.5}
.rate.high{color:var(--bad)}.rate.medium{color:var(--warn)}.rate.low{color:var(--muted)}
.places{display:flex;flex-wrap:wrap;gap:4px 14px;margin:8px 0 0;font:13px/1.5 "IBM Plex Mono",ui-monospace,"Cascadia Mono",Consolas,Menlo,monospace;color:var(--muted);word-break:break-all}
.places .more{font-family:inherit;color:var(--faint)}
.item .fix{margin:12px 0 0;color:var(--fg)}
ul.plain{list-style:none;margin:0;padding:0}
ul.plain>li{padding:14px 0;border-top:1px solid var(--line)}
ul.plain ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:14px}
.where{display:block;font-size:13px;color:var(--muted);font-family:"IBM Plex Mono",ui-monospace,Consolas,Menlo,monospace;word-break:break-all}
.muted{color:var(--muted)}.sub2{display:block;font-size:14px;color:var(--muted)}
.about p{color:var(--muted);max-width:64ch}
.actions{display:flex;gap:12px;align-items:center;margin-top:28px;flex-wrap:wrap}
button{font:inherit;font-size:14px;font-weight:600;padding:9px 16px;border-radius:8px;border:1px solid var(--accent);background:var(--accent);color:#fff;cursor:pointer}
.hint{font-size:13px;color:var(--faint)}
details{margin-top:40px;color:var(--muted)}summary{cursor:pointer}
pre{white-space:pre-wrap;font-size:12px;color:var(--muted)}
footer{margin-top:72px;padding-top:18px;border-top:1px solid var(--line);font-size:13px;color:var(--faint);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap}
a{color:var(--accent)}
@media (max-width:640px){main{padding:24px 16px 56px}h1{font-size:30px}.cover{padding-top:36px}.stats{grid-template-columns:repeat(2,1fr)}.stat:nth-child(3){padding-left:0;border-left:0}.stat:nth-child(n+3){border-top:1px solid var(--line)}.badge{width:68px;height:68px;line-height:62px;font-size:30px}.first{padding:22px 18px 4px}.item{gap:12px}.item .num{width:30px}.top .tag{display:none}}
@page{size:letter;margin:16mm 16mm 20mm;@bottom-left{content:"Hard Keel · Encryption map · Confidential";font:8pt Inter,"Segoe UI",system-ui,sans-serif;color:#76828c}@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt Inter,"Segoe UI",system-ui,sans-serif;color:#76828c}}
@media print{
:root{--bg:#fff;--fg:#121a1f;--muted:#4d5963;--faint:#76828c;--line:#d9dfe3;--panel:#f3f6f7;--accent:#2f7d71;--bad:#a0301f;--warn:#7a520c;--good:#2f7d71;--t3:#4f6b8a}
html,body{background:#fff}body{font-size:10.5pt;line-height:1.5;-webkit-print-color-adjust:exact;print-color-adjust:exact}
main{max-width:none;padding:0}
.cover{padding-top:18pt}h1{font-size:26pt;margin:4pt 0 2pt}.verdict{margin-top:16pt}.verdict.small{margin-top:10pt}.badge{width:62px;height:62px;line-height:56px;font-size:26px}.verdict.small .badge{width:46px;height:46px;line-height:42px;font-size:15px}.score{font-size:14pt}.score strong{font-size:18pt}.stats{margin-top:16pt}.stat{padding-top:8pt;padding-bottom:8pt}.stat .n{font-size:20pt}.scope{margin-top:8pt}.first{margin-top:18pt;padding:14pt 16pt 2pt}.first li{padding-bottom:8pt}.first .note{margin-bottom:10pt}
.actions,details{display:none}
section{margin-top:28pt}.lead{margin-top:28pt;break-after:avoid}
h2{break-after:avoid}.note{break-after:avoid}
.first{break-inside:avoid}
.item{padding:10pt 0}
.tier{break-before:auto}
a{color:inherit;text-decoration:none}
footer{margin-top:36pt;break-inside:avoid}
}
</style></head><body><main>
<header class="top">${LOGO}<div class="tag">Confidential</div></header>
<div class="cover">
<div class="eyebrow">Quantum readiness report</div>
<h1>Encryption map</h1>
<p class="sub">Prepared ${esc(longDate(r.createdAt))} with Hard Keel Quantum Scan ${esc(r.version)}</p>
${verdict}
${peopleVerdict}
${stats}
${ratingLine}
${checkedLine}
<div class="actions"><button type="button" onclick="window.print()">Save as PDF</button><span class="hint">In the print window, choose Save as PDF.</span></div>
</div>
${firstSection}
${findingsIntro}
${tiers}
${strengths}
${cloud}
${people}
${accepted}
<section><h2>What was checked</h2><ul class="plain">${areas || "<li>Nothing this time.</li>"}</ul></section>
<section class="about"><h2>About this report</h2><p>Quantum Scan uses look-only checks: normal connections and local settings, with no logins, changes or attack traffic. Findings are ranked by what breaks first: weak encryption that is unsafe today, then traffic that could be recorded now and decrypted later, then long-lived signatures, then everything else that uses RSA or elliptic curves.</p><p>The grade uses Hard Keel method v${esc(g.method)}, the same as a code scan. This report was created on your computer and stays there unless you share it. It names your systems, so treat it as confidential.</p></section>
<details><summary>Activity log (${activity.length} entries)</summary><pre>${esc(activity.join("\n"))}</pre></details>
<footer><span>Hard Keel · Encryption map · Confidential</span><span>hardkeel.com · contact@hardkeel.com</span></footer>
</main></body></html>
`;
}
