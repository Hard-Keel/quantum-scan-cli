// Hostnames under a domain, from public Certificate Transparency logs (via crt.sh).
// Every public certificate is logged, so this finds names people forget: old APIs, staging
// sites, a vendor's portal on your domain. It reads a public log only. It never contacts any
// of the hosts it finds; checking them still needs the domain proved and quantum-scan map.
import { MAX_WEB_TARGETS } from "./map-web.js";
const HOST = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const YEAR_MS = 365 * 86_400_000;
/** A bare domain from what someone typed: "https://Example.com/x" -> "example.com". Null if it isn't one. */
export function ctDomain(raw) {
    const d = raw.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/:?#].*$/, "").replace(/^\*\./, "").replace(/\.$/, "");
    if (!HOST.test(d) || /^\d+(\.\d+){3}$/.test(d))
        return null;
    return d;
}
/** Sorts hostnames so a domain's own name comes first, then by name read from the right (api.example.com near app.example.com). */
function byName(a, b) {
    const ka = a.split(".").reverse().join(".");
    const kb = b.split(".").reverse().join(".");
    return ka < kb ? -1 : ka > kb ? 1 : 0;
}
/** Turns crt.sh rows into hostnames under the domain. Wildcards become the name they cover; emails and other names are dropped. */
export function hostsFromCt(domain, rows, now = Date.now()) {
    const current = new Set();
    const expired = new Set();
    for (const r of rows) {
        const end = r.not_after ? Date.parse(r.not_after.endsWith("Z") ? r.not_after : r.not_after + "Z") : NaN;
        const live = Number.isNaN(end) || end >= now;
        if (!live && now - end > YEAR_MS)
            continue;
        for (const raw of String(r.name_value ?? "").split(/\s+/)) {
            const n = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
            if (!HOST.test(n))
                continue;
            if (n !== domain && !n.endsWith("." + domain))
                continue;
            (live ? current : expired).add(n);
        }
    }
    for (const n of current)
        expired.delete(n);
    return { domain, current: [...current].sort(byName), recentlyExpired: [...expired].sort(byName) };
}
/** The one request this makes: crt.sh's search for the domain and everything under it. */
export function ctUrl(domain) {
    return `https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`;
}
/** Looks the domain up on crt.sh. One request, with a plain user agent and nothing about the person running it. */
export async function lookupCt(domain, version, fetchFn = fetch, timeoutMs = 45_000) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), timeoutMs);
    try {
        const res = await fetchFn(ctUrl(domain), { headers: { accept: "application/json", "user-agent": `hardkeel-quantum-scan/${version}` }, signal: ctl.signal });
        if (!res.ok)
            return { error: `crt.sh answered ${res.status}. It's often busy; try again in a minute.` };
        const body = (await res.text()).trim();
        let rows;
        try {
            rows = body ? JSON.parse(body) : [];
        }
        catch {
            return { error: "crt.sh sent something that isn't a list of certificates. It's often busy; try again in a minute." };
        }
        if (!Array.isArray(rows))
            return { error: "crt.sh sent something that isn't a list of certificates." };
        const hosts = hostsFromCt(domain, rows);
        if (!hosts.current.includes(domain) && !hosts.recentlyExpired.includes(domain))
            hosts.current.unshift(domain);
        return hosts;
    }
    catch (e) {
        return { error: ctl.signal.aborted ? "crt.sh didn't answer in time. It's often busy; try again in a minute." : `couldn't reach crt.sh (${reason(e)})` };
    }
    finally {
        clearTimeout(timer);
    }
}
/** Node's fetch says only "fetch failed"; the cause has the useful part, like ENOTFOUND. */
function reason(e) {
    const c = e?.cause;
    return c?.code ?? c?.message ?? (e instanceof Error ? e.message : String(e));
}
/** What the hosts command prints. */
export function hostsText(h, showExpired) {
    const lines = [];
    const n = h.current.length;
    lines.push(`Hostnames under ${h.domain} in public certificate logs (crt.sh): ${n} with a current certificate.`, "");
    for (const x of h.current)
        lines.push(`  ${x}`);
    if (h.recentlyExpired.length) {
        lines.push("");
        if (showExpired) {
            lines.push(`Only on certificates that expired in the last year (often gone, sometimes forgotten):`, "");
            for (const x of h.recentlyExpired)
                lines.push(`  ${x}`);
        }
        else {
            lines.push(`${h.recentlyExpired.length} more appear only on certificates that expired in the last year. Add --all to list them.`);
        }
    }
    const list = showExpired ? [...h.current, ...h.recentlyExpired] : h.current;
    lines.push("", "This read a public log only. None of these hosts were contacted.", `To check them: prove ${h.domain} (quantum-scan prove ${h.domain}), then run quantum-scan map and paste this list when it asks for websites:`, "", `  ${list.slice(0, MAX_WEB_TARGETS).join(" ")}`);
    if (list.length > MAX_WEB_TARGETS)
        lines.push("", `That's the first ${MAX_WEB_TARGETS}; a map run checks at most ${MAX_WEB_TARGETS} addresses.`);
    return lines.join("\n") + "\n";
}
