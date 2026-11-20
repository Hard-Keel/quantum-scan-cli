// .quantum-scan-ignore: findings a team has looked at and marked not an issue.
//
//   # comments start with #
//   rule:py-weak-hash          a rule, everywhere
//   legacy/                    every finding under a folder
//   src/old.py                 every finding in one file
//   src/old.py:py-weak-hash    one rule in one file
//
// Leaked keys and passwords can't be ignored by rule, only by file, so one line can't hide every secret.
export const IGNORE_FILE = ".quantum-scan-ignore";
export function parseIgnore(text) {
    const out = [];
    for (const raw of text.split(/\r?\n/)) {
        const line = raw.replace(/\s+#.*$/, "").trim();
        if (!line || line.startsWith("#"))
            continue;
        if (line.startsWith("rule:")) {
            const rule = line.slice(5).trim();
            if (rule)
                out.push({ rule });
            continue;
        }
        const m = line.match(/^(.+?):([a-z0-9][a-z0-9-]*)$/);
        if (m && !/^[a-zA-Z]$/.test(m[1]))
            out.push({ path: m[1].replace(/^\.\//, ""), rule: m[2] });
        else
            out.push({ path: line.replace(/^\.\//, "") });
    }
    return out;
}
function pathMatches(entry, file) {
    if (entry.endsWith("/"))
        return file.startsWith(entry);
    return file === entry || file.startsWith(`${entry}/`);
}
export function applyIgnore(findings, entries) {
    const kept = [];
    const ignored = {};
    for (const f of findings) {
        const hit = entries.some((e) => {
            if (e.rule && e.path)
                return e.rule === f.ruleId && pathMatches(e.path, f.file);
            if (e.rule)
                return e.rule === f.ruleId && f.kind !== "secret";
            return e.path ? pathMatches(e.path, f.file) : false;
        });
        if (hit)
            ignored[f.ruleId] = (ignored[f.ruleId] ?? 0) + 1;
        else
            kept.push(f);
    }
    return { kept, ignored };
}
