// .quantum-scan-ignore: findings a team has looked at and marked not an issue.
//
//   # comments start with #
//   rule:py-weak-hash          a rule, everywhere
//   legacy/                    every finding under a folder
//   src/old.py                 every finding in one file
//   src/old.py:py-weak-hash    one rule in one file
//   example.com:443:web-tls-static-rsa   a known leftover on a website (quantum-scan map)
//   example.com                every finding on a website, any port (quantum-scan map)
//
// Windows-style paths (legacy\old.py) work too.
// Leaked keys and passwords can't be ignored by rule, only by file, so one line can't hide every secret.

import type { Finding } from "./types.ts";

export const IGNORE_FILE = ".quantum-scan-ignore";

interface Entry {
  rule?: string;
  path?: string;
}

export function parseIgnore(text: string): Entry[] {
  const out: Entry[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    if (line.startsWith("rule:")) {
      const rule = line.slice(5).trim();
      if (rule) out.push({ rule });
      continue;
    }
    const norm = (p: string) => p.split("\\").join("/").replace(/^\.\//, "");
    // A rule id always has a letter, so "example.com:443" stays a place, not a rule called 443.
    const m = line.match(/^(.+?):([a-z0-9-]*[a-z][a-z0-9-]*)$/);
    if (m && !/^[a-zA-Z]$/.test(m[1])) out.push({ path: norm(m[1]), rule: m[2] });
    else out.push({ path: norm(line) });
  }
  return out;
}

function pathMatches(entry: string, file: string): boolean {
  if (entry.endsWith("/")) return file.startsWith(entry);
  // "example.com" covers "example.com:443"; "src/a.py" covers "src/a.py:12" in the encryption map.
  return file === entry || file.startsWith(`${entry}/`) || file.startsWith(`${entry}:`);
}

/** The same matching, for encryption map findings (websites, this machine), where the place is a target. */
export function applyIgnoreTargets<T extends { ruleId: string; target: string; risk: string }>(findings: T[], entries: Entry[]): { kept: T[]; accepted: T[] } {
  const kept: T[] = [];
  const accepted: T[] = [];
  for (const f of findings) {
    const hit = entries.some((e) => {
      if (e.rule && e.path) return e.rule === f.ruleId && pathMatches(e.path, f.target);
      if (e.rule) return e.rule === f.ruleId && f.risk !== "secret";
      return e.path ? pathMatches(e.path, f.target) : false;
    });
    (hit ? accepted : kept).push(f);
  }
  return { kept, accepted };
}

export function applyIgnore(findings: Finding[], entries: Entry[]): { kept: Finding[]; ignored: Record<string, number> } {
  const kept: Finding[] = [];
  const ignored: Record<string, number> = {};
  for (const f of findings) {
    const hit = entries.some((e) => {
      if (e.rule && e.path) return e.rule === f.ruleId && pathMatches(e.path, f.file);
      if (e.rule) return e.rule === f.ruleId && f.kind !== "secret";
      return e.path ? pathMatches(e.path, f.file) : false;
    });
    if (hit) ignored[f.ruleId] = (ignored[f.ruleId] ?? 0) + 1;
    else kept.push(f);
  }
  return { kept, ignored };
}
