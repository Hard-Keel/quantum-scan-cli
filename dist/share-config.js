// Local settings for the command-line version: the random install ID, whether anonymized sharing is on,
// offline mode, the optional industry and size, and what the last run would have sent.
// Kept in one JSON file in the user's settings folder. Nothing here leaves the machine except
// through share.ts, and only the fields that file builds.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
export const INDUSTRIES = [
    "finance",
    "healthcare",
    "government",
    "defense",
    "technology",
    "telecom",
    "energy-utilities",
    "manufacturing",
    "retail",
    "education",
    "professional-services",
    "other",
];
export const SIZES = ["1-50", "51-250", "251-1000", "1000+"];
export function settingsPath(env = process.env, platform = process.platform) {
    if (env.QUANTUM_SCAN_CONFIG)
        return resolve(env.QUANTUM_SCAN_CONFIG);
    if (platform === "win32" && env.APPDATA)
        return join(env.APPDATA, "Hard Keel", "quantum-scan.json");
    if (platform === "darwin")
        return join(homedir(), "Library", "Application Support", "Hard Keel", "quantum-scan.json");
    return join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "hardkeel", "quantum-scan.json");
}
function fresh() {
    return {
        id: randomBytes(16).toString("hex"),
        sharing: "on",
        offline: false,
        noticeShown: false,
        ownershipToken: randomBytes(12).toString("hex"),
        state: {},
    };
}
export function loadSettings(path = settingsPath()) {
    const base = fresh();
    if (!existsSync(path))
        return base;
    try {
        const raw = JSON.parse(readFileSync(path, "utf8"));
        return {
            ...base,
            ...raw,
            id: typeof raw.id === "string" && /^[a-f0-9]{32}$/.test(raw.id) ? raw.id : base.id,
            ownershipToken: typeof raw.ownershipToken === "string" && /^[a-f0-9]{24}$/.test(raw.ownershipToken) ? raw.ownershipToken : base.ownershipToken,
            industry: INDUSTRIES.includes(raw.industry) ? raw.industry : undefined,
            size: SIZES.includes(raw.size) ? raw.size : undefined,
            state: raw.state && typeof raw.state === "object" ? raw.state : {},
        };
    }
    catch {
        return base;
    }
}
/** Saves settings. Never throws: a read-only home folder must not break a scan. */
export function saveSettings(s, path = settingsPath()) {
    try {
        mkdirSync(dirname(path), { recursive: true });
        const tmp = `${path}.${process.pid}.tmp`;
        writeFileSync(tmp, JSON.stringify(s, null, 2) + "\n", { mode: 0o600 });
        renameSync(tmp, path);
    }
    catch {
        // ignore
    }
}
export function folderKey(folder) {
    return createHash("sha256").update(resolve(folder)).digest("hex").slice(0, 16);
}
/** Whether this run may send its summary, and why not. */
export function sharingState(s, opts, env = process.env) {
    if (opts.offline || s.offline || /^(1|true|yes|on)$/i.test(env.QUANTUM_SCAN_OFFLINE ?? ""))
        return "offline";
    if (/^(0|false|no|off)$/i.test(env.QUANTUM_SCAN_SHARING ?? ""))
        return "env-off";
    if (env.DO_NOT_TRACK && env.DO_NOT_TRACK !== "0")
        return "do-not-track";
    return s.sharing === "off" ? "off" : "on";
}
export const NOTICE = `Hard Keel Quantum Scan shares anonymized, aggregated usage stats about how its
checks perform and what kinds of encryption they find, to improve our products.
It never includes your code, keys, files, server names, IP addresses or company name.

  See what's sent:      quantum-scan config show-shared
  Turn it off:          quantum-scan config sharing off   (or QUANTUM_SCAN_SHARING=off)
  Send nothing at all:  --offline                         (or QUANTUM_SCAN_OFFLINE=1)
  Details:              https://hardkeel.com/privacy/
`;
/**
 * Prints the notice the first time, before anything is sent. In automated pipelines,
 * where settings may not survive between runs, it prints every run, at the top of the log.
 */
export function showNoticeIfNeeded(s, state, env = process.env, write = (t) => process.stderr.write(t)) {
    if (state !== "on")
        return false;
    const ci = Boolean(env.CI || env.GITHUB_ACTIONS);
    if (s.noticeShown && !ci)
        return false;
    write(`\n${NOTICE}\n`);
    s.noticeShown = true;
    return true;
}
