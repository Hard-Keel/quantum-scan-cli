// Builds and sends the anonymized summary of a run. Counts are rounded into bands and every name is
// checked against a fixed list, so nothing taken from the scanned code or systems can reach us.
// What is sent is exactly what buildPayload returns; `quantum-scan config show-shared` prints it.

import { ALGORITHMS } from "./rules.ts";
import type { Industry, Settings, Size } from "./share-config.ts";

export const SHARE_URL = "https://scan.hardkeel.com/v1/share";
export const PAYLOAD_VERSION = 1;

export type Band = "1" | "2-5" | "6-20" | "21-100" | "100+";
export const BANDS: Band[] = ["1", "2-5", "6-20", "21-100", "100+"];

export function band(n: number): Band | null {
  if (!Number.isFinite(n) || n < 1) return null;
  if (n === 1) return "1";
  if (n <= 5) return "2-5";
  if (n <= 20) return "6-20";
  if (n <= 100) return "21-100";
  return "100+";
}

export const AREAS = ["code", "web", "host", "network", "vpn", "cloud"] as const;
export type AreaName = (typeof AREAS)[number];

/** Error kinds a run may report. Messages are never sent, only these labels. */
export const ERROR_KINDS = ["timeout", "refused", "dns", "tls", "ssh", "read", "parse", "permission", "other"] as const;
export type ErrorKind = (typeof ERROR_KINDS)[number];

/** Post-quantum algorithms we credit. Anything else is dropped. */
export const PQC_NAMES = ["ML-KEM", "Hybrid ML-KEM key exchange", "ML-DSA", "SLH-DSA", "FN-DSA", "Hybrid SSH key exchange"];

/** Extra algorithm names the encryption map uses beyond the code rules. */
export const MAP_ALGORITHMS = ["TLS key exchange", "SSH key exchange", "SSH host key", "TLS certificate", "Static RSA key exchange", "SSH weak settings", "Expired certificate", "Certificate name mismatch", "Untrusted certificate", "Self-signed certificate",
  // Network and connected equipment (map-network.ts NET_RULES; listed here so the Worker needn't load network code).
  "Telnet", "Plain FTP", "Remote Desktop open", "VNC open", "Remote support tool", "Setup page open", "Admin page over plain HTTP", "Vendor default certificate", "Open print port", "LPD printing", "Camera stream port", "DVR service port", "MQTT without encryption", "Docker API open", "Docker API port open", "Database open on the network", "UPnP on the router", "Router forward from the internet"];

const KNOWN_ALGORITHMS = new Set([...Object.keys(ALGORITHMS), ...MAP_ALGORITHMS, ...PQC_NAMES]);
const RULE_ID = /^[a-z0-9][a-z0-9-]{0,59}$/;

/** Everything a run knows that the summary may be built from. */
export interface RunFacts {
  command: "scan" | "map";
  areas: AreaName[];
  rules: Record<string, number>; // rule id -> findings this run
  algorithms: Record<string, { count: number; quantumVulnerable: number }>;
  quantumSafe: Record<string, number>; // post-quantum algorithm -> uses
  fixed: Record<string, number>; // rule id -> findings gone since last run
  ignored: Record<string, number>; // rule id -> findings the user marked not an issue
  replacements: Record<string, number>; // post-quantum algorithm -> new uses since last run
  errors: ErrorKind[];
}

export interface Payload {
  v: number;
  id: string;
  tool: string;
  os: "linux" | "darwin" | "win32" | "other";
  ci: boolean;
  command: "scan" | "map";
  areas: AreaName[];
  rules: Record<string, Band>;
  fixed: Record<string, Band>;
  ignored: Record<string, Band>;
  algorithms: Record<string, { n: Band; qv: Band | "0" }>;
  quantumSafe: Record<string, Band>;
  replacements: Record<string, Band>;
  errors: ErrorKind[];
  industry?: Industry;
  size?: Size;
}

function bandMap(src: Record<string, number>, keyOk: (k: string) => boolean): Record<string, Band> {
  const out: Record<string, Band> = {};
  for (const [k, n] of Object.entries(src)) {
    const b = band(n);
    if (b && keyOk(k)) out[k] = b;
  }
  return out;
}

export function buildPayload(facts: RunFacts, s: Settings, toolVersion: string, env: NodeJS.ProcessEnv = process.env, platform = process.platform): Payload {
  const ruleOk = (k: string) => RULE_ID.test(k);
  const algorithms: Payload["algorithms"] = {};
  const other = { count: 0, quantumVulnerable: 0 };
  for (const [name, v] of Object.entries(facts.algorithms)) {
    const target = KNOWN_ALGORITHMS.has(name) ? name : null;
    if (!target) {
      other.count += v.count;
      other.quantumVulnerable += v.quantumVulnerable;
      continue;
    }
    const n = band(v.count);
    if (n) algorithms[target] = { n, qv: band(v.quantumVulnerable) ?? "0" };
  }
  const on = band(other.count);
  if (on) algorithms.other = { n: on, qv: band(other.quantumVulnerable) ?? "0" };
  const pqcOk = (k: string) => PQC_NAMES.includes(k);
  const payload: Payload = {
    v: PAYLOAD_VERSION,
    id: s.id,
    tool: /^\d+\.\d+\.\d+$/.test(toolVersion) ? toolVersion : "0.0.0",
    os: platform === "linux" || platform === "darwin" || platform === "win32" ? platform : "other",
    ci: Boolean(env.CI || env.GITHUB_ACTIONS),
    command: facts.command,
    areas: AREAS.filter((a) => facts.areas.includes(a)),
    rules: bandMap(facts.rules, ruleOk),
    fixed: bandMap(facts.fixed, ruleOk),
    ignored: bandMap(facts.ignored, ruleOk),
    algorithms,
    quantumSafe: bandMap(facts.quantumSafe, pqcOk),
    replacements: bandMap(facts.replacements, pqcOk),
    errors: ERROR_KINDS.filter((e) => facts.errors.includes(e)),
  };
  if (s.industry) payload.industry = s.industry;
  if (s.size) payload.size = s.size;
  return payload;
}

/** Sends the summary. Never throws and never waits more than a few seconds. */
export async function sendPayload(p: Payload, url = SHARE_URL, timeoutMs = 3000): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": `hardkeel-quantum-scan/${p.tool}` },
      body: JSON.stringify(p),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** Compares this run with the last one in the same folder: what went away, and what post-quantum use is new. */
export function diffRuns(prev: { rules: Record<string, number>; pqc: Record<string, number> } | undefined, now: { rules: Record<string, number>; pqc: Record<string, number> }) {
  const fixed: Record<string, number> = {};
  const replacements: Record<string, number> = {};
  if (!prev) return { fixed, replacements };
  for (const [rule, n] of Object.entries(prev.rules)) {
    const gone = n - (now.rules[rule] ?? 0);
    if (gone > 0) fixed[rule] = gone;
  }
  for (const [alg, n] of Object.entries(now.pqc)) {
    const added = n - (prev.pqc[alg] ?? 0);
    if (added > 0) replacements[alg] = added;
  }
  return { fixed, replacements };
}
