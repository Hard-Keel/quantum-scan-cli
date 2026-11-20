// This machine: reads local encryption settings only. No network connections, no changes,
// and private keys are never opened (only .pub files and certificates).

import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { ALGORITHMS } from "./rules.ts";
import type { ActivityLog } from "./map-activity.ts";
import { emptyResult, type AreaResult, type MapFinding } from "./map-types.ts";
import { certKey, certSignature, sshFindings } from "./map-web.ts";

export interface HostIO {
  platform: NodeJS.Platform;
  home: string;
  read(path: string): string | null; // null when missing or unreadable
  list(dir: string): string[] | null;
  run(cmd: string, args: string[]): string | null; // stdout+stderr, null on failure
}

export const realIO: HostIO = {
  platform: process.platform,
  home: homedir(),
  read(p) {
    try {
      return readFileSync(p, "utf8");
    } catch {
      return null;
    }
  },
  list(d) {
    try {
      return readdirSync(d);
    } catch {
      return null;
    }
  },
  run(cmd, args) {
    try {
      return execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], timeout: 15000, windowsHide: true });
    } catch (e) {
      // ssh -V prints to stderr and some tools exit non-zero while still answering.
      const err = e as { stdout?: string; stderr?: string };
      const out = `${err.stdout ?? ""}${err.stderr ?? ""}`;
      return out || null;
    }
  },
};

// ---------- SSH server settings ----------

export interface SshdSettings {
  kex?: string;
  ciphers?: string;
  macs?: string;
  hostKeyAlgorithms?: string;
}

/** First value of each setting wins, as in sshd. Follows Include lines one level deep. */
export function parseSshd(text: string, io?: HostIO, dir?: string, out: SshdSettings = {}): SshdSettings {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    if (/^match\s/i.test(line)) break; // settings after Match apply only to some users
    const m = line.match(/^(\S+)\s+(.+)$/);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const val = m[2].trim();
    if (key === "include" && io && dir) {
      for (const pattern of val.split(/\s+/)) {
        const full = pattern.startsWith("/") || /^[A-Za-z]:/.test(pattern) ? pattern : join(dir, pattern);
        const star = full.lastIndexOf("*");
        if (star >= 0) {
          const folder = full.slice(0, full.lastIndexOf("/", star));
          const suffix = full.slice(star + 1);
          for (const f of (io.list(folder) ?? []).filter((n) => n.endsWith(suffix)).sort()) {
            const t = io.read(join(folder, f));
            if (t) parseSshd(t, undefined, undefined, out);
          }
        } else {
          const t = io.read(full);
          if (t) parseSshd(t, undefined, undefined, out);
        }
      }
    }
    if (key === "kexalgorithms") out.kex ??= val;
    if (key === "ciphers") out.ciphers ??= val;
    if (key === "macs") out.macs ??= val;
    if (key === "hostkeyalgorithms") out.hostKeyAlgorithms ??= val;
  }
  return out;
}

/** OpenSSH version from `ssh -V`, e.g. 9.6. */
export function opensshVersion(text: string | null): number | null {
  const m = text?.match(/OpenSSH_for_Windows_(\d+)\.(\d+)|OpenSSH_(\d+)\.(\d+)/);
  if (!m) return null;
  return Number(m[1] ?? m[3]) + Number(m[2] ?? m[4]) / 10;
}

const explicit = (v?: string) => (v && !/^[+\-^]/.test(v) ? v.split(",").map((s) => s.trim()) : null);

function checkSshd(io: HostIO, log: ActivityLog, res: AreaResult): void {
  const dir = io.platform === "win32" ? "C:/ProgramData/ssh" : "/etc/ssh";
  const path = `${dir}/sshd_config`;
  const text = io.read(path);
  if (text === null) return; // no SSH server here
  log.record("host", path, "read SSH server settings");
  res.checked.push(path);
  const s = parseSshd(text, io, dir);
  const version = opensshVersion(io.run("ssh", ["-V"]));
  log.record("host", "ssh -V", "read the installed OpenSSH version");

  const kex = explicit(s.kex);
  // Defaults: OpenSSH 9.0 added sntrup761x25519 by default, 9.9 added mlkem768x25519.
  const defaultPqc = version !== null && version >= 9.0;
  const lists = {
    kex: kex ?? (defaultPqc ? ["sntrup761x25519-sha512"] : ["curve25519-sha256"]),
    ciphers: explicit(s.ciphers) ?? [],
    macs: explicit(s.macs) ?? [],
    hostKeys: explicit(s.hostKeyAlgorithms) ?? [],
  };
  const r = sshFindings(lists, "host", path, false);
  // Host keys are judged from the key files below, not the algorithm list.
  res.findings.push(...r.findings.filter((f) => f.ruleId !== "ssh-host-key"));
  if (r.pqc) res.strengths.push({ area: "host", target: path, algorithm: "Hybrid SSH key exchange", title: kex ? "SSH server allows quantum-safe hybrid key exchange" : `SSH server uses quantum-safe hybrid key exchange by default (OpenSSH ${version})` });
  if (!kex && version === null) res.skipped.push({ target: path, reason: "couldn't read the OpenSSH version, so the default key exchange is a guess" });
}

// ---------- public key files ----------

/** Type and size of an OpenSSH public key line. Never reads private keys. */
export function sshPublicKey(line: string): { type: string; bits?: number } | null {
  const m = line.trim().match(/^(ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp\d+|sk-[a-z0-9@.-]+)\s+([A-Za-z0-9+/=]+)/);
  if (!m) return null;
  if (m[1] !== "ssh-rsa") return { type: m[1] };
  try {
    const b = Buffer.from(m[2], "base64");
    let off = 0;
    const next = () => {
      const len = b.readUInt32BE(off);
      const v = b.subarray(off + 4, off + 4 + len);
      off += 4 + len;
      return v;
    };
    next(); // "ssh-rsa"
    next(); // e
    const n = next();
    const lead = n[0] === 0 ? 1 : 0;
    const bytes = n.length - lead;
    const topBits = 8 - Math.clz32(n[lead]) + 24;
    return { type: "ssh-rsa", bits: (bytes - 1) * 8 + topBits };
  } catch {
    return { type: "ssh-rsa" };
  }
}

function keyFinding(path: string, k: { type: string; bits?: number }, role: string): MapFinding {
  const base = { area: "host" as const, target: path, internetFacing: false };
  if (k.type === "ssh-dss") return { ...base, ruleId: "host-key-dsa", title: `${role} uses DSA`, algorithm: "DSA", primitive: "signature", risk: "weak-now", severity: "high", fix: ALGORITHMS.DSA.fix };
  if (k.type === "ssh-rsa" && k.bits && k.bits < 2048) return { ...base, ruleId: "host-key-small-rsa", title: `${role} uses a ${k.bits}-bit RSA key`, algorithm: "RSA", primitive: "signature", risk: "weak-now", severity: "high", keySize: k.bits, fix: "Replace with an Ed25519 key, or RSA of at least 3072 bits." };
  const alg = k.type === "ssh-rsa" ? "RSA signature" : k.type.includes("ed25519") ? "Ed25519" : k.type.includes("ed448") ? "Ed448" : "ECDSA";
  return { ...base, ruleId: "host-key-quantum", title: `${role} uses ${alg === "RSA signature" ? `${k.bits ?? ""}-bit RSA`.trim() : alg}`, algorithm: alg, primitive: "signature", risk: "quantum-vulnerable", severity: "medium", keySize: k.bits, fix: "Keep it for now; plan to move to post-quantum signatures once OpenSSH supports them." };
}

function checkKeyFiles(io: HostIO, log: ActivityLog, res: AreaResult): void {
  const dirs: [string, string][] = [
    [io.platform === "win32" ? "C:/ProgramData/ssh" : "/etc/ssh", "SSH host key"],
    [join(io.home, ".ssh"), "Your SSH key"],
  ];
  for (const [dir, role] of dirs) {
    const names = io.list(dir);
    if (!names) continue;
    for (const name of names.filter((n) => n.endsWith(".pub")).sort()) {
      const path = join(dir, name).split("\\").join("/");
      const text = io.read(path);
      if (!text) continue;
      log.record("host", path, "read public key type and size");
      const k = sshPublicKey(text);
      if (!k) continue;
      res.checked.push(path);
      res.findings.push(keyFinding(path, k, role));
    }
  }
}

// ---------- OpenSSL and system policy ----------

export function opensslPolicyFindings(text: string, path: string): MapFinding[] {
  const out: MapFinding[] = [];
  const base = { area: "host" as const, target: path, internetFacing: false };
  const min = text.match(/^\s*MinProtocol\s*=\s*(\S+)/im)?.[1];
  if (min && /^(TLSv1|TLSv1\.1|SSLv3)$/i.test(min)) {
    const a = ALGORITHMS["TLS 1.0/1.1"];
    out.push({ ...base, ruleId: "host-openssl-old-tls", title: `OpenSSL allows ${min} system-wide`, algorithm: "TLS 1.0/1.1", primitive: a.primitive, risk: a.risk, severity: a.severity, fix: "Set MinProtocol = TLSv1.2 in the OpenSSL config." });
  }
  const level = text.match(/^\s*CipherString\s*=.*@SECLEVEL=(\d)/im)?.[1];
  if (level !== undefined && Number(level) < 2) {
    out.push({ ...base, ruleId: "host-openssl-seclevel", title: `OpenSSL security level lowered to ${level}`, algorithm: "Weak TLS ciphers", primitive: "protocol", risk: "weak-now", severity: "medium", fix: "Use @SECLEVEL=2 or higher, which blocks SHA-1 and keys under 2048 bits." });
  }
  return out;
}

function checkOpenssl(io: HostIO, log: ActivityLog, res: AreaResult): void {
  if (io.platform === "win32") return;
  for (const path of ["/etc/ssl/openssl.cnf", "/usr/lib/ssl/openssl.cnf", "/etc/pki/tls/openssl.cnf", "/opt/homebrew/etc/openssl@3/openssl.cnf"]) {
    const text = io.read(path);
    if (text === null) continue;
    log.record("host", path, "read OpenSSL settings");
    res.checked.push(path);
    res.findings.push(...opensslPolicyFindings(text, path));
  }
  const policy = io.read("/etc/crypto-policies/config");
  if (policy !== null) {
    log.record("host", "/etc/crypto-policies/config", "read the system encryption policy");
    res.checked.push("/etc/crypto-policies/config");
    if (/^\s*LEGACY/m.test(policy)) {
      res.findings.push({ area: "host", target: "/etc/crypto-policies/config", internetFacing: false, ruleId: "host-crypto-policy-legacy", title: "System encryption policy is LEGACY", algorithm: "Weak TLS ciphers", primitive: "protocol", risk: "weak-now", severity: "medium", fix: "Run update-crypto-policies --set DEFAULT (or FUTURE)." });
    }
  }
}

// ---------- certificates ----------

function certFromPem(pem: string): X509Certificate | null {
  try {
    return new X509Certificate(pem);
  } catch {
    return null;
  }
}

export function localCertFindings(c: { keyType: string; bits?: number; sigWeak?: boolean; notAfter: number; isCa?: boolean; label: string; target: string }, now = Date.now()): MapFinding[] {
  const base = { area: "host" as const, target: c.target, internetFacing: false };
  const out: MapFinding[] = [];
  if (c.notAfter < now) out.push({ ...base, ruleId: "host-cert-expired", title: `${c.label} has expired`, algorithm: "Expired certificate", primitive: "protocol", risk: "weak-now", severity: "medium", fix: "Renew or remove the expired certificate." });
  if (c.sigWeak) out.push({ ...base, ruleId: "host-cert-weak-signature", title: `${c.label} is signed with SHA-1`, algorithm: "SHA-1", primitive: "hash", risk: "weak-now", severity: "high", fix: "Reissue it signed with SHA-256 or stronger." });
  if (c.keyType === "RSA" && c.bits && c.bits < 2048) out.push({ ...base, ruleId: "host-cert-small-rsa", title: `${c.label} uses a ${c.bits}-bit RSA key`, algorithm: "RSA", primitive: "signature", risk: "weak-now", severity: "high", keySize: c.bits, fix: "Reissue with at least a 2048-bit RSA key, or ECDSA P-256." });
  else if (c.keyType === "RSA" || c.keyType === "ECDSA" || c.keyType === "Ed25519") {
    out.push({ ...base, ruleId: c.isCa ? "host-ca-quantum" : "host-cert-quantum", title: `${c.label} uses ${c.keyType === "RSA" ? `${c.bits ?? ""}-bit RSA`.trim() : c.keyType}`, algorithm: c.keyType === "RSA" ? "RSA signature" : c.keyType, primitive: "signature", risk: "quantum-vulnerable", severity: "medium", keySize: c.bits, longLived: c.isCa, fix: c.isCa ? "Certificate authorities stay trusted for years: plan an ML-DSA authority by 2030." : "Plan to move to ML-DSA certificates once your certificate authority offers them." });
  }
  return out;
}

function checkLinuxCerts(io: HostIO, log: ActivityLog, res: AreaResult): void {
  if (io.platform === "win32") return;
  const live = "/etc/letsencrypt/live";
  for (const name of io.list(live) ?? []) {
    const path = `${live}/${name}/cert.pem`;
    const pem = io.read(path);
    if (!pem) continue;
    log.record("host", path, "read certificate details");
    const cert = certFromPem(pem);
    if (!cert) continue;
    res.checked.push(path);
    const k = certKey(cert);
    res.findings.push(...localCertFindings({ keyType: k.type, bits: k.bits, sigWeak: Boolean(certSignature(Buffer.from(cert.raw))?.weak), notAfter: Date.parse(cert.validTo), label: `Certificate for ${name}`, target: path }));
  }
}

// ---------- Windows ----------

/** Protocols and ciphers explicitly turned on in the Schannel registry. Missing keys mean the Windows default. */
export function parseSchannel(text: string): { enabledProtocols: string[]; enabledCiphers: string[] } {
  const enabledProtocols: string[] = [];
  const enabledCiphers: string[] = [];
  let key = "";
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (/^HKEY_/i.test(line)) {
      key = line;
      continue;
    }
    const m = line.match(/^Enabled\s+REG_DWORD\s+0x([0-9a-f]+)/i);
    if (!m || Number.parseInt(m[1], 16) === 0) continue;
    const proto = key.match(/\\Protocols\\(SSL 2\.0|SSL 3\.0|TLS 1\.0|TLS 1\.1)\\Server$/i);
    if (proto) enabledProtocols.push(proto[1]);
    const cipher = key.match(/\\Ciphers\\(Triple DES 168|DES 56\/56|RC4 [0-9/]+|NULL)$/i);
    if (cipher) enabledCiphers.push(cipher[1]);
  }
  return { enabledProtocols, enabledCiphers };
}

const CERT_PS = "Get-ChildItem Cert:\\LocalMachine\\My | ForEach-Object { $s = $null; try { $s = $_.PublicKey.Key.KeySize } catch {}; [pscustomobject]@{ Subject = $_.Subject; NotAfter = $_.NotAfter.ToUniversalTime().ToString('o'); Sig = $_.SignatureAlgorithm.FriendlyName; Key = $_.PublicKey.Oid.FriendlyName; Size = $s } } | ConvertTo-Json -Compress";

export function parseWindowsCerts(json: string): { subject: string; notAfter: number; sig: string; key: string; size?: number }[] {
  try {
    const v = JSON.parse(json.trim() || "[]");
    const list = Array.isArray(v) ? v : [v];
    return list.map((c) => ({ subject: String(c.Subject ?? ""), notAfter: Date.parse(c.NotAfter), sig: String(c.Sig ?? ""), key: String(c.Key ?? ""), size: typeof c.Size === "number" ? c.Size : undefined }));
  } catch {
    return [];
  }
}

function checkWindows(io: HostIO, log: ActivityLog, res: AreaResult): void {
  if (io.platform !== "win32") return;
  const reg = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL";
  const text = io.run("reg", ["query", reg, "/s"]);
  log.record("host", reg, "read Windows TLS (Schannel) settings");
  if (text) {
    res.checked.push(reg);
    const s = parseSchannel(text);
    const base = { area: "host" as const, target: reg, internetFacing: false };
    if (s.enabledProtocols.length) {
      const a = ALGORITHMS["TLS 1.0/1.1"];
      res.findings.push({ ...base, ruleId: "host-schannel-old-tls", title: `Windows has ${s.enabledProtocols.join(" and ")} turned on for servers`, algorithm: "TLS 1.0/1.1", primitive: a.primitive, risk: a.risk, severity: a.severity, fix: "Set Enabled to 0 for these protocols under SCHANNEL\\Protocols, or remove the keys on Windows Server 2022 and later." });
    }
    if (s.enabledCiphers.length) {
      res.findings.push({ ...base, ruleId: "host-schannel-weak-cipher", title: `Windows has ${s.enabledCiphers.join(" and ")} turned on`, algorithm: "Weak TLS ciphers", primitive: "protocol", risk: "weak-now", severity: "high", fix: "Set Enabled to 0 for these ciphers under SCHANNEL\\Ciphers." });
    }
  }
  const json = io.run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", CERT_PS]);
  log.record("host", "Cert:\\LocalMachine\\My", "read this machine's certificate details");
  for (const c of parseWindowsCerts(json ?? "")) {
    const keyType = /RSA/i.test(c.key) ? "RSA" : /EC|ECC|ECDSA/i.test(c.key) ? "ECDSA" : "other";
    const cn = c.subject.match(/CN=([^,]+)/)?.[1] ?? "a certificate";
    res.findings.push(...localCertFindings({ keyType, bits: keyType === "RSA" ? c.size : undefined, sigWeak: /sha1|md5/i.test(c.sig), notAfter: c.notAfter, label: `Certificate for ${cn}`, target: "Cert:\\LocalMachine\\My" }));
  }
  if (json !== null) res.checked.push("Cert:\\LocalMachine\\My");
}

export function runHost(log: ActivityLog, io: HostIO = realIO): AreaResult {
  const res = emptyResult("host");
  for (const step of [checkSshd, checkKeyFiles, checkOpenssl, checkLinuxCerts, checkWindows]) {
    try {
      step(io, log, res);
    } catch (e) {
      res.errors.push({ area: "host", target: step.name, kind: "read", message: e instanceof Error ? e.message : String(e) });
    }
  }
  return res;
}
