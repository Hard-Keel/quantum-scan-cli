// Websites and public services: proof of ownership, then look-only checks.
// Every check is a normal connection: the TLS handshake a browser makes, or the settings an SSH
// server announces before any login. No logins, no vulnerability tests, no attack traffic.
import { promises as dns } from "node:dns";
import { isIP, connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { randomBytes } from "node:crypto";
import { ALGORITHMS } from "./rules.js";
import { emptyResult } from "./map-types.js";
const HOSTNAME = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
/** "example.com", "api.example.com:8443", "git.example.com:22", "ssh://git.example.com". IP addresses are refused. */
export function parseTarget(raw) {
    let s = raw.trim().toLowerCase();
    let kind = null;
    const scheme = s.match(/^([a-z]+):\/\//);
    if (scheme) {
        if (scheme[1] === "ssh")
            kind = "ssh";
        else if (scheme[1] !== "https")
            return { error: `${raw}: use a hostname, https:// or ssh://` };
        s = s.slice(scheme[0].length);
    }
    s = s.replace(/\/.*$/, "");
    let port = kind === "ssh" ? 22 : 443;
    const pm = s.match(/^(.*):(\d{1,5})$/);
    if (pm) {
        s = pm[1];
        port = Number(pm[2]);
    }
    if (isIP(s) || /^\[.*\]$/.test(s))
        return { error: `${raw}: use a hostname under a domain you proved, not an IP address` };
    if (!HOSTNAME.test(s))
        return { error: `${raw}: not a hostname` };
    if (port < 1 || port > 65535)
        return { error: `${raw}: bad port` };
    kind ??= port === 22 ? "ssh" : "tls";
    return { host: s, port, kind, label: `${s}:${port}` };
}
export const PROOF_PREFIX = "_hardkeel-scan";
export function proofRecord(domain, token) {
    return { name: `${PROOF_PREFIX}.${domain}`, value: `hardkeel-scan-verify=${token}` };
}
/** The proved domain that covers a host: the host itself or any parent of it. */
export function coveringDomain(host, proved) {
    for (const d of proved)
        if (host === d || host.endsWith(`.${d}`))
            return d;
    return null;
}
/** Candidate domains to look for proof on, nearest first: api.eu.example.com -> api.eu.example.com, eu.example.com, example.com. */
export function parentDomains(host) {
    const parts = host.split(".");
    const out = [];
    for (let i = 0; i <= parts.length - 2; i++)
        out.push(parts.slice(i).join("."));
    return out;
}
/** Public resolvers tried only when this machine's own DNS doesn't answer (for example a local stub that is down). */
export const PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8"];
export function publicLookup(servers = PUBLIC_RESOLVERS) {
    return (name) => {
        const r = new dns.Resolver({ timeout: 3000, tries: 2 });
        r.setServers(servers);
        return r.resolveTxt(name);
    };
}
/** DNS answered, and the name has no such record. Anything else means DNS itself didn't answer. */
const DNS_NO_RECORD = new Set(["ENOTFOUND", "ENODATA", "ENONAME"]);
/**
 * Checks the DNS record that proves a domain is yours. Uses this machine's DNS first. If that DNS
 * doesn't answer at all, asks a public resolver for this one record, and says so in the activity log.
 */
export async function checkProof(domain, token, log, lookup = (n) => dns.resolveTxt(n), fallback) {
    const { name, value } = proofRecord(domain, token);
    const match = (records) => records.some((chunks) => chunks.join("").trim() === value);
    log.record("web", name, "DNS lookup of the ownership record");
    let firstError;
    try {
        return { status: match(await lookup(name)) ? "found" : "missing" };
    }
    catch (e) {
        const code = String(e?.code ?? "");
        if (DNS_NO_RECORD.has(code))
            return { status: "missing" };
        firstError = code || (e instanceof Error ? e.message : String(e));
    }
    if (!fallback)
        return { status: "lookup-failed", detail: `this machine's DNS didn't answer (${firstError})` };
    log.record("web", name, `DNS lookup of the ownership record via a public resolver, because this machine's DNS didn't answer (${firstError})`);
    try {
        return { status: match(await fallback(name)) ? "found" : "missing" };
    }
    catch (e) {
        const code = String(e?.code ?? "");
        if (DNS_NO_RECORD.has(code))
            return { status: "missing" };
        return { status: "lookup-failed", detail: `this machine's DNS didn't answer (${firstError}), and neither did a public resolver (${code || "error"})` };
    }
}
/** Whether a domain is proved. Kept for callers that only need yes or no. */
export async function hasProof(domain, token, log, lookup, fallback) {
    return (await checkProof(domain, token, log, lookup, fallback)).status === "found";
}
const TIMEOUT_MS = 8000;
export function errorKind(e) {
    const code = String(e?.code ?? "");
    if (code === "ETIMEDOUT" || code === "TIMEOUT")
        return "timeout";
    if (code === "ECONNREFUSED" || code === "ECONNRESET")
        return "refused";
    if (code === "ENOTFOUND" || code === "EAI_AGAIN")
        return "dns";
    if (code.startsWith("ERR_SSL") || code.startsWith("ERR_TLS") || /SSL|TLS/i.test(code))
        return "tls";
    return "other";
}
export function handshake(host, port, opts) {
    return new Promise((resolveP) => {
        let done = false;
        const finish = (h, s) => {
            if (done)
                return;
            done = true;
            s?.destroy();
            resolveP(h);
        };
        let sock;
        try {
            sock = tlsConnect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, ...opts }, () => {
                let cert;
                try {
                    cert = sock.getPeerX509Certificate() ?? undefined;
                }
                catch {
                    cert = undefined;
                }
                const eph = sock.getEphemeralKeyInfo();
                finish({
                    ok: true,
                    protocol: sock.getProtocol(),
                    cipher: sock.getCipher()?.name,
                    keyExchange: eph && "name" in eph ? eph.name : undefined,
                    cert,
                    authorized: sock.authorized,
                    authError: sock.authorizationError ? String(sock.authorizationError) : undefined,
                }, sock);
            });
        }
        catch (e) {
            finish({ ok: false, error: errorKind(e), message: e instanceof Error ? e.message : String(e) });
            return;
        }
        sock.setTimeout(TIMEOUT_MS, () => finish({ ok: false, error: "timeout", message: "timed out" }, sock));
        sock.on("error", (e) => finish({ ok: false, error: errorKind(e), message: e.message }, sock));
    });
}
/** Whether this Node.js can offer the hybrid X25519 + ML-KEM-768 key exchange (OpenSSL 3.5 or later). */
export function canTestHybrid(openssl = process.versions.openssl ?? "") {
    const m = openssl.match(/^(\d+)\.(\d+)/);
    return Boolean(m && (Number(m[1]) > 3 || (Number(m[1]) === 3 && Number(m[2]) >= 5)));
}
// Signature algorithm OIDs a certificate can be signed with.
const SIG_OIDS = {
    "1.2.840.113549.1.1.4": { name: "RSA with MD5", weak: true },
    "1.2.840.113549.1.1.5": { name: "RSA with SHA-1", weak: true },
    "1.2.840.113549.1.1.11": { name: "RSA with SHA-256" },
    "1.2.840.113549.1.1.12": { name: "RSA with SHA-384" },
    "1.2.840.113549.1.1.13": { name: "RSA with SHA-512" },
    "1.2.840.113549.1.1.10": { name: "RSA-PSS" },
    "1.2.840.10045.4.1": { name: "ECDSA with SHA-1", weak: true },
    "1.2.840.10045.4.3.2": { name: "ECDSA with SHA-256" },
    "1.2.840.10045.4.3.3": { name: "ECDSA with SHA-384" },
    "1.2.840.10045.4.3.4": { name: "ECDSA with SHA-512" },
    "1.3.101.112": { name: "Ed25519" },
    "1.3.101.113": { name: "Ed448" },
    "2.16.840.1.101.3.4.3.17": { name: "ML-DSA-44", pqc: true },
    "2.16.840.1.101.3.4.3.18": { name: "ML-DSA-65", pqc: true },
    "2.16.840.1.101.3.4.3.19": { name: "ML-DSA-87", pqc: true },
};
function readLen(b, i) {
    const first = b[i];
    if (first < 0x80)
        return [first, i + 1];
    const n = first & 0x7f;
    let len = 0;
    for (let k = 0; k < n; k++)
        len = len * 256 + b[i + 1 + k];
    return [len, i + 1 + n];
}
function oidString(b) {
    const parts = [Math.floor(b[0] / 40), b[0] % 40];
    let v = 0;
    for (let i = 1; i < b.length; i++) {
        v = v * 128 + (b[i] & 0x7f);
        if (!(b[i] & 0x80)) {
            parts.push(v);
            v = 0;
        }
    }
    return parts.join(".");
}
/** The OID of the algorithm a DER certificate is signed with: Certificate ::= SEQUENCE { tbs, signatureAlgorithm, signature }. */
export function certSignatureOid(der) {
    try {
        if (der[0] !== 0x30)
            return null;
        let [, i] = readLen(der, 1); // into Certificate
        if (der[i] !== 0x30)
            return null;
        const [tbsLen, tbsStart] = readLen(der, i + 1);
        i = tbsStart + tbsLen; // skip tbsCertificate
        if (der[i] !== 0x30)
            return null;
        [, i] = readLen(der, i + 1); // into AlgorithmIdentifier
        if (der[i] !== 0x06)
            return null;
        const [oidLen, oidStart] = readLen(der, i + 1);
        return oidString(der.subarray(oidStart, oidStart + oidLen));
    }
    catch {
        return null;
    }
}
export function certSignature(der) {
    const oid = certSignatureOid(der);
    return oid ? (SIG_OIDS[oid] ?? { name: `other (${oid})` }) : null;
}
export function certKey(cert) {
    try {
        const k = cert.publicKey;
        const t = k.asymmetricKeyType ?? "";
        const d = (k.asymmetricKeyDetails ?? {});
        if (t === "rsa" || t === "rsa-pss")
            return { type: "RSA", bits: d.modulusLength };
        if (t === "ec")
            return { type: "ECDSA", curve: d.namedCurve };
        if (t === "ed25519")
            return { type: "Ed25519" };
        if (t === "ed448")
            return { type: "Ed448" };
        if (t.startsWith("ml-dsa"))
            return { type: "ML-DSA" };
        return { type: "other" };
    }
    catch {
        return { type: "other" };
    }
}
/** Turns a certificate into findings: expiry, weak signing, small keys, and its quantum status. */
export function certFindings(cert, host, label, authorized, authError, now = Date.now()) {
    const out = [];
    const base = { area: "web", target: label, internetFacing: true };
    const sig = certSignature(Buffer.from(cert.raw));
    const key = certKey(cert);
    if (Date.parse(cert.validTo) < now) {
        out.push({ ...base, ruleId: "web-cert-expired", title: "Certificate has expired", algorithm: "Expired certificate", primitive: "protocol", risk: "weak-now", severity: "high", fix: "Renew the certificate. Browsers and clients refuse expired ones." });
    }
    if (!cert.checkHost(host)) {
        out.push({ ...base, ruleId: "web-cert-name", title: "Certificate doesn't match this hostname", algorithm: "Certificate name mismatch", primitive: "protocol", risk: "exposed", severity: "medium", fix: "Use a certificate that names this hostname." });
    }
    else if (authorized === false && authError && !/CERT_HAS_EXPIRED/i.test(authError)) {
        const self = /SELF_SIGNED|self.signed/i.test(authError);
        out.push({
            ...base,
            ruleId: self ? "web-cert-self-signed" : "web-cert-untrusted",
            title: self ? "Certificate is self-signed" : "Certificate isn't trusted by standard clients",
            algorithm: self ? "Self-signed certificate" : "Untrusted certificate",
            primitive: "protocol",
            risk: "exposed",
            severity: "medium",
            fix: "Use a certificate from a public certificate authority, or serve the full chain.",
        });
    }
    if (sig?.weak) {
        out.push({ ...base, ruleId: "web-cert-weak-signature", title: `Certificate signed with ${sig.name}`, algorithm: /MD5/.test(sig.name) ? "MD5" : "SHA-1", primitive: "hash", risk: "weak-now", severity: "high", fix: "Reissue the certificate signed with SHA-256 or stronger." });
    }
    if (key.type === "RSA" && key.bits && key.bits < 2048) {
        out.push({ ...base, ruleId: "web-cert-small-rsa", title: `Certificate uses a ${key.bits}-bit RSA key`, algorithm: "RSA", primitive: "signature", risk: "weak-now", severity: "high", keySize: key.bits, fix: "Reissue with at least a 2048-bit RSA key, or ECDSA P-256." });
    }
    else if (key.type === "RSA" || key.type === "ECDSA" || key.type === "Ed25519" || key.type === "Ed448") {
        const alg = key.type === "RSA" ? "RSA signature" : key.type;
        out.push({
            ...base,
            ruleId: "web-cert-quantum",
            title: `Certificate uses ${key.type === "RSA" ? `${key.bits ?? ""}-bit RSA`.trim() : key.type}${sig ? `, signed with ${sig.name}` : ""}`,
            algorithm: alg,
            primitive: "signature",
            risk: "quantum-vulnerable",
            severity: "medium",
            keySize: key.bits,
            fix: "Plan to move to ML-DSA certificates once your certificate authority offers them. Short-lived certificates make the switch easy.",
        });
    }
    return { findings: out, pqc: key.type === "ML-DSA" || Boolean(sig?.pqc) };
}
// ---------- raw cipher suite probe ----------
// Recent OpenSSL builds (Node.js 22 and later) can't offer 3DES at all, so a normal handshake can't test it.
// This sends one ordinary TLS 1.2 ClientHello listing only the given cipher suites, reads the server's
// answer (ServerHello or an alert) and hangs up. No keys are exchanged.
export const SUITES_3DES = [0x000a, 0xc012, 0xc008, 0x0016, 0x0013];
function u16(n) {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(n);
    return b;
}
const vec16 = (b) => Buffer.concat([u16(b.length), b]);
const ext = (type, body) => Buffer.concat([u16(type), vec16(body)]);
export function clientHello(host, suites) {
    const name = Buffer.from(host, "ascii");
    const sni = vec16(Buffer.concat([Buffer.from([0]), vec16(name)]));
    const exts = Buffer.concat([
        isIP(host) ? Buffer.alloc(0) : ext(0x0000, sni),
        ext(0x000a, vec16(Buffer.concat([0x001d, 0x0017, 0x0018].map(u16)))), // groups: x25519, P-256, P-384
        ext(0x000b, Buffer.from([1, 0])), // uncompressed points
        ext(0x000d, vec16(Buffer.concat([0x0401, 0x0501, 0x0201, 0x0403, 0x0503, 0x0203, 0x0804].map(u16)))),
        ext(0xff01, Buffer.from([0])), // renegotiation info
    ]);
    const body = Buffer.concat([
        Buffer.from([0x03, 0x03]), // TLS 1.2
        randomBytes(32),
        Buffer.from([0]), // no session id
        vec16(Buffer.concat(suites.map(u16))),
        Buffer.from([1, 0]), // no compression
        vec16(exts),
    ]);
    const hs = Buffer.concat([Buffer.from([1, (body.length >> 16) & 255, (body.length >> 8) & 255, body.length & 255]), body]);
    return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), vec16(hs)]);
}
/** The cipher suite a ServerHello picked, null for an alert, undefined while more bytes are needed. */
export function serverHelloSuite(buf) {
    if (buf.length < 5)
        return undefined;
    if (buf[0] === 0x15)
        return null; // alert: the server refused every suite offered
    if (buf[0] !== 0x16)
        return null;
    if (buf.length < 5 + 4 + 2 + 32 + 1)
        return undefined;
    if (buf[5] !== 0x02)
        return null;
    const sidLen = buf[5 + 4 + 2 + 32];
    const at = 5 + 4 + 2 + 32 + 1 + sidLen;
    if (buf.length < at + 2)
        return undefined;
    return buf.readUInt16BE(at);
}
/** Whether the server accepts one of these TLS 1.2 cipher suites. */
export const acceptsSuites = (host, port, suites, servername) => new Promise((resolveP) => {
    let buf = Buffer.alloc(0);
    let done = false;
    const sock = netConnect({ host, port });
    const finish = (v) => {
        if (done)
            return;
        done = true;
        sock.destroy();
        resolveP(v);
    };
    sock.setTimeout(TIMEOUT_MS, () => finish(false));
    sock.on("error", () => finish(false));
    sock.on("close", () => finish(false));
    sock.on("connect", () => sock.write(clientHello(servername ?? host, suites)));
    sock.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        const suite = serverHelloSuite(buf);
        if (suite === undefined && buf.length < 16384)
            return;
        finish(typeof suite === "number" && suites.includes(suite));
    });
});
const GAP_MS = 250;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** About 6 handshakes, one at a time: normal, hybrid ML-KEM, TLS 1.0, TLS 1.1, 3DES, static RSA key exchange. */
export async function checkTls(t, log, res, hs = handshake, gap = GAP_MS, probe = acceptsSuites) {
    log.record("web", t.label, "TLS handshake, normal settings");
    const main = await hs(t.host, t.port, { minVersion: "TLSv1.2" });
    if (!main.ok) {
        // Can't reach it at all: don't try again.
        if (main.error === "dns" || main.error === "refused" || main.error === "timeout") {
            res.errors.push({ area: "web", target: t.label, kind: main.error, message: main.message ?? "couldn't connect" });
            return;
        }
        // Maybe it only speaks old TLS: try once more allowing it before giving up.
        await sleep(gap);
        log.record("web", t.label, "TLS handshake allowing TLS 1.0");
        const old = await hs(t.host, t.port, { minVersion: "TLSv1", ciphers: "DEFAULT:@SECLEVEL=0" });
        if (!old.ok) {
            res.errors.push({ area: "web", target: t.label, kind: main.error ?? "other", message: main.message ?? "couldn't connect" });
            return;
        }
        Object.assign(main, old);
    }
    res.checked.push(t.label);
    const base = { area: "web", target: t.label, internetFacing: true };
    // Key exchange: does it offer the quantum-safe hybrid?
    let hybrid = null;
    if (main.protocol === "TLSv1.3" && canTestHybrid()) {
        await sleep(gap);
        log.record("web", t.label, "TLS handshake offering only hybrid X25519 + ML-KEM-768");
        const h = await hs(t.host, t.port, { minVersion: "TLSv1.3", ecdhCurve: "X25519MLKEM768" });
        hybrid = h.ok;
    }
    if (hybrid) {
        res.strengths.push({ area: "web", target: t.label, algorithm: "Hybrid ML-KEM key exchange", title: "Offers quantum-safe hybrid key exchange (X25519 + ML-KEM-768)" });
    }
    else {
        const kx = main.keyExchange ?? "ECDH";
        res.findings.push({
            ...base,
            ruleId: "web-tls-kex",
            title: `Key exchange uses ${kx}${hybrid === null ? "" : " with no quantum-safe option"}${main.protocol !== "TLSv1.3" ? `, over ${main.protocol ?? "an old TLS version"}` : ""}`,
            algorithm: "TLS key exchange",
            primitive: "key-agreement",
            risk: "quantum-vulnerable",
            severity: "high",
            fix: main.protocol === "TLSv1.3"
                ? "Turn on hybrid X25519MLKEM768 key exchange. Recent OpenSSL (3.5+), BoringSSL, nginx, Caddy and most CDNs support it."
                : "Move to TLS 1.3 first, then turn on hybrid X25519MLKEM768 key exchange.",
        });
        if (hybrid === null && main.protocol === "TLSv1.3")
            res.skipped.push({ target: t.label, reason: "this Node.js can't test hybrid ML-KEM key exchange (needs OpenSSL 3.5 or later)" });
    }
    if (main.cert) {
        const c = certFindings(main.cert, t.host, t.label, main.authorized, main.authError);
        res.findings.push(...c.findings);
        if (c.pqc)
            res.strengths.push({ area: "web", target: t.label, algorithm: "ML-DSA", title: "Certificate uses ML-DSA" });
    }
    // Old TLS versions.
    const old = [];
    for (const v of ["TLSv1", "TLSv1.1"]) {
        await sleep(gap);
        log.record("web", t.label, `TLS handshake allowing only ${v === "TLSv1" ? "TLS 1.0" : "TLS 1.1"}`);
        const r = await hs(t.host, t.port, { minVersion: v, maxVersion: v, ciphers: "DEFAULT:@SECLEVEL=0" });
        if (r.ok)
            old.push(v === "TLSv1" ? "TLS 1.0" : "TLS 1.1");
    }
    if (old.length) {
        const a = ALGORITHMS["TLS 1.0/1.1"];
        res.findings.push({ ...base, ruleId: "web-tls-old", title: `Accepts ${old.join(" and ")}`, algorithm: "TLS 1.0/1.1", primitive: a.primitive, risk: a.risk, severity: a.severity, fix: a.fix });
    }
    // Weak TLS 1.2 cipher suites.
    await sleep(gap);
    log.record("web", t.label, "TLS 1.2 hello offering only 3DES cipher suites (reads the server's answer, then disconnects)");
    if (await probe(t.host, t.port, SUITES_3DES))
        res.findings.push({ ...base, ruleId: "web-tls-3des", title: "Accepts 3DES cipher suites", algorithm: "3DES", primitive: "block-cipher", risk: "weak-now", severity: "high", fix: ALGORITHMS["Weak TLS ciphers"].fix });
    await sleep(gap);
    log.record("web", t.label, "TLS 1.2 handshake offering only static RSA key exchange");
    const rsa = await hs(t.host, t.port, { minVersion: "TLSv1", maxVersion: "TLSv1.2", ciphers: "AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:@SECLEVEL=0" });
    if (rsa.ok) {
        // With TLS 1.3 on offer, current browsers and clients never pick static RSA (TLS 1.3 also blocks
        // downgrades), so only old clients are exposed. Still worth fixing, but not an emergency.
        const modern = main.protocol === "TLSv1.3";
        res.findings.push({
            ...base,
            ruleId: "web-tls-static-rsa",
            title: modern ? "Still accepts static RSA key exchange from old clients (no forward secrecy for them)" : "Accepts static RSA key exchange (no forward secrecy)",
            algorithm: "Static RSA key exchange",
            primitive: "key-agreement",
            risk: modern ? "exposed" : "weak-now",
            severity: modern ? "low" : "medium",
            fix: modern
                ? "Allow only ECDHE cipher suites for TLS 1.2. Some hosts charge for this (on Cloudflare, custom cipher suites need Advanced Certificate Manager). If you can't change it now, accept it as a known leftover in .quantum-scan-ignore."
                : "Allow only ECDHE cipher suites. With static RSA, anyone who later gets the key can read every recorded session.",
        });
    }
}
function nameList(buf, off) {
    const len = buf.readUInt32BE(off);
    const s = buf.subarray(off + 4, off + 4 + len).toString("latin1");
    return [s ? s.split(",") : [], off + 4 + len];
}
/** Parses the server's SSH_MSG_KEXINIT packet (RFC 4253, section 7.1). */
export function parseKexInit(packet) {
    try {
        const len = packet.readUInt32BE(0);
        const pad = packet[4];
        const payload = packet.subarray(5, 4 + len - pad);
        if (payload[0] !== 20)
            return null;
        let off = 17; // message byte + 16-byte cookie
        const lists = [];
        for (let i = 0; i < 6; i++) {
            const [l, next] = nameList(payload, off);
            lists.push(l);
            off = next;
        }
        return { kex: lists[0], hostKeys: lists[1], ciphers: lists[2], macs: lists[4] };
    }
    catch {
        return null;
    }
}
export const CLIENT_BANNER = "SSH-2.0-HardKeelQuantumScan_1.0";
/** Reads the server's banner and the settings it announces, then hangs up. No keys are exchanged and no login is tried. */
export function sshKexInit(host, port) {
    return new Promise((resolveP) => {
        let buf = Buffer.alloc(0);
        let banner = null;
        let done = false;
        const sock = netConnect({ host, port });
        const finish = (v) => {
            if (done)
                return;
            done = true;
            sock.destroy();
            resolveP(v);
        };
        sock.setTimeout(TIMEOUT_MS, () => finish({ error: "timeout", message: "timed out" }));
        sock.on("error", (e) => finish({ error: errorKind(e), message: e.message }));
        sock.on("connect", () => sock.write(`${CLIENT_BANNER}\r\n`));
        sock.on("data", (d) => {
            buf = Buffer.concat([buf, d]);
            if (buf.length > 65536)
                return finish({ error: "ssh", message: "server sent too much data" });
            while (banner === null) {
                const nl = buf.indexOf(0x0a);
                if (nl < 0)
                    return;
                const line = buf.subarray(0, nl).toString("latin1").replace(/\r$/, "");
                buf = buf.subarray(nl + 1);
                if (line.startsWith("SSH-"))
                    banner = line;
                else if (buf.length === 0)
                    return;
            }
            if (buf.length < 5)
                return;
            const len = buf.readUInt32BE(0);
            if (len > 35000)
                return finish({ error: "ssh", message: "unexpected packet" });
            if (buf.length < 4 + len)
                return;
            const k = parseKexInit(buf.subarray(0, 4 + len));
            finish(k ? { banner, ...k } : { error: "ssh", message: "couldn't read the server's settings" });
        });
    });
}
const SSH_PQC_KEX = /^(mlkem768x25519-sha256|sntrup761x25519-sha512(@openssh\.com)?|mlkem768nistp256-sha256|mlkem1024nistp384-sha384)$/;
const SSH_WEAK_KEX = /^(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)$/;
const SSH_WEAK_CIPHER = /(^3des|^arcfour|^blowfish|^cast128|-cbc$|^des)/;
const SSH_WEAK_MAC = /^(hmac-md5|hmac-sha1|hmac-md5-96|hmac-sha1-96|umac-64)(-etm@openssh\.com)?$/;
export function sshFindings(k, area, target, internetFacing) {
    const out = [];
    const base = { area, target, internetFacing };
    const pqc = k.kex.some((x) => SSH_PQC_KEX.test(x));
    if (!pqc) {
        out.push({ ...base, ruleId: "ssh-kex", title: `SSH key exchange has no quantum-safe option (offers ${k.kex.filter((x) => !x.startsWith("ext-info") && !x.startsWith("kex-strict")).slice(0, 2).join(", ")})`, algorithm: "SSH key exchange", primitive: "key-agreement", risk: "quantum-vulnerable", severity: "high", fix: "Upgrade to OpenSSH 9.9 or later and allow mlkem768x25519-sha256 (or sntrup761x25519-sha512) key exchange." });
    }
    const weak = [...k.kex.filter((x) => SSH_WEAK_KEX.test(x)), ...k.ciphers.filter((x) => SSH_WEAK_CIPHER.test(x)), ...k.macs.filter((x) => SSH_WEAK_MAC.test(x)), ...k.hostKeys.filter((x) => x === "ssh-dss" || x === "ssh-rsa")];
    if (weak.length) {
        out.push({ ...base, ruleId: "ssh-weak", title: `SSH allows weak settings: ${[...new Set(weak)].slice(0, 4).join(", ")}`, algorithm: "SSH weak settings", primitive: "protocol", risk: "weak-now", severity: "medium", fix: "Remove SHA-1, CBC, 3DES and arcfour options from KexAlgorithms, Ciphers, MACs and HostKeyAlgorithms." });
    }
    const hk = k.hostKeys.filter((x) => x !== "ssh-dss");
    if (hk.length) {
        out.push({ ...base, ruleId: "ssh-host-key", title: `SSH host keys use ${[...new Set(hk.map(hostKeyFamily))].join(", ")}`, algorithm: "SSH host key", primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: "Plan to move host keys to post-quantum signatures once OpenSSH supports them; keep Ed25519 until then." });
    }
    return { findings: out, pqc };
}
function hostKeyFamily(x) {
    if (x.includes("ed25519"))
        return "Ed25519";
    if (x.includes("ecdsa"))
        return "ECDSA";
    if (x.includes("rsa"))
        return "RSA";
    return x;
}
export async function checkSsh(t, log, res, ssh = sshKexInit) {
    log.record("web", t.label, "SSH connection: read the server's announced settings, then disconnect (no login)");
    const k = await ssh(t.host, t.port);
    if ("error" in k) {
        res.errors.push({ area: "web", target: t.label, kind: k.error, message: k.message });
        return;
    }
    res.checked.push(t.label);
    const r = sshFindings(k, "web", t.label, true);
    res.findings.push(...r.findings);
    if (r.pqc)
        res.strengths.push({ area: "web", target: t.label, algorithm: "Hybrid SSH key exchange", title: "SSH offers quantum-safe hybrid key exchange" });
}
export const MAX_WEB_TARGETS = 200;
/** Runs the website area: proves each domain, then checks only addresses under a proved domain. */
export async function runWeb(targets, log, o) {
    const res = { ...emptyResult("web"), unproved: [], dnsFailed: [] };
    const fallback = o.fallbackLookup !== undefined ? o.fallbackLookup : o.lookup ? null : publicLookup();
    const parsed = [];
    for (const raw of targets.slice(0, MAX_WEB_TARGETS)) {
        const p = parseTarget(raw);
        if ("error" in p)
            res.skipped.push({ target: raw, reason: p.error });
        else if (!parsed.some((x) => x.label === p.label))
            parsed.push(p);
    }
    if (targets.length > MAX_WEB_TARGETS)
        res.skipped.push({ target: `${targets.length - MAX_WEB_TARGETS} more`, reason: `at most ${MAX_WEB_TARGETS} addresses per run` });
    const proved = [];
    const tried = new Map();
    for (const t of parsed) {
        if (coveringDomain(t.host, proved))
            continue;
        let found = null;
        for (const d of parentDomains(t.host)) {
            if (tried.has(d))
                continue;
            const r = await checkProof(d, o.token, log, o.lookup, fallback);
            tried.set(d, r);
            if (r.status === "found") {
                found = d;
                break;
            }
        }
        if (found)
            proved.push(found);
    }
    for (const t of parsed) {
        if (!coveringDomain(t.host, proved)) {
            const failed = parentDomains(t.host).map((d) => tried.get(d)).find((r) => r?.status === "lookup-failed");
            if (failed) {
                res.errors.push({ area: "web", target: t.label, kind: "dns", message: `couldn't look up the ownership record: ${failed.detail ?? "DNS didn't answer"}` });
                if (!res.dnsFailed.includes(t.label))
                    res.dnsFailed.push(t.label);
                continue;
            }
            res.skipped.push({ target: t.label, reason: "no ownership record found for this domain" });
            if (!res.unproved.includes(registrable(t.host)))
                res.unproved.push(registrable(t.host));
            continue;
        }
        if (t.kind === "ssh")
            await checkSsh(t, log, res, o.ssh);
        else
            await checkTls(t, log, res, o.handshake, o.gapMs, o.cipherProbe);
    }
    return res;
}
/** A best guess at the domain someone would put the record on: the last two labels. */
export function registrable(host) {
    return host.split(".").slice(-2).join(".");
}
