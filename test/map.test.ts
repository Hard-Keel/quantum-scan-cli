import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, X509Certificate } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as netServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as tlsServer } from "node:tls";
import { ActivityLog } from "../src/map-activity.ts";
import { opensshVersion, opensslPolicyFindings, parseSchannel, parseSshd, parseWindowsCerts, runHost, sshPublicKey, type HostIO } from "../src/map-host.ts";
import { rank, tierOf } from "../src/map-rank.ts";
import { parseScope, runMap, type Prompter } from "../src/map-run.ts";
import type { MapFinding } from "../src/map-types.ts";
import { canTestHybrid, certFindings, certSignatureOid, checkTls, coveringDomain, handshake, parentDomains, parseKexInit, parseTarget, proofRecord, runWeb, sshKexInit, type Handshake } from "../src/map-web.ts";
import { emptyResult } from "../src/map-types.ts";
import { loadSettings } from "../src/share-config.ts";

// Throwaway self-signed certificates, made fresh for each run so no keys live in the repository.
// test-*: RSA 2048, SHA-256, for localhost. weak-*: RSA 1024, SHA-1, for old.example.com, valid 1 day.
const fxDir = mkdtempSync(join(tmpdir(), "qs-tls-"));
let haveOpenssl = true;
try {
  const req = (name: string, args: string[]) =>
    execFileSync("openssl", ["req", "-x509", "-nodes", "-keyout", join(fxDir, `${name}-key.pem`), "-out", join(fxDir, `${name}-cert.pem`), ...args], { stdio: "ignore" });
  req("test", ["-newkey", "rsa:2048", "-sha256", "-days", "30", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"]);
  req("weak", ["-newkey", "rsa:1024", "-sha1", "-days", "1", "-subj", "/CN=old.example.com"]);
} catch {
  haveOpenssl = false;
}
const fx = (n: string) => readFileSync(join(fxDir, n));

test("targets: hostnames only, ports pick TLS or SSH, IP addresses refused", () => {
  assert.deepEqual(parseTarget("Example.com"), { host: "example.com", port: 443, kind: "tls", label: "example.com:443" });
  assert.deepEqual(parseTarget("https://api.example.com:8443/path"), { host: "api.example.com", port: 8443, kind: "tls", label: "api.example.com:8443" });
  assert.equal((parseTarget("ssh://git.example.com") as { kind: string }).kind, "ssh");
  assert.equal((parseTarget("git.example.com:22") as { kind: string }).kind, "ssh");
  assert.ok("error" in parseTarget("10.0.0.5"));
  assert.ok("error" in parseTarget("8.8.8.8:443"));
  assert.ok("error" in parseTarget("ftp://example.com"));
  assert.ok("error" in parseTarget("localhost"));
});

test("ownership: one record covers a domain and everything under it, never a look-alike", () => {
  assert.equal(coveringDomain("api.example.com", ["example.com"]), "example.com");
  assert.equal(coveringDomain("example.com", ["example.com"]), "example.com");
  assert.equal(coveringDomain("badexample.com", ["example.com"]), null);
  assert.equal(coveringDomain("example.com.evil.net", ["example.com"]), null);
  assert.deepEqual(parentDomains("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"]);
  assert.deepEqual(proofRecord("example.com", "abc"), { name: "_hardkeel-scan.example.com", value: "hardkeel-scan-verify=abc" });
});

test("web: addresses under an unproved domain are never contacted", async () => {
  const contacted: string[] = [];
  const hs = async (host: string): Promise<Handshake> => {
    contacted.push(host);
    return { ok: false, error: "refused", message: "no" };
  };
  const lookup = async (name: string) => (name === "_hardkeel-scan.ours.com" ? [["hardkeel-scan-verify=tok"]] : name === "_hardkeel-scan.theirs.com" ? [["hardkeel-scan-verify=wrong"]] : []);
  const log = new ActivityLog();
  const res = await runWeb(["www.ours.com", "theirs.com", "shop.theirs.com", "1.2.3.4"], log, { token: "tok", lookup, handshake: hs, gapMs: 0 });
  assert.ok(contacted.every((h) => h === "www.ours.com"));
  assert.ok(contacted.length > 0);
  assert.deepEqual(res.unproved, ["theirs.com"]);
  assert.equal(res.skipped.filter((s) => s.reason.includes("ownership")).length, 2);
  assert.ok(res.skipped.some((s) => s.target === "1.2.3.4"));
  assert.ok(log.entries.some((e) => e.includes("_hardkeel-scan.ours.com")));
});

test("tls: certificate signature algorithm and findings from the certificate", { skip: !haveOpenssl && "needs the openssl command" }, () => {
  const good = new X509Certificate(fx("test-cert.pem"));
  assert.equal(certSignatureOid(Buffer.from(good.raw)), "1.2.840.113549.1.1.11");
  const g = certFindings(good, "localhost", "localhost:443", true, undefined);
  assert.deepEqual(g.findings.map((f) => f.ruleId), ["web-cert-quantum"]);

  const weak = new X509Certificate(fx("weak-cert.pem"));
  const w = certFindings(weak, "www.example.com", "www.example.com:443", false, "SELF_SIGNED_CERT", Date.now() + 5 * 86_400_000);
  const ids = w.findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ["web-cert-expired", "web-cert-name", "web-cert-small-rsa", "web-cert-weak-signature"]);
});

function startTls(opts: Record<string, unknown>): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const srv = tlsServer({ key: fx("test-key.pem"), cert: fx("test-cert.pem"), ...opts }, (s) => s.end());
    srv.on("tlsClientError", () => {});
    srv.listen(0, "127.0.0.1", () => resolve({ port: (srv.address() as { port: number }).port, close: () => srv.close() }));
  });
}

test("tls: a TLS 1.3 server with hybrid ML-KEM gets credit and no key exchange finding", { skip: (!canTestHybrid() || !haveOpenssl) && "needs OpenSSL 3.5 and the openssl command" }, async () => {
  const srv = await startTls({ ecdhCurve: "X25519MLKEM768:X25519", minVersion: "TLSv1.3" });
  try {
    const res = emptyResult("web");
    const log = new ActivityLog();
    await checkTls({ host: "localhost", port: srv.port, kind: "tls", label: `localhost:${srv.port}` }, log, res, (h, p, o) => handshake("127.0.0.1", p, { ...o, servername: "localhost" }), 0);
    assert.deepEqual(res.strengths.map((s) => s.algorithm), ["Hybrid ML-KEM key exchange"]);
    assert.ok(!res.findings.some((f) => f.ruleId === "web-tls-kex"));
    assert.ok(!res.findings.some((f) => f.ruleId === "web-tls-old"));
    assert.ok(log.entries.length >= 5 && log.entries.length <= 7);
  } finally {
    srv.close();
  }
});

test("tls: a TLS 1.2 server without hybrid is flagged for key exchange and static RSA", { skip: !haveOpenssl && "needs the openssl command" }, async () => {
  const srv = await startTls({ maxVersion: "TLSv1.2", ciphers: "ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256" });
  try {
    const res = emptyResult("web");
    await checkTls({ host: "localhost", port: srv.port, kind: "tls", label: `localhost:${srv.port}` }, new ActivityLog(), res, (h, p, o) => handshake("127.0.0.1", p, { ...o, servername: "localhost" }), 0);
    const ids = res.findings.map((f) => f.ruleId);
    assert.ok(ids.includes("web-tls-kex"));
    assert.ok(ids.includes("web-tls-static-rsa"));
    assert.ok(!ids.includes("web-tls-3des"));
    assert.equal(res.strengths.length, 0);
  } finally {
    srv.close();
  }
});

function kexInitPacket(lists: string[]): Buffer {
  const parts: Buffer[] = [Buffer.from([20]), Buffer.alloc(16)];
  for (const l of [...lists, "none", "none", "", "", ""].slice(0, 10)) {
    const b = Buffer.from(l, "latin1");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    parts.push(len, b);
  }
  parts.push(Buffer.from([0]), Buffer.alloc(4));
  const payload = Buffer.concat(parts);
  const pad = 8 - ((payload.length + 5) % 8) + 4;
  const head = Buffer.alloc(5);
  head.writeUInt32BE(payload.length + pad + 1);
  head[4] = pad;
  return Buffer.concat([head, payload, Buffer.alloc(pad)]);
}

test("ssh: reads the announced settings, then hangs up without a login", async () => {
  const pkt = kexInitPacket(["curve25519-sha256,diffie-hellman-group14-sha1", "ssh-ed25519,rsa-sha2-256", "aes128-ctr,aes256-cbc", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256"]);
  assert.deepEqual(parseKexInit(pkt)?.kex, ["curve25519-sha256", "diffie-hellman-group14-sha1"]);
  let received = "";
  const srv = netServer((s) => {
    // Like OpenSSH: banner first, settings once the client's banner arrives.
    s.write("SSH-2.0-OpenSSH_8.9\r\n");
    s.on("data", (d) => {
      received += d.toString("latin1");
      if (received.includes("\n")) s.write(pkt);
    });
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  try {
    const k = await sshKexInit("127.0.0.1", (srv.address() as { port: number }).port);
    assert.ok(!("error" in k));
    if (!("error" in k)) {
      assert.equal(k.banner, "SSH-2.0-OpenSSH_8.9");
      assert.deepEqual(k.hostKeys, ["ssh-ed25519", "rsa-sha2-256"]);
    }
    assert.match(received, /^SSH-2\.0-HardKeelQuantumScan/);
    assert.equal(received.split("\n").length, 2); // our banner line only
  } finally {
    srv.close();
  }
});

test("rank: broken now, then internet-facing key exchange, then long-lived signatures, then the rest", () => {
  const f = (o: Partial<MapFinding>): MapFinding => ({ area: "web", target: "x", ruleId: "r", title: "t", algorithm: "RSA", primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: "", internetFacing: false, ...o });
  assert.equal(tierOf(f({ risk: "weak-now" })), 1);
  assert.equal(tierOf(f({ primitive: "key-agreement", internetFacing: true })), 2);
  assert.equal(tierOf(f({ primitive: "key-agreement", internetFacing: false })), 4);
  assert.equal(tierOf(f({ longLived: true })), 3);
  assert.deepEqual(rank([f({}), f({ risk: "exposed" }), f({ longLived: true }), f({ primitive: "key-agreement", internetFacing: true })]).map((x) => x.tier), [1, 2, 3, 4]);
});

// ---------- this machine ----------

function sshRsaPub(bits: number): string {
  const { publicKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = publicKey.export({ format: "jwk" }) as { n: string; e: string };
  const mp = (b64: string) => {
    let b = Buffer.from(b64, "base64url");
    if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
    return b;
  };
  const str = (b: Buffer) => {
    const l = Buffer.alloc(4);
    l.writeUInt32BE(b.length);
    return Buffer.concat([l, b]);
  };
  return `ssh-rsa ${Buffer.concat([str(Buffer.from("ssh-rsa")), str(mp(jwk.e)), str(mp(jwk.n))]).toString("base64")} me@laptop`;
}

test("host: public key sizes, sshd settings, OpenSSL policy, Windows settings", () => {
  assert.deepEqual(sshPublicKey(sshRsaPub(1024)), { type: "ssh-rsa", bits: 1024 });
  assert.deepEqual(sshPublicKey(sshRsaPub(3072)), { type: "ssh-rsa", bits: 3072 });
  assert.deepEqual(sshPublicKey("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me"), { type: "ssh-ed25519" });
  assert.equal(opensshVersion("OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13"), 9.6);
  assert.equal(opensshVersion("OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2"), 8.1);

  const s = parseSshd("# x\nKexAlgorithms curve25519-sha256\nCiphers aes256-cbc,aes128-ctr\nMatch User bob\n  Ciphers 3des-cbc\n");
  assert.equal(s.kex, "curve25519-sha256");
  assert.equal(s.ciphers, "aes256-cbc,aes128-ctr");

  assert.deepEqual(opensslPolicyFindings("[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT@SECLEVEL=1\n", "/etc/ssl/openssl.cnf").map((f) => f.ruleId), ["host-openssl-old-tls", "host-openssl-seclevel"]);
  assert.deepEqual(opensslPolicyFindings("MinProtocol = TLSv1.2\nCipherString = DEFAULT@SECLEVEL=2\n", "x"), []);

  const reg = [
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server",
    "    Enabled    REG_DWORD    0x1",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server",
    "    Enabled    REG_DWORD    0x0",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168",
    "    Enabled    REG_DWORD    0xffffffff",
  ].join("\r\n");
  assert.deepEqual(parseSchannel(reg), { enabledProtocols: ["TLS 1.0"], enabledCiphers: ["Triple DES 168"] });
  assert.equal(parseWindowsCerts('{"Subject":"CN=web01","NotAfter":"2030-01-01T00:00:00Z","Sig":"sha256RSA","Key":"RSA","Size":2048}')[0].size, 2048);
});

function fakeIO(files: Record<string, string>, platform: NodeJS.Platform = "linux", run: Record<string, string> = {}): HostIO {
  return {
    platform,
    home: "/home/me",
    read: (p) => files[p] ?? null,
    list: (d) => {
      const names = Object.keys(files).filter((p) => p.startsWith(`${d}/`) && !p.slice(d.length + 1).includes("/")).map((p) => p.slice(d.length + 1));
      return names.length ? names : null;
    },
    run: (cmd) => run[cmd] ?? null,
  };
}

test("host: an old SSH server with a small key is flagged; private keys are never read", () => {
  const reads: string[] = [];
  const files = {
    "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nCiphers 3des-cbc,aes128-ctr\n",
    "/etc/ssh/sshd_config.d/10-kex.conf": "KexAlgorithms curve25519-sha256\n",
    "/etc/ssh/ssh_host_rsa_key.pub": sshRsaPub(1024),
    "/etc/ssh/ssh_host_rsa_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nnot read\n",
    "/home/me/.ssh/id_ed25519.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me",
  };
  const io = fakeIO(files, "linux", { ssh: "OpenSSH_9.6p1" });
  const read = io.read;
  io.read = (p) => {
    reads.push(p);
    return read(p);
  };
  const res = runHost(new ActivityLog(), io);
  const ids = res.findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ["host-key-quantum", "host-key-small-rsa", "ssh-kex", "ssh-weak"]);
  assert.ok(!reads.includes("/etc/ssh/ssh_host_rsa_key"));
});

test("host: a recent OpenSSH with default settings gets credit for hybrid key exchange", () => {
  const res = runHost(new ActivityLog(), fakeIO({ "/etc/ssh/sshd_config": "PermitRootLogin no\n" }, "linux", { ssh: "OpenSSH_9.9p1" }));
  assert.equal(res.strengths.length, 1);
  assert.ok(!res.findings.some((f) => f.ruleId === "ssh-kex"));
});

// ---------- the whole map ----------

test("map: refuses to run unattended without a scope file", async () => {
  const s = loadSettings(join(mkdtempSync(join(tmpdir(), "qs-")), "none.json"));
  const out = await runMap({ outDir: mkdtempSync(join(tmpdir(), "qs-")), cwd: ".", version: "0.0.0", settings: s, sharingOn: false, interactive: false, write: () => {} });
  assert.equal(out.code, 2);
  assert.ok("error" in parseScope('{"version":1,"areas":{"cloud":{}}}'));
});

test("map: the answer is no unless the person says yes", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-"));
  const answers = ["", "", "maybe", ""];
  const p: Prompter = { ask: async () => answers.shift() ?? "", close: () => {} };
  const s = loadSettings(join(dir, "none.json"));
  const out = await runMap({ outDir: join(dir, "out"), cwd: dir, version: "0.0.0", settings: s, sharingOn: false, interactive: true, prompter: () => p, write: () => {} });
  assert.equal(out.code, 0);
  assert.equal(out.facts, undefined);
});

test("map: runs from a scope file, writes the report locally, and the counts carry no targets", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-"));
  writeFileSync(join(dir, "app.py"), "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\nh = hashlib.md5(password)\n");
  writeFileSync(join(dir, "quantum-scan.scope.json"), JSON.stringify({ version: 1, created: "2026-11-20", ownershipToken: "a".repeat(24), areas: { code: { folders: ["."] }, web: { targets: ["secret-host.ours.com"] }, host: {} } }));
  const s = loadSettings(join(dir, "none.json"));
  const log = console.log;
  const out = await runMap({
    scopePath: join(dir, "quantum-scan.scope.json"),
    outDir: join(dir, "map"),
    cwd: dir,
    version: "0.0.0",
    settings: s,
    sharingOn: true,
    interactive: false,
    write: () => {},
    web: { lookup: async () => [[`hardkeel-scan-verify=${"a".repeat(24)}`]], handshake: async (_h, _p, o) => (o.ecdhCurve ? { ok: false, error: "tls" } : { ok: true, protocol: "TLSv1.3", keyExchange: "X25519" }), gapMs: 0 },
    hostIO: fakeIO({ "/etc/ssh/ssh_host_ed25519_key.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA root@secret-host" }),
  }).finally(() => (console.log = log));
  assert.equal(out.code, 0);
  const html = readFileSync(join(dir, "map", "map.html"), "utf8");
  assert.match(html, /secret-host\.ours\.com/);
  assert.match(readFileSync(join(dir, "map", "activity.log"), "utf8"), /DNS lookup/);
  assert.equal(JSON.parse(readFileSync(join(dir, "map", "map.cbom.json"), "utf8")).bomFormat, "CycloneDX");
  const facts = JSON.stringify(out.facts);
  assert.doesNotMatch(facts, /secret-host|ours\.com|app\.py|\/etc\//);
  assert.ok(out.report!.counts[1] >= 1); // MD5 and RSA-1024 are broken now
  assert.ok(out.report!.findings.some((f) => f.ruleId === "web-tls-kex" && f.tier === 2));
});
