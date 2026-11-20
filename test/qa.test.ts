// Regression tests for the bugs found in QA pass 1 (qa/QA-LOG.md). Each test names its log entry.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer as netServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as tlsServer } from "node:tls";
import { X509Certificate } from "node:crypto";
import { ActivityLog } from "../src/map-activity.ts";
import { applyIgnore, applyIgnoreTargets, parseIgnore } from "../src/ignore.ts";
import { buildMapReport, mapHtml, mapText } from "../src/map-report.ts";
import { rank } from "../src/map-rank.ts";
import { runMap } from "../src/map-run.ts";
import { emptyResult, type MapFinding } from "../src/map-types.ts";
import { acceptsSuites, certFindings, checkProof, checkTls, clientHello, handshake, runWeb, serverHelloSuite, SUITES_3DES, type Handshake } from "../src/map-web.ts";
import { loadSettings } from "../src/share-config.ts";
import { walkFolder } from "../src/walk.ts";
import type { Finding } from "../src/types.ts";

const dnsError = (code: string) => Object.assign(new Error(code), { code });
const TOKEN = "a".repeat(24);
const RECORD = [[`hardkeel-scan-verify=${TOKEN}`]];

// ---------- QA-1: ownership check when this machine's DNS doesn't answer ----------

test("QA-1: a refused local resolver falls back to a public resolver, and the log says so", async () => {
  const log = new ActivityLog();
  const r = await checkProof("example.com", TOKEN, log, async () => { throw dnsError("ECONNREFUSED"); }, async () => RECORD);
  assert.equal(r.status, "found");
  assert.ok(log.entries.some((e) => /public resolver/.test(e) && /ECONNREFUSED/.test(e)));
});

test("QA-1: 'no such record' is an answer, so no fallback is asked", async () => {
  let asked = false;
  const r = await checkProof("example.com", TOKEN, new ActivityLog(), async () => { throw dnsError("ENODATA"); }, async () => { asked = true; return RECORD; });
  assert.equal(r.status, "missing");
  assert.equal(asked, false);
});

test("QA-1: when DNS never answers, the address is reported as couldn't check, not as unproved", async () => {
  const res = await runWeb(["www.example.com"], new ActivityLog(), { token: TOKEN, lookup: async () => { throw dnsError("ECONNREFUSED"); }, fallbackLookup: async () => { throw dnsError("ETIMEOUT"); }, gapMs: 0 });
  assert.deepEqual(res.unproved, []);
  assert.deepEqual(res.dnsFailed, ["www.example.com:443"]);
  assert.equal(res.errors[0].kind, "dns");
  assert.match(res.errors[0].message, /DNS didn't answer/);
  assert.ok(!res.skipped.some((s) => /no ownership record/.test(s.reason)));
});

// ---------- QA-2: the map has an overall readiness score ----------

const mf = (o: Partial<MapFinding>): MapFinding => ({ area: "web", target: "example.com:443", ruleId: "web-cert-quantum", title: "t", algorithm: "ECDSA", primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: "f", internetFacing: true, ...o });

test("QA-2: the map report carries the method v1 score, with credit for quantum-safe key exchange", () => {
  const res = { ...emptyResult("web"), findings: [mf({})], strengths: [{ area: "web" as const, target: "example.com:443", algorithm: "Hybrid ML-KEM key exchange", title: "hybrid" }] };
  const r = buildMapReport([res], rank(res.findings), "0.2.0");
  assert.equal(r.score.method, "1");
  assert.equal(r.score.grade, "A");
  assert.equal(r.score.pqc.keyExchange, true);
  assert.match(mapText(r), /^Hard Keel Quantum Scan · encryption map\n\nQuantum readiness: A/);
  assert.match(mapHtml(r, []), /Quantum readiness \d+\/100/);
});

// ---------- QA-3: one unreadable folder doesn't stop the scan ----------

test("QA-3: a missing folder gives a plain message", () => {
  assert.throws(() => walkFolder(join(tmpdir(), "qs-does-not-exist-" + Date.now())), /that folder doesn't exist/);
});

const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
test("QA-3: a locked subfolder is skipped and listed, the rest is still scanned", { skip: (isRoot || process.platform === "win32") && "permissions don't apply to root or work differently on Windows" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-locked-"));
  mkdirSync(join(dir, "locked"));
  writeFileSync(join(dir, "locked", "a.py"), "x = 1\n");
  writeFileSync(join(dir, "ok.py"), "x = 1\n");
  chmodSync(join(dir, "locked"), 0o000);
  try {
    const w = walkFolder(dir);
    assert.deepEqual(w.files.map((f) => f.path), ["ok.py"]);
    assert.deepEqual(w.unreadable, [{ path: "locked/", reason: "permission denied" }]);
  } finally {
    chmodSync(join(dir, "locked"), 0o755);
  }
});

// ---------- QA-4: 3DES is tested even where Node.js can't offer it ----------

function fakeTls(answer: number | null): Promise<{ port: number; close: () => void }> {
  return new Promise((resolve) => {
    const srv = netServer((c) => {
      c.on("error", () => {});
      c.once("data", () => {
        if (answer === null) return void c.end(Buffer.from([0x15, 3, 3, 0, 2, 2, 40]));
        const body = Buffer.concat([Buffer.from([3, 3]), Buffer.alloc(32, 7), Buffer.from([0, answer >> 8, answer & 255, 0, 0, 0])]);
        const hs = Buffer.concat([Buffer.from([2, 0, 0, body.length]), body]);
        c.write(Buffer.concat([Buffer.from([0x16, 3, 3, 0, hs.length]), hs]));
      });
    });
    srv.listen(0, "127.0.0.1", () => resolve({ port: (srv.address() as { port: number }).port, close: () => srv.close() }));
  });
}

test("QA-4: the 3DES probe reads the server's choice, and an alert means no", async () => {
  const yes = await fakeTls(0x000a);
  const no = await fakeTls(null);
  try {
    assert.equal(await acceptsSuites("127.0.0.1", yes.port, SUITES_3DES), true);
    assert.equal(await acceptsSuites("127.0.0.1", no.port, SUITES_3DES), false);
  } finally {
    yes.close();
    no.close();
  }
  const hello = clientHello("example.com", SUITES_3DES);
  assert.equal(hello[0], 0x16);
  assert.equal(hello.readUInt16BE(3), hello.length - 5);
  assert.ok(hello.includes(Buffer.from("example.com")));
  assert.equal(serverHelloSuite(Buffer.from([0x15, 3, 3, 0, 2, 2, 40])), null);
  assert.equal(serverHelloSuite(Buffer.from([0x16, 3, 3])), undefined);
});

// ---------- QA-6: static RSA next to TLS 1.3 ----------

test("QA-6: static RSA on a server that offers TLS 1.3 is a low-severity leftover, and can be accepted", async () => {
  const hs = async (_h: string, _p: number, o: Record<string, unknown>): Promise<Handshake> => {
    if (o.ecdhCurve) return { ok: true, protocol: "TLSv1.3" };
    if (o.maxVersion === "TLSv1" || o.maxVersion === "TLSv1.1") return { ok: false, error: "tls" };
    return { ok: true, protocol: o.maxVersion === "TLSv1.2" ? "TLSv1.2" : "TLSv1.3", keyExchange: "X25519" };
  };
  const res = emptyResult("web");
  await checkTls({ host: "example.com", port: 443, kind: "tls", label: "example.com:443" }, new ActivityLog(), res, hs, 0, async () => false);
  const rsa = res.findings.find((f) => f.ruleId === "web-tls-static-rsa")!;
  assert.equal(rsa.severity, "low");
  assert.match(rsa.title, /old clients/);
  assert.match(rsa.fix, /Advanced Certificate Manager/);

  const entries = parseIgnore("example.com:443:web-tls-static-rsa\n");
  const a = applyIgnoreTargets(res.findings, entries);
  assert.deepEqual(a.accepted.map((f) => f.ruleId), ["web-tls-static-rsa"]);
  const r = buildMapReport([{ ...res, findings: a.kept }], rank(a.kept), "0.2.0", new Date(), a.accepted);
  assert.ok(!r.findings.some((f) => f.ruleId === "web-tls-static-rsa"));
  assert.equal(r.accepted.length, 1);
  assert.match(mapHtml(r, []), /Accepted as known leftovers/);
});

test("QA-6: accepted leftovers from .quantum-scan-ignore are left out of the map's score", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-accept-"));
  writeFileSync(join(dir, "scope.json"), JSON.stringify({ version: 1, ownershipToken: TOKEN, areas: { web: { targets: ["example.com"] } } }));
  const web = { lookup: async () => RECORD, gapMs: 0, cipherProbe: async () => false, handshake: async (_h: string, _p: number, o: Record<string, unknown>): Promise<Handshake> => (o.maxVersion === "TLSv1" || o.maxVersion === "TLSv1.1" ? { ok: false, error: "tls" } : { ok: true, protocol: o.maxVersion === "TLSv1.2" ? "TLSv1.2" : "TLSv1.3", keyExchange: "X25519" }) };
  const opts = { scopePath: join(dir, "scope.json"), cwd: dir, version: "0.2.0", settings: loadSettings(join(dir, "s.json")), sharingOn: false, interactive: false, write: () => {}, web };
  const before = await runMap({ ...opts, outDir: join(dir, "m1") });
  writeFileSync(join(dir, ".quantum-scan-ignore"), "example.com:443:web-tls-static-rsa\n");
  const after = await runMap({ ...opts, outDir: join(dir, "m2") });
  assert.ok(before.report!.findings.some((f) => f.ruleId === "web-tls-static-rsa"));
  assert.ok(!after.report!.findings.some((f) => f.ruleId === "web-tls-static-rsa"));
  assert.ok(after.report!.score.score > before.report!.score.score);
  assert.equal(after.facts!.ignored["web-tls-static-rsa"], 1);
  assert.ok("score" in JSON.parse(readFileSync(join(dir, "m2", "map.json"), "utf8")));
});

// ---------- QA-7: Windows-style paths in .quantum-scan-ignore ----------

const cf = (file: string, ruleId = "py-weak-hash"): Finding => ({ kind: "crypto", ruleId, title: "t", algorithm: "MD5", primitive: "hash", risk: "weak-now", severity: "medium", file, line: 1, snippet: "", fix: "" });

test("QA-7: backslash paths match, and host:port is a place, not a rule named 443", () => {
  assert.equal(applyIgnore([cf("legacy/old.py")], parseIgnore("legacy\\old.py\r\n")).kept.length, 0);
  assert.equal(applyIgnore([cf("legacy/old.py")], parseIgnore(".\\legacy\\\r\n")).kept.length, 0);
  assert.deepEqual(parseIgnore("example.com:443"), [{ path: "example.com:443" }]);
  assert.equal(applyIgnoreTargets([mf({ target: "example.com:443" }), mf({ target: "api.example.com:443" })], parseIgnore("example.com")).accepted.length, 1);
});

// ---------- QA-9 and QA-10: certificate findings ----------

let certDir: string | null = mkdtempSync(join(tmpdir(), "qs-qa-cert-"));
try {
  execFileSync("openssl", ["req", "-x509", "-nodes", "-newkey", "rsa:2048", "-md5", "-days", "3", "-keyout", join(certDir, "k.pem"), "-out", join(certDir, "c.pem"), "-subj", "/CN=md5.example.com", "-addext", "subjectAltName=DNS:md5.example.com"], { stdio: "ignore" });
} catch {
  certDir = null;
}

test("QA-9 and QA-10: an expired certificate isn't also called untrusted, and MD5 is labelled MD5", { skip: !certDir && "needs the openssl command" }, () => {
  const cert = new X509Certificate(readFileSync(join(certDir!, "c.pem")));
  const later = Date.now() + 10 * 86_400_000;
  const r = certFindings(cert, "md5.example.com", "md5.example.com:443", false, "CERT_HAS_EXPIRED", later);
  const ids = r.findings.map((f) => f.ruleId);
  assert.ok(ids.includes("web-cert-expired"));
  assert.ok(!ids.includes("web-cert-untrusted"));
  assert.equal(r.findings.find((f) => f.ruleId === "web-cert-weak-signature")?.algorithm, "MD5");
});

// ---------- the HTML report reads in light mode and on paper ----------

test("report: the HTML has light, dark and print styles and hides the area column on phones", () => {
  const html = mapHtml(buildMapReport([emptyResult("code")], [], "0.2.0"), []);
  assert.match(html, /prefers-color-scheme:dark/);
  assert.match(html, /@media print/);
  assert.match(html, /max-width:640px\)\{\.area\{display:none\}/);
  assert.ok(!/\bcrypto\b/i.test(html.replace(/<style>[\s\S]*?<\/style>/, "")));
});

// ---------- a real handshake still works end to end ----------

test("tls: real OpenSSL accepts the hand-built hello", { skip: !certDir && "needs the openssl command" }, async () => {
  const srv = await new Promise<{ port: number; close: () => void }>((resolve) => {
    const s = tlsServer({ key: readFileSync(join(certDir!, "k.pem")), cert: readFileSync(join(certDir!, "c.pem")), ciphers: "AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0" }, (c) => c.end());
    s.on("tlsClientError", () => {});
    s.listen(0, "127.0.0.1", () => resolve({ port: (s.address() as { port: number }).port, close: () => s.close() }));
  });
  try {
    assert.equal(await acceptsSuites("127.0.0.1", srv.port, [0x002f], "md5.example.com"), true);
    assert.equal(await acceptsSuites("127.0.0.1", srv.port, SUITES_3DES, "md5.example.com"), false);
    assert.ok((await handshake("127.0.0.1", srv.port, { servername: "md5.example.com" })).ok);
  } finally {
    srv.close();
  }
});
