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
import { cloudKeyAdvice } from "../src/map-cloud-keys.ts";
import { deviceFindings, machineRanges, readUpnp, runNetwork, suggestedRanges, type NetIO } from "../src/map-network.ts";
import { scorePeople } from "../src/map-people.ts";
import type { Finding } from "../src/types.ts";
import { scanFile } from "../src/scan.ts";

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

// ---------- pass 2 (0.3.0): network, cloud keys, people ----------

const quietNet = (cidr: string, seen: Set<string> = new Set()): NetIO => ({
  interfaces: () => [{ address: cidr.split("/")[0], cidr }],
  probe: async (h) => (seen.add(h), "timeout"),
  http: async () => null,
  cert: async () => null,
  upnp: async () => null,
  sleep: async () => {},
});

test("QA-16: a computer on a /16 can check the /24 it's on, and is offered it", async () => {
  const io = quietNet("10.20.30.40/16");
  assert.equal(machineRanges(io).length, 1);
  assert.deepEqual(suggestedRanges(io), ["10.20.30.0/24"]);
  const seen = new Set<string>();
  const r = await runNetwork({ ranges: ["10.20.30.0/28"] }, new ActivityLog(), { io: quietNet("10.20.30.40/16", seen), gapMs: 0 });
  assert.equal(r.skipped.length, 0);
  assert.equal(seen.size, 14);
  assert.deepEqual(suggestedRanges(quietNet("192.168.1.50/24")), ["192.168.1.0/24"]);
  assert.deepEqual(suggestedRanges(quietNet("192.168.1.50/28")), ["192.168.1.48/28"]);
  assert.deepEqual(suggestedRanges(quietNet("100.64.1.2/10")), [], "carrier-grade or public ranges aren't offered");
});

test("QA-17: router forwards are fetched only from a plain address inside the approved ranges", async () => {
  let hits = 0;
  const srv = netServer((c) => (hits++, c.end()));
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", () => r()));
  const port = (srv.address() as { port: number }).port;
  try {
    const out = await readUpnp(`http://127.0.0.1:${port}/rootDesc.xml`, () => false);
    assert.ok(out.outside);
    assert.ok((await readUpnp("http://router.example/rootDesc.xml", () => true)).outside);
    assert.ok((await readUpnp("not a url", () => true)).outside);
    assert.equal(hits, 0);
  } finally {
    srv.close();
  }
  // And runNetwork hands the approved ranges to the reader, then checks again.
  let asked: ((h: string) => boolean) | undefined;
  const io = { ...quietNet("192.168.1.50/24"), upnp: async (allowed: (h: string) => boolean) => ((asked = allowed), { host: "192.168.9.1", mappings: [] }) };
  const r = await runNetwork({ ranges: ["192.168.1.0/30"] }, new ActivityLog(), { io, gapMs: 0 });
  assert.ok(asked && asked("192.168.1.1") && !asked("192.168.9.1"));
  assert.match(r.skipped.map((s) => s.reason).join(" "), /outside the approved ranges/);
});

test("QA-18: port 2375 is only an open Docker API when it says it's Docker", () => {
  const ids = (server?: string) => deviceFindings({ ip: "192.168.1.9", open: [2375], pages: server === undefined ? [] : [{ port: 2375, tls: false, page: { status: 404, server } }] }).findings.map((f) => `${f.ruleId}:${f.severity}`);
  assert.deepEqual(ids("Docker/27.3.1 (linux)"), ["net-docker-api:critical"]);
  assert.deepEqual(ids("nginx"), ["net-docker-port:medium"]);
  assert.deepEqual(ids(), ["net-docker-port:medium"]);
});

test("QA-19 and QA-20: cloud keys read CloudFormation in either order, and customer-supplied Google disk keys count as yours", () => {
  const cfn = (a: string, b: string) => `AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketEncryption:\n        ServerSideEncryptionConfiguration:\n          - ServerSideEncryptionByDefault:\n              ${a}\n              ${b}\n`;
  assert.equal(cloudKeyAdvice("t.yaml", cfn("KMSMasterKeyID: !Ref Key", "SSEAlgorithm: aws:kms"))[0].custody, "provider-kms");
  assert.equal(cloudKeyAdvice("t.yaml", cfn("SSEAlgorithm: aws:kms", "KMSMasterKeyID: !Ref Key"))[0].custody, "provider-kms");
  assert.equal(cloudKeyAdvice("t.yaml", cfn("SSEAlgorithm: AES256", "BucketKeyEnabled: true"))[0].custody, "provider");
  const tf = 'resource "google_compute_disk" "a" {\n  disk_encryption_key {\n    raw_key = var.k\n  }\n}\nresource "google_compute_disk" "b" {\n  size = 10\n}\n';
  assert.deepEqual(cloudKeyAdvice("main.tf", tf).map((a) => a.resource), ["google_compute_disk.b"]);
});

test("QA-21: the address limit says which addresses were left out and what to do", async () => {
  const r = await runNetwork({ ranges: [], routed: ["10.20.0.0/20"] }, new ActivityLog(), { io: quietNet("192.168.1.50/24"), gapMs: 0 });
  const s = r.skipped.find((x) => /first 1,024/.test(x.reason))!;
  assert.equal(s.target, "3,070 addresses from 10.20.4.1 on");
});

test("QA-22 and QA-23: cloud key counts read naturally, and a 'no' comes before a 'not sure' of the same weight", () => {
  const html = mapHtml(buildMapReport([emptyResult("code")], [], "0.3.0", new Date(), [], { cloudKeys: cloudKeyAdvice("main.tf", 'resource "aws_db_instance" "x" {\n  storage_encrypted = true\n}\n'), people: null }), []);
  assert.match(html, /1 uses keys the provider holds; 0 use keys/);
  const p = scorePeople({ backups: "unsure", "incident-plan": "no", mfa: "unsure", "verify-requests": "no" })!;
  assert.deepEqual(p.gaps.map((g) => g.answer), ["no", "no", "unsure", "unsure"]);
});

test("QA-26: a map where nothing was checked isn't given a grade", () => {
  const people = { answeredAt: "2026-11-20", ...scorePeople({ mfa: "no", backups: "yes" })! };
  const none = buildMapReport([], [], "0.3.0", new Date(), [], { cloudKeys: [], people });
  assert.match(mapText(none), /not graded, because nothing was checked/);
  assert.doesNotMatch(mapText(none), /A \(100\/100/);
  assert.match(mapHtml(none, []), /Quantum readiness not graded/);
  const web = { ...emptyResult("web"), skipped: [{ target: "example.com", reason: "domain not proved" }] };
  assert.match(mapText(buildMapReport([web], [], "0.3.0")), /not graded/);
  const code = { ...emptyResult("code"), checked: ["repo (3 files)"] };
  assert.match(mapText(buildMapReport([code], [], "0.3.0")), /Quantum readiness: A\+? \(100\/100/);
});

// ---------- QA-27: Go TLS curve lists that turn off the post-quantum default ----------

test("QA-27: a Go TLS curve list without ML-KEM is flagged, and one that keeps the hybrid group isn't", () => {
  const only = scanFile("gateway/server.go", "cfg := &tls.Config{\n\tCurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},\n}\n");
  assert.deepEqual(only.map((f) => [f.line, f.algorithm]), [[2, "X25519"]]);
  const hybrid = scanFile("gateway/server.go", "\tCurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},\n");
  assert.equal(hybrid.length, 0);
});

// ---------- QA-28: AWS's published sample key is skipped on purpose ----------

test("QA-28: AWS's documented sample access key isn't reported as leaked, but a made-up one is", () => {
  const sample = "AKIA" + "IOSFODNN7" + "EXAMPLE";
  const madeUp = "AKIA" + "Q7R2HB4KZT5WN3XD";
  assert.equal(scanFile("app/settings.py", `AWS_ACCESS_KEY_ID = "${sample}"\n`).length, 0);
  assert.equal(scanFile("app/settings.py", `AWS_ACCESS_KEY_ID = "${madeUp}"\n`).filter((f) => f.risk === "secret").length, 1);
});

// ---------- QA-29: false leaked-key alarms found by the 100-project re-scan ----------

test("QA-29: translated labels, editor token names and Go-style test folders aren't leaked keys", () => {
  const secrets = (path: string, text: string) => scanFile(path, text).filter((f) => f.risk === "secret");
  // A translated "Password" label in a language file, and the same shape anywhere else.
  assert.equal(secrets("src/node/i18n/locales/ja.json", '  "LOGIN_PASSWORD": "パスワードを入力してください。設定ファイルを確認",\n').length, 0);
  assert.equal(secrets("src/strings.json", '  "INCORRECT_PASSWORD": "รหัสผ่านไม่ถูกต้องกรุณาลองอีกครั้ง",\n').length, 0);
  assert.equal(secrets("app/locales/de.yml", '  password_hint: "Kennwort2024MindestensZwölf"\n').length, 0);
  // A syntax highlighter's token names.
  assert.equal(secrets("js/editor.js", "  { token: 'excludedRequestDomains:', after: ' ' },\n").length, 0);
  // Test keys in a Go-style test folder (caddytest/, httptest/, testutil/).
  const key = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n";
  assert.equal(secrets("caddytest/caddy.localhost.key", key).length, 0);
  assert.equal(secrets("internal/testutil/key.pem", key).length, 0);
  assert.equal(secrets("deploy/tls.key", key).length, 1);
  // Folders that only end in "test" are still real code.
  assert.equal(secrets("latest/key.pem", key).length, 1);
  // Fakes in real token formats inside test files, and Java-style test fixtures.
  assert.equal(secrets("src/__tests__/redact.test.ts", "  token: 'xoxb-" + "2" + "4".repeat(11) + "-abcDEF123ghiJKL',\n").length, 0);
  assert.equal(secrets("module/web/src/testFixtures/resources/test-key.pem", key).length, 0);
  assert.equal(secrets("packages/e2e-auth-server/keys.ts", key).length, 0);
  // Local databases, example settings files, API specs and secret-store references.
  assert.equal(secrets(".github/workflows/ci.yml", "  DATABASE_URL: postgresql://app:" + "Ci7pass" + "word9@localhost:5432/app\n").length, 0);
  assert.equal(secrets("app/settings.py", 'DATABASE_URL = "postgres://app:' + "Pr0dPass" + 'Word77@db.internal:5432/app"\n').length, 1);
  assert.equal(secrets("server/.env.example", 'API_TOKEN="' + "a1b2c3d4" + 'e5f6a7b8c9"\n').length, 0);
  assert.equal(secrets("api/openapi.yaml", '  JoinToken: "SWMTKN-1-' + "3pu6hszjas19xyp7gh" + 'x1"\n').length, 0);
  assert.equal(secrets("infra/ddns.tf", '  CLOUDFLARE_API_TOKEN = "bao:secret/' + "cloudflare" + '1#token"\n').length, 0);
  // Names that describe a token rather than hold one.
  assert.equal(secrets("api/repo.py", '_ACCESS_TOKEN_KEY = "oauth_server:' + "access_token" + ':v2"\n').length, 0);
  assert.equal(secrets("tools/load.py", 'tokenizer_id = "google/paligemma2' + '-3b-pt-224"\n').length, 0);
  // A public client key is safe to ship.
  assert.equal(secrets("telemetry.py", "POSTHOG_API_KEY = 'phc_" + "q8Zr2Lk9Xw4Tn7Vb" + "3Hj5Pm1Rs6'\n").length, 0);
  // A detect-secrets baseline, a Storybook story, a test package, a CSS design token, a Dockerfile cache folder.
  assert.equal(secrets(".secrets.baseline", '      "hashed_secret": "665b1' + "a9c3e7f" + '20d4b8e61",\n').length, 0);
  assert.equal(secrets("src/CopyInput.stories.ts", "const INITIAL_TOKEN = 'n8n_" + "q8Zr2Lk9Xw4Tn7Vb" + "';\n").length, 0);
  assert.equal(secrets("packages/bruno-tests/src/auth.js", key).length, 0);
  assert.equal(secrets("src/styles.vue", "  { name: '2xs', token: 'var(--shadow" + "-2xs-1)' },\n").length, 0);
  assert.equal(secrets("api/Dockerfile", "ENV TIKTOKEN_CACHE_DIR=/app/api/" + "tiktoken2\n").length, 0);
  // Real-looking values still count.
  assert.equal(secrets("app/config.py", 'API_KEY = "' + "q8Zr2Lk9" + "Xw4Tn7Vb" + '"\n').length, 1);
  assert.equal(secrets("app/config.py", 'SECRET_TOKEN = "' + "QwErTyUiOpAsDfGh" + "JkLzXcVbNmQwErTyU" + '"\n').length, 1);
});
