import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCbom } from "../src/cbom.ts";
import { main, repoPrefix } from "../src/cli.ts";
import { toFinding } from "../src/map-rank.ts";
import type { MapFinding } from "../src/map-types.ts";
import { buildMapSarif, buildSarif, sarifRuleId, toUri } from "../src/sarif.ts";
import { scanFile, scanFiles } from "../src/scan.ts";
import type { Finding } from "../src/types.ts";

const SRC = ["pw = hashlib.md5(password)", "k = ec.generate_private_key(ec.SECP256R1())", "kx = ec.ECDH()"].join("\n");

const mapFinding = (o: Partial<MapFinding>): MapFinding => ({
  area: "web",
  target: "example.com:443",
  ruleId: "web-x",
  title: "t",
  algorithm: "RSA",
  primitive: "signature",
  risk: "quantum-vulnerable",
  severity: "medium",
  fix: "f",
  internetFacing: true,
  ...o,
});

// ---------- SARIF ----------

test("sarif: GitHub severity scores keep quantum-breakable encryption below what is broken now", () => {
  const run = buildSarif(scanFile("a.py", SRC), "0.0.0").runs[0];
  const sev = Object.fromEntries(run.tool.driver.rules.map((r) => [r.id, (r.properties as Record<string, string>)["security-severity"]]));
  assert.equal(sev["weak-now/md5-hash"], "5.5");
  assert.ok(Number(sev["quantum-vulnerable/ecdh-key-exchange"]) < 7);
  for (const r of run.tool.driver.rules) {
    const p = r.properties as { tags: string[] };
    assert.ok(p.tags.includes("security"), "code scanning only treats rules tagged security as security alerts");
    assert.ok((r.help as { markdown: string }).markdown.includes("**Fix:**"));
  }
  assert.ok(run.tool.driver.rules.find((r) => r.id.startsWith("quantum-vulnerable/"))!.properties.tags.includes("post-quantum"));
});

test("sarif: rule ids come from the setting, not the message, so they don't change with the ports found", () => {
  const base: Finding = { kind: "config", ruleId: "infra-open", title: "SSH (22) open to the whole internet", algorithm: "Open to the internet", primitive: "setting", risk: "exposed", severity: "high", file: "main.tf", line: 3, snippet: "", fix: "f" };
  assert.equal(sarifRuleId(base), sarifRuleId({ ...base, title: "RDP (3389) open to the whole internet" }));
  assert.equal(sarifRuleId(base), "exposed/open-to-the-internet");
  const ssh: Finding = { ...base, kind: "crypto", algorithm: "SSH key exchange", primitive: "key-agreement", risk: "quantum-vulnerable" };
  assert.equal(sarifRuleId(ssh), "quantum-vulnerable/ssh-key-exchange");
});

test("sarif: paths are relative to the repository, fingerprints survive lines moving", () => {
  const a = buildSarif(scanFile("lib/a.py", SRC), "0.0.0", { uriPrefix: "services/api" }).runs[0].results;
  const loc = a[0].locations[0] as { physicalLocation: { artifactLocation: { uri: string; uriBaseId: string }; region: { startLine: number } } };
  assert.equal(loc.physicalLocation.artifactLocation.uri, "services/api/lib/a.py");
  assert.equal(loc.physicalLocation.artifactLocation.uriBaseId, "%SRCROOT%");
  const moved = buildSarif(scanFile("lib/a.py", "\n\n" + SRC), "0.0.0", { uriPrefix: "services/api" }).runs[0].results;
  assert.deepEqual(moved.map((r) => r.partialFingerprints), a.map((r) => r.partialFingerprints));
  assert.equal(new Set(a.map((r) => r.partialFingerprints["hardkeelFinding/v1"])).size, a.length);
  assert.equal(toUri("./dir name/x.ts", "."), "dir%20name/x.ts");
  assert.equal(toUri("x\\y.ts", "a\\b\\"), "a/b/x/y.ts");
});

test("sarif: the map points to sites and devices, not files", () => {
  const items = [
    { finding: toFinding(mapFinding({ area: "network", target: "192.168.1.1:23", ruleId: "net-telnet", algorithm: "Telnet", primitive: "protocol", risk: "exposed", severity: "high" })), target: { name: "192.168.1.1:23", area: "network" } },
    { finding: { ...toFinding(mapFinding({ area: "code", target: "app.py:2" })), file: "app.py", line: 2 }, target: { name: "app.py", area: "code" } },
  ];
  const run = buildMapSarif(items, "0.0.0", { score: { grade: "C", score: 70 } }).runs[0];
  const [net, code] = run.results.map((r) => r.locations[0] as Record<string, any>);
  assert.equal(net.logicalLocations[0].fullyQualifiedName, "network:192.168.1.1:23");
  assert.equal(net.physicalLocation, undefined);
  assert.equal(code.physicalLocation.region.startLine, 2);
  assert.equal(run.results[0].properties.area, "network");
  assert.deepEqual(run.properties, { readinessGrade: "C", readinessScore: 70 });
});

test("sarif: findings with no line get no region, since SARIF lines start at 1", () => {
  const f = { ...scanFile("a.py", SRC)[0], line: 0 };
  const loc = buildSarif([f], "0.0.0").runs[0].results[0].locations[0] as { physicalLocation: Record<string, unknown> };
  assert.equal(loc.physicalLocation.region, undefined);
});

// ---------- CycloneDX ----------

test("cbom: a complete document with an id, the scanned component and what depends on what", () => {
  const bom = buildCbom(scanFile("a.py", SRC), { repo: "acme/api", toolVersion: "0.0.0" });
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.equal(bom.$schema, "http://cyclonedx.org/schema/bom-1.6.schema.json");
  assert.equal(bom.dependencies[0].ref, bom.metadata.component["bom-ref"]);
  assert.deepEqual(bom.dependencies[0].dependsOn.sort(), bom.components.map((c) => c["bom-ref"]).sort());
  const md5 = bom.components.find((c) => c.name === "MD5") as Record<string, any>;
  assert.equal(md5.cryptoProperties.oid, "1.2.840.113549.2.5");
  assert.equal(md5.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 0);
  assert.deepEqual(md5.evidence.occurrences, [{ location: "a.py", line: 1 }]);
});

test("cbom: post-quantum encryption already in use is listed, with its NIST level where the code names it", () => {
  const { findings, pqc } = scanFiles([{ path: "kex.go", content: "c := mlkem.GenerateKey768()\nconst kem = \"ML-KEM-768\"\nsig := \"ML-DSA-65\"\n" }]);
  const bom = buildCbom(findings, { repo: "r", toolVersion: "0", quantumSafe: pqc.map((p) => ({ algorithm: p.algorithm, use: p.use, location: p.file, line: p.line })) });
  const names = bom.components.map((c) => c.name);
  assert.ok(names.includes("ML-KEM") && names.includes("ML-DSA"), names.join(", "));
  const safe = bom.components.filter((c) => (c.properties as { name: string; value: string }[]).some((p) => p.value === "quantum-safe"));
  assert.equal(safe.length, 2);
  const bom2 = buildCbom([], { repo: "r", toolVersion: "0", quantumSafe: [{ algorithm: "ML-KEM-1024", use: "key-establishment", location: "x" }] });
  const kem = bom2.components[0] as Record<string, any>;
  assert.equal(kem.cryptoProperties.algorithmProperties.primitive, "kem");
  assert.equal(kem.cryptoProperties.algorithmProperties.nistQuantumSecurityLevel, 5);
  assert.equal(kem.cryptoProperties.oid, "2.16.840.1.101.3.4.4.3");
  assert.deepEqual(kem.evidence.occurrences, [{ location: "x" }]);
});

test("cbom: certificate problems aren't encryption methods; TLS and SSH findings get the right protocol", () => {
  const fs = [
    mapFinding({ algorithm: "Expired certificate", primitive: "protocol", risk: "weak-now" }),
    mapFinding({ algorithm: "Certificate name mismatch", primitive: "protocol", risk: "exposed" }),
    mapFinding({ algorithm: "Weak TLS ciphers", primitive: "protocol", risk: "weak-now", target: "/etc/ssl/openssl.cnf" }),
    mapFinding({ algorithm: "SSH weak settings", primitive: "protocol", risk: "weak-now", target: "/etc/ssh/sshd_config" }),
    mapFinding({ algorithm: "TLS 1.0/1.1", primitive: "protocol", risk: "weak-now" }),
  ].map(toFinding);
  const bom = buildCbom(fs, { repo: "map", toolVersion: "0" });
  const by = Object.fromEntries(bom.components.map((c) => [c.name, (c as Record<string, any>).cryptoProperties.protocolProperties]));
  assert.deepEqual(Object.keys(by).sort(), ["SSH weak settings", "TLS 1.0/1.1", "Weak TLS ciphers"]);
  assert.deepEqual(by["TLS 1.0/1.1"], { type: "tls", version: "1.0/1.1" });
  assert.deepEqual(by["Weak TLS ciphers"], { type: "tls" });
  assert.deepEqual(by["SSH weak settings"], { type: "ssh" });
  for (const c of bom.components) for (const o of (c as Record<string, any>).evidence.occurrences) assert.equal(o.line, undefined);
});

// ---------- command line ----------

test("cli: --format cyclonedx prints the inventory, and SARIF paths start at the repository root", () => {
  const repo = mkdtempSync(join(tmpdir(), "qs-repo-"));
  mkdirSync(join(repo, ".git"));
  mkdirSync(join(repo, "svc", "api"), { recursive: true });
  writeFileSync(join(repo, "svc", "api", "a.py"), SRC);
  assert.equal(repoPrefix(join(repo, "svc", "api")), "svc/api");
  assert.equal(repoPrefix(repo), "");
  const lines: string[] = [];
  const log = console.log;
  console.log = (s: string) => lines.push(s);
  try {
    assert.equal(main([join(repo, "svc", "api"), "--format", "cyclonedx", "--fail-on", "none", "--offline"]), 0);
    assert.equal(main([join(repo, "svc", "api"), "--format", "sarif", "--fail-on", "none", "--offline"]), 0);
    assert.equal(main([repo, "--format", "nope", "--offline"]), 2);
  } finally {
    console.log = log;
  }
  const bom = JSON.parse(lines[0]);
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.ok(bom.components.length >= 2);
  const sarif = JSON.parse(lines[1]);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "svc/api/a.py");
});
