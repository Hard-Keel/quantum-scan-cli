import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildCbom } from "../src/cbom.ts";
import { main, repoPrefix } from "../src/cli.ts";
import { toFinding } from "../src/map-rank.ts";
import { buildMapSarif } from "../src/map-sarif.ts";
import type { MapFinding } from "../src/map-types.ts";
import { buildSarif, ruleId, toUri } from "../src/sarif.ts";
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

test("sarif: quantum-breakable encryption scores below what is broken now, and rules carry help", () => {
  const run = buildSarif(scanFile("a.py", SRC), "0.0.0").runs[0];
  const sev = Object.fromEntries(run.tool.driver.rules.map((r) => [r.id, r.properties["security-severity"]]));
  assert.equal(sev["weak-now/md5-hash"], "5.5");
  assert.equal(sev["quantum-vulnerable/ecdh-key-exchange"], "6.0"); // high, capped
  for (const r of run.tool.driver.rules) {
    assert.ok(r.help.markdown.includes("**Fix:**"));
    assert.equal(r.helpUri, "https://hardkeel.com/quantum-scan/");
    assert.ok(!r.properties.tags.includes("cryptography"));
  }
  assert.ok(run.tool.driver.rules.find((r) => r.id.startsWith("quantum-vulnerable/"))!.properties.tags.includes("post-quantum"));
  // A high-severity quantum finding still stays at Medium on GitHub (under 7.0).
  const high = buildMapSarif([mapFinding({ severity: "high" })], "0.0.0").runs[0];
  assert.ok(Number(high.tool.driver.rules[0].properties["security-severity"]) < 7);
});

test("sarif: rule ids come from the setting, not the message, so they don't change with the ports found", () => {
  const base: Finding = { kind: "config", ruleId: "infra-open", title: "SSH (22) open to the whole internet", algorithm: "Open to the internet", primitive: "setting", risk: "exposed", severity: "high", file: "main.tf", line: 3, snippet: "", fix: "f" };
  assert.equal(ruleId(base), ruleId({ ...base, title: "RDP (3389) open to the whole internet" }));
  assert.equal(ruleId(base), "exposed/open-to-the-internet");
  const ssh: Finding = { ...base, kind: "crypto", algorithm: "SSH key exchange", primitive: "key-agreement", risk: "quantum-vulnerable" };
  assert.equal(ruleId(ssh), "quantum-vulnerable/ssh-key-exchange");
});

test("sarif: paths can start at the repository root, and fingerprints still survive lines moving", () => {
  const a = buildSarif(scanFile("lib/a.py", SRC), "0.0.0", { uriPrefix: "services/api" }).runs[0].results;
  const loc = a[0].locations[0] as { physicalLocation: { artifactLocation: { uri: string; uriBaseId: string } } };
  assert.equal(loc.physicalLocation.artifactLocation.uri, "services/api/lib/a.py");
  assert.equal(loc.physicalLocation.artifactLocation.uriBaseId, "%SRCROOT%");
  const moved = buildSarif(scanFile("lib/a.py", "\n\n" + SRC), "0.0.0", { uriPrefix: "services/api" }).runs[0].results;
  assert.deepEqual(moved.map((r) => r.partialFingerprints), a.map((r) => r.partialFingerprints));
  assert.equal(toUri("./dir name/x.ts", "."), "dir%20name/x.ts");
  assert.equal(toUri("x\\y.ts", "a\\b\\"), "a/b/x/y.ts");
});

// ---------- CycloneDX ----------

test("cbom: common algorithms carry their object identifier", () => {
  const { findings, inventory } = scanFiles([{ path: "a.py", content: SRC + '\nkem = "ML-KEM-768"\n' }]);
  const bom = buildCbom(findings, { repo: "r", toolVersion: "0" }, inventory);
  const by = Object.fromEntries(bom.components.map((c) => [c.name, c as Record<string, any>]));
  assert.equal(by["MD5"].cryptoProperties.oid, "1.2.840.113549.2.5");
  assert.equal(by["ML-KEM-768"].cryptoProperties.oid, "2.16.840.1.101.3.4.4.2");
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
});

// ---------- command line ----------

test("cli: SARIF paths start at the repository root when a subfolder is scanned", () => {
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
    assert.equal(main([join(repo, "svc", "api"), "--format", "sarif", "--fail-on", "none", "--offline"]), 0);
  } finally {
    console.log = log;
  }
  const sarif = JSON.parse(lines[0]);
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "svc/api/a.py");
});
