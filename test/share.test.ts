import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run } from "../src/cli.ts";
import { applyIgnore, parseIgnore } from "../src/ignore.ts";
import { band, buildPayload, diffRuns, type Payload, type RunFacts } from "../src/share.ts";
import { loadSettings, sharingState, showNoticeIfNeeded } from "../src/share-config.ts";
import { scanFile } from "../src/scan.ts";

const settings = () => loadSettings(join(mkdtempSync(join(tmpdir(), "qs-")), "s.json"));

const facts = (o: Partial<RunFacts> = {}): RunFacts => ({ command: "scan", areas: ["code"], rules: {}, algorithms: {}, quantumSafe: {}, fixed: {}, ignored: {}, replacements: {}, errors: [], ...o });

test("bands: counts are rounded so one run's numbers can't fingerprint a company", () => {
  assert.deepEqual([0, 1, 2, 5, 6, 20, 21, 100, 101, 5000].map(band), [null, "1", "2-5", "2-5", "6-20", "6-20", "21-100", "21-100", "100+", "100+"]);
});

test("payload: only known names and rule ids, never anything from the scanned code", () => {
  const s = settings();
  const p = buildPayload(
    facts({
      rules: { "py-rsa-generate": 3, "Bad Rule /etc/passwd": 1 },
      algorithms: { RSA: { count: 3, quantumVulnerable: 3 }, "acme-internal-cipher": { count: 2, quantumVulnerable: 0 } },
      quantumSafe: { "ML-KEM": 1, "something.acme.com": 4 },
    }),
    s,
    "0.2.0",
    {},
    "linux",
  );
  assert.deepEqual(p.rules, { "py-rsa-generate": "2-5" });
  assert.deepEqual(p.algorithms, { RSA: { n: "2-5", qv: "2-5" }, other: { n: "2-5", qv: "0" } });
  assert.deepEqual(p.quantumSafe, { "ML-KEM": "1" });
  assert.equal(p.ci, false);
  assert.equal(p.industry, undefined);
  assert.doesNotMatch(JSON.stringify(p), /acme|passwd/);
});

test("sharing: on by default, off by setting, environment, do-not-track or offline", () => {
  const s = settings();
  assert.equal(sharingState(s, {}, {}), "on");
  assert.equal(sharingState(s, { offline: true }, {}), "offline");
  assert.equal(sharingState(s, {}, { QUANTUM_SCAN_OFFLINE: "1" }), "offline");
  assert.equal(sharingState(s, {}, { QUANTUM_SCAN_SHARING: "off" }), "env-off");
  assert.equal(sharingState(s, {}, { DO_NOT_TRACK: "1" }), "do-not-track");
  s.sharing = "off";
  assert.equal(sharingState(s, {}, {}), "off");
});

test("notice: shown once on a workstation, every run in a pipeline, never when sharing is off", () => {
  const s = settings();
  const seen: string[] = [];
  const w = (t: string) => void seen.push(t);
  assert.equal(showNoticeIfNeeded(s, "on", {}, w), true);
  assert.equal(showNoticeIfNeeded(s, "on", {}, w), false);
  assert.equal(showNoticeIfNeeded(s, "on", { CI: "true" }, w), true);
  assert.equal(showNoticeIfNeeded(settings(), "off", {}, w), false);
  assert.match(seen[0].replace(/\s+/g, " "), /never includes your code, keys, files, server names, IP addresses or company name/);
  assert.match(seen[0], /config sharing off/);
  assert.doesNotMatch(seen[0], /publish/i);
});

test("fixed and replacements: worked out locally from the last run", () => {
  assert.deepEqual(diffRuns(undefined, { rules: { a: 1 }, pqc: {} }), { fixed: {}, replacements: {} });
  assert.deepEqual(diffRuns({ rules: { a: 3, b: 1 }, pqc: {} }, { rules: { a: 1 }, pqc: { "ML-KEM": 2 } }), { fixed: { a: 2, b: 1 }, replacements: { "ML-KEM": 2 } });
});

test("ignore file: by rule, file or folder; secrets only by file", () => {
  const src = 'h = hashlib.md5(password)\nKEY = "AKIAIOSFODNN7EXAMPL3"\n';
  const findings = [...scanFile("app/a.py", src), ...scanFile("legacy/b.py", src)];
  const rules = [...new Set(findings.map((f) => f.ruleId))];
  const weak = findings.find((f) => f.kind === "crypto")!.ruleId;
  const secret = findings.find((f) => f.kind === "secret")?.ruleId;
  const { kept, ignored } = applyIgnore(findings, parseIgnore(`# reviewed\nrule:${weak}\nlegacy/\n${secret ? `rule:${secret}` : ""}\n`));
  assert.ok(rules.length >= 1);
  assert.ok(!kept.some((f) => f.ruleId === weak));
  assert.ok(!kept.some((f) => f.file.startsWith("legacy/")));
  if (secret) assert.ok(kept.some((f) => f.ruleId === secret && f.file === "app/a.py"));
  assert.ok((ignored[weak] ?? 0) >= 1);
});

test("cli: sends one summary per run, nothing with --offline or sharing off, and shows what it sent", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-"));
  writeFileSync(join(dir, "a.py"), "pw = hashlib.md5(password)\n");
  const cfg = join(mkdtempSync(join(tmpdir(), "qs-cfg-")), "settings.json");
  process.env.QUANTUM_SCAN_CONFIG = cfg;
  const sent: Payload[] = [];
  const send = async (p: Payload) => (sent.push(p), true);
  const quiet = { log: console.log, err: process.stderr.write };
  console.log = () => {};
  process.stderr.write = (() => true) as typeof process.stderr.write;
  try {
    for (const k of ["CI", "GITHUB_ACTIONS", "DO_NOT_TRACK", "QUANTUM_SCAN_SHARING", "QUANTUM_SCAN_OFFLINE"]) delete process.env[k];
    assert.equal(await run([dir, "--quiet"], { send }), 1);
    assert.equal(sent.length, 1);
    assert.deepEqual(Object.keys(sent[0].rules), ["py-weak-hash"]);
    assert.doesNotMatch(JSON.stringify(sent[0]), new RegExp(dir.replace(/[\\/]/g, ".")));

    await run([dir, "--quiet", "--offline"], { send });
    assert.equal(sent.length, 1);

    writeFileSync(join(dir, "a.py"), "print('fixed')\n");
    await run(["config", "sharing", "off"], { send });
    await run([dir, "--quiet"], { send });
    assert.equal(sent.length, 1);
    const saved = JSON.parse(readFileSync(cfg, "utf8"));
    assert.equal(saved.lastShared.notSent, "off");
    assert.deepEqual(saved.lastShared.wouldHaveSent.fixed, { "py-weak-hash": "1" });
    assert.equal(saved.noticeShown, true);
  } finally {
    console.log = quiet.log;
    process.stderr.write = quiet.err;
    delete process.env.QUANTUM_SCAN_CONFIG;
  }
});
