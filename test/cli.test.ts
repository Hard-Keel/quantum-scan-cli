import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main } from "../src/cli.ts";
import { buildSarif } from "../src/sarif.ts";
import { scanFile } from "../src/scan.ts";

const SRC = ["pw = hashlib.md5(password)", "k = ec.generate_private_key(ec.SECP256R1())"].join("\n");

test("sarif: one rule per kind of problem, weak is error, quantum is warning", () => {
  const s = buildSarif(scanFile("a.py", SRC), "0.0.0");
  const run = s.runs[0];
  assert.deepEqual(run.results.map((r) => [r.ruleId, r.level]), [
    ["weak-now/md5-hash", "error"],
    ["quantum-vulnerable/ecdsa-signature", "warning"],
  ]);
  assert.equal(run.tool.driver.rules.length, 2);
  // GitHub code scanning shows a severity only when the rule carries security-severity.
  assert.deepEqual(run.tool.driver.rules.map((r) => r.properties.tags[0]), ["security", "security"]);
  assert.ok(run.tool.driver.rules.every((r) => Number(r.properties["security-severity"]) > 0));
});

test("sarif: fingerprints survive lines moving, and a whole-file finding has no line", () => {
  const a = buildSarif(scanFile("a.py", SRC), "0.0.0").runs[0].results;
  const b = buildSarif(scanFile("a.py", "\n\n# moved down\n" + SRC), "0.0.0").runs[0].results;
  assert.deepEqual(a.map((r) => r.partialFingerprints), b.map((r) => r.partialFingerprints));
  assert.notDeepEqual(a.map((r) => r.locations[0].physicalLocation.region), b.map((r) => r.locations[0].physicalLocation.region));
  const whole = buildSarif([{ ...scanFile("a.py", SRC)[0], line: 0 }], "0.0.0").runs[0].results[0];
  assert.equal("region" in whole.locations[0].physicalLocation, false);
});

test("cli: exit code follows --fail-on, files are written", () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-"));
  writeFileSync(join(dir, "a.py"), SRC);
  const out = join(dir, "out.json");
  const log = console.log;
  console.log = () => {};
  try {
    assert.equal(main([dir, "--format", "json", "--output", out, "--cbom", join(dir, "c.json")]), 1);
    assert.equal(main([dir, "--quiet", "--fail-on", "none"]), 0);
    assert.equal(main([dir, "--quiet", "--fail-on", "quantum-vulnerable"]), 1);
  } finally {
    console.log = log;
  }
  assert.equal(JSON.parse(readFileSync(out, "utf8")).findings.length, 2);
  assert.equal(JSON.parse(readFileSync(join(dir, "c.json"), "utf8")).bomFormat, "CycloneDX");
});

test("cli: --format cyclonedx and sarif write the inventory and findings", () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-"));
  writeFileSync(join(dir, "a.py"), SRC);
  const log = console.log;
  console.log = () => {};
  try {
    main([dir, "--format", "cyclonedx", "--output", join(dir, "inv.json"), "--fail-on", "none"]);
    main([dir, "--format", "sarif", "--output", join(dir, "f.sarif"), "--fail-on", "none"]);
  } finally {
    console.log = log;
  }
  const bom = JSON.parse(readFileSync(join(dir, "inv.json"), "utf8"));
  assert.equal(bom.bomFormat, "CycloneDX");
  assert.equal(bom.specVersion, "1.6");
  assert.equal(JSON.parse(readFileSync(join(dir, "f.sarif"), "utf8")).version, "2.1.0");
});
