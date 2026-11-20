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
