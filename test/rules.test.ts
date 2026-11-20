import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkRule, loadRules, render } from "../scripts/build-rules.mjs";
import { scanFile } from "../src/scan.ts";

const { rules, problems } = loadRules();

test("community rules: every rule passes its checks", () => {
  assert.deepEqual(problems, []);
  assert.ok(rules.length >= 20);
});

test("community rules: the bundle is up to date", () => {
  assert.equal(readFileSync(new URL("../src/community-rules.ts", import.meta.url), "utf8"), render(rules));
});

test("community rules: each example is found end to end, look-alikes are not", () => {
  for (const r of rules) {
    const path = `src/example${r.extensions[0]}`;
    for (const line of r.examples.match) {
      assert.ok(scanFile(path, line).some((f) => f.ruleId === r.id), `${r.id} should find: ${line}`);
    }
    for (const line of r.examples.noMatch) {
      assert.ok(!scanFile(path, line).some((f) => f.ruleId === r.id), `${r.id} should not find: ${line}`);
    }
  }
});

test("community rules: the checker catches common mistakes", () => {
  const good = JSON.parse(readFileSync(new URL("../rules/community/rust-rsa-crate.json", import.meta.url), "utf8"));
  const check = (over: object) => checkRule({ ...good, ...over }, "rust-rsa-crate.json", new Set());
  assert.deepEqual(check({}), []);
  assert.match(check({ algorithm: "Kyber" }).join(), /unknown algorithm/);
  assert.match(check({ pattern: "(a+)+b" }).join(), /nested repeat/);
  assert.match(check({ examples: { match: ["nothing here"], noMatch: ["x"] } }).join(), /does not match its own example/);
  assert.match(check({ id: "py-rsa-generate" }).join(), /file name/);
  assert.match(checkRule({ ...good, id: "py-rsa-generate" }, "py-rsa-generate.json", new Set(["py-rsa-generate"])).join(), /already used/);
});

test("community rules: short RSA keys in new languages are weak now", () => {
  const [f] = scanFile("src/Keys.cs", "var p = new RSACryptoServiceProvider(1024);");
  assert.equal(f.risk, "weak-now");
  assert.equal(f.keySize, 1024);
});
