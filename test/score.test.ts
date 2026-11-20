import { test } from "node:test";
import assert from "node:assert/strict";
import { readinessScore, useMultiplier, gradeSentence } from "../src/score.ts";
import { badgeSvg, shieldsEndpoint } from "../src/badge.ts";
import { findPqc } from "../src/pqc.ts";
import { scanFile, scanFiles } from "../src/scan.ts";

const scan = (path: string, src: string) => scanFile(path, src);

test("score: nothing found is A, post-quantum in use with nothing found is A+", () => {
  assert.equal(readinessScore([]).grade, "A");
  assert.equal(readinessScore([]).score, 100);
  assert.equal(readinessScore([]).due, null);
  const pqc = findPqc("src/kem.go", 'import "crypto/mlkem"');
  assert.equal(readinessScore([], pqc).grade, "A+");
});

test("score: signatures alone can still be A", () => {
  const s = readinessScore(scan("a.go", "sig, _ := ed25519.Sign(priv, msg)"));
  assert.equal(s.grade, "A");
  assert.equal(s.score, 98);
  assert.equal(s.due, "2035");
});

test("score: quantum-breakable key exchange holds the grade at B", () => {
  const s = readinessScore(scan("a.py", "x = X25519PrivateKey.generate()"));
  assert.equal(s.score, 95);
  assert.equal(s.grade, "B");
  assert.equal(s.due, "2030");
});

test("score: weak encryption holds at C, a leaked key holds at D", () => {
  assert.equal(readinessScore(scan("a.py", "h = hashlib.md5(password)")).grade, "C");
  const leaked = readinessScore(scan("app/config.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLQ"'));
  assert.equal(leaked.counts.secret, 1);
  assert.equal(leaked.grade, "D");
  assert.equal(leaked.due, "now");
  assert.match(gradeSentence(leaked), /revoked/);
});

test("score: more uses of one algorithm count more, up to double", () => {
  assert.equal(useMultiplier(1), 1);
  assert.equal(useMultiplier(4), 1.5);
  assert.equal(useMultiplier(1000), 2);
  const one = readinessScore(scan("a.py", "h = hashlib.md5(password)"));
  const many = readinessScore(scan("a.py", Array(16).fill("h = hashlib.md5(password)").join("\n")));
  assert.equal(100 - one.score, 6);
  assert.equal(100 - many.score, 12);
});

test("score: categories are capped so one area can't hide the rest", () => {
  const src = ["md5", "sha1"].map((h) => Array(16).fill(`h = hashlib.${h}(x)`).join("\n")).join("\n") +
    "\nc = DES.new(k)\nc = ARC4.new(k)\nc = Cipher(a, modes.ECB())";
  const s = readinessScore(scan("a.py", src));
  // Without the cap: 12 + 12 + 10 + 10 + 10 = 54. The weak-encryption cap is 30.
  assert.equal(s.score, 70);
  assert.equal(s.grade, "C");
});

test("score: post-quantum key exchange in use halves the key-exchange deduction", () => {
  const { findings, pqc } = scanFiles([
    { path: "tls.go", content: "k, _ := ecdh.X25519().GenerateKey(rand.Reader)" },
    { path: "kem.go", content: 'import "crypto/mlkem"' },
  ]);
  assert.equal(pqc.length, 1);
  const without = readinessScore(findings);
  const withPqc = readinessScore(findings, pqc);
  assert.equal(100 - without.score, 5);
  assert.equal(withPqc.score, 98); // 2.5 off, 97.5 rounds up
  assert.equal(withPqc.grade, "B"); // credit moves the number, not the letter
});

test("pqc: finds ML-KEM, hybrids, ML-DSA and SLH-DSA; ignores docs and test code", () => {
  const algs = (p: string, src: string) => findPqc(p, src).map((x) => x.algorithm);
  assert.deepEqual(algs("a.go", "curves := []tls.CurveID{tls.X25519MLKEM768}"), ["Hybrid ML-KEM key exchange"]);
  assert.deepEqual(algs("a.py", "kem = oqs.KeyEncapsulation('ML-KEM-768')"), ["ML-KEM"]);
  assert.deepEqual(algs("a.ts", "const sig = ml_dsa65.sign(sk, msg)"), ["ML-DSA"]);
  assert.deepEqual(algs("a.java", 'Signature.getInstance("SLH-DSA")'), ["SLH-DSA"]);
  assert.deepEqual(algs("README.md", "We plan to adopt ML-KEM."), []);
  const { pqc } = scanFiles([{ path: "test/kem_test.go", content: 'import "crypto/mlkem"' }]);
  assert.equal(pqc.length, 0);
});

test("badge: valid SVG, grade and score in the text, colour by grade, grey when not scanned", () => {
  const s = readinessScore(scan("a.py", "x = X25519PrivateKey.generate()"));
  const svg = badgeSvg(s);
  assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg" width="\d+" height="20"/);
  assert.match(svg, /quantum readiness: B · 95/);
  assert.match(svg, /fill="#97ca00"/);
  assert.doesNotMatch(svg, /<script|href=/);
  assert.match(badgeSvg(null), /not scanned/);
  assert.deepEqual(shieldsEndpoint(null), { schemaVersion: 1, label: "quantum readiness", message: "not scanned", color: "9f9f9f" });
});

test("tuning: test vectors, integration fixtures, magic strings and camelCase names are not leaked secrets", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB";
  assert.equal(scanFile("vectors/cryptography_vectors/asymmetric/rsa.pem", key).length, 0);
  assert.equal(scanFile("integration/resources/tls/local.key", key).length, 0);
  assert.equal(scanFile("tap/fixtures.ts", key).length, 0);
  assert.equal(scanFile("deploy/server.key", key).length, 1); // a real key file still counts
  assert.equal(scanFile("ssh/keys.go", 'const privateKeyAuthMagic = "openssh-key-v1\\x00"').length, 0);
  assert.equal(scanFile("_oid.py", 'AttributeOID.CHALLENGE_PASSWORD: "challengePassword",').length, 0);
});
