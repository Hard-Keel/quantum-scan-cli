import { test } from "node:test";
import assert from "node:assert/strict";
import { findInventory } from "../src/inventory.ts";
import { buildCbom } from "../src/cbom.ts";
import { scanFiles } from "../src/scan.ts";

const algs = (path: string, src: string) => findInventory(path, src).map((i) => i.algorithm);

test("inventory: Python hashes, HMAC, AES-GCM, ChaCha20 and key derivation", () => {
  const src = [
    "h = hashlib.sha256(data).hexdigest()",
    "d = hashes.SHA384()",
    "m = hmac.new(key, msg, hashlib.sha512)",
    "box = AESGCM(key)",
    "c = Cipher(algorithms.AES256(key), modes.CBC(iv))",
    "x = ChaCha20Poly1305(key)",
    "kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=s, iterations=600000)",
    "# hashlib.sha256 in a comment is ignored",
  ].join("\n");
  assert.deepEqual(algs("app.py", src), ["SHA-256", "SHA-384", "HMAC-SHA512", "AES-GCM", "AES-256-CBC", "ChaCha20-Poly1305", "PBKDF2-SHA256"]);
});

test("inventory: JavaScript ciphers keep key size and mode; WebCrypto too", () => {
  const items = findInventory("a.ts", ["createCipheriv('aes-256-gcm', key, iv)", "createHash('sha256')", "crypto.subtle.digest('SHA-384', buf)", "{ name: 'AES-GCM', length: 256 }", "createHmac('sha256', k)", "pbkdf2Sync(pw, salt, 1e5, 32, 'sha512')"].join("\n"));
  assert.deepEqual(items.map((i) => i.algorithm), ["AES-256-GCM", "SHA-256", "SHA-384", "AES-256-GCM", "HMAC-SHA256", "PBKDF2-SHA512"]);
  const aes = items[0];
  assert.equal(aes.keySize, 256);
  assert.equal(aes.mode, "gcm");
  assert.equal(aes.primitive, "ae");
  assert.equal(aes.nistQuantumLevel, 5);
  assert.deepEqual(aes.functions, ["encrypt", "decrypt"]);
});

test("inventory: Go and Java", () => {
  assert.deepEqual(algs("m.go", "h := sha256.Sum256(b)\nb, _ := aes.NewCipher(k)\ng, _ := cipher.NewGCM(b)\nmac := hmac.New(sha256.New, k)\nk := argon2.IDKey(p, s, 1, 64*1024, 4, 32)"), ["SHA-256", "AES", "AES-GCM", "HMAC-SHA256", "Argon2"]);
  assert.deepEqual(algs("A.java", 'MessageDigest.getInstance("SHA-256");\nCipher.getInstance("AES/GCM/NoPadding");\nMac.getInstance("HmacSHA384");\nSecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");\nkeyGen.init(256);'), ["SHA-256", "AES-GCM", "HMAC-SHA384", "PBKDF2-SHA256", "AES-256"]);
});

test("inventory: post-quantum algorithms with their NIST level", () => {
  const items = findInventory("pq.go", "k := mlkem.GenerateKey768()\nalg := \"ML-KEM-768\"\ncurves := []tls.CurveID{tls.X25519MLKEM768}\nsig := \"ML-DSA-65\"");
  assert.deepEqual(items.map((i) => [i.algorithm, i.nistQuantumLevel]), [["ML-KEM-768", 3], ["X25519MLKEM768", 3], ["ML-DSA-65", 3]]);
});

test("inventory: weak and broken algorithms are left to findings, docs and lockfiles are ignored", () => {
  assert.deepEqual(algs("a.py", "hashlib.md5(x)\nhashlib.sha1(x)\nAES.new(k, AES.MODE_ECB)"), []);
  assert.deepEqual(algs("README.md", "We use hashlib.sha256 everywhere"), []);
  const r = scanFiles([{ path: "package-lock.json", content: '"integrity": "sha512-abc"' }, { path: "test/x.test.ts", content: "createHash('sha256')" }, { path: "src/x.ts", content: "createHash('sha256')" }]);
  assert.deepEqual(r.inventory.map((i) => i.file), ["src/x.ts"]);
});

test("inventory: the CBOM lists safe algorithms next to findings, with usage, mode and level", () => {
  const { findings, inventory } = scanFiles([{ path: "src/a.ts", content: "createCipheriv('aes-128-cbc', k, iv)\ncreateHash('sha256')\ncreateHash('sha256')\ngenerateKeyPairSync('rsa', { modulusLength: 2048 })" }]);
  const cbom = buildCbom(findings, { repo: "r", toolVersion: "t", timestamp: "2026-11-23T00:00:00Z" }, inventory);
  const byName = Object.fromEntries(cbom.components.map((c) => [c.name, c]));
  assert.ok(byName["RSA-2048"]);
  assert.deepEqual((byName["RSA-2048"].cryptoProperties as { algorithmProperties: { cryptoFunctions: string[] } }).algorithmProperties.cryptoFunctions, ["encrypt", "decrypt"]);
  const sha = byName["SHA-256"];
  assert.equal(sha.properties.find((p) => p.name === "hardkeel:occurrences")?.value, "2");
  assert.equal(sha.properties.find((p) => p.name === "hardkeel:risk")?.value, "ok");
  const aes = byName["AES-128-CBC"].cryptoProperties as { algorithmProperties: Record<string, unknown> };
  assert.deepEqual(aes.algorithmProperties, { primitive: "block-cipher", nistQuantumSecurityLevel: 1, parameterSetIdentifier: "128", mode: "cbc", cryptoFunctions: ["encrypt", "decrypt"] });
  assert.match(byName["AES-128-CBC"].properties.map((p) => p.value).join(" "), /integrity/);
});

test("inventory: never changes the grade", async () => {
  const { readinessScore } = await import("../src/score.ts");
  const a = scanFiles([{ path: "src/a.ts", content: "generateKeyPairSync('rsa', { modulusLength: 2048 })" }]);
  const b = scanFiles([{ path: "src/a.ts", content: "generateKeyPairSync('rsa', { modulusLength: 2048 })\ncreateHash('sha256')\ncreateCipheriv('aes-256-gcm', k, iv)" }]);
  assert.deepEqual(readinessScore(a.findings, a.pqc), readinessScore(b.findings, b.pqc));
});

test("cbom: an id per run, a folder named without its path, every asset linked, no line 0", () => {
  const f = { kind: "crypto" as const, ruleId: "x", title: "t", algorithm: "RSA", primitive: "public-key-encryption" as const, risk: "quantum-vulnerable" as const, severity: "medium" as const, file: "192.168.1.1:443", line: 0, snippet: "", fix: "f", keySize: 2048 };
  const a = buildCbom([f], { repo: "/home/someone/work/shop-api/", toolVersion: "t" });
  const b = buildCbom([f], { repo: "C:\\Users\\someone\\shop-api", toolVersion: "t" });
  assert.match(a.serialNumber, /^urn:uuid:[0-9a-f-]{36}$/);
  assert.notEqual(a.serialNumber, b.serialNumber);
  assert.equal(a.metadata.component.name, "shop-api");
  assert.equal(b.metadata.component.name, "shop-api");
  assert.equal(buildCbom([f], { repo: "owner/name", toolVersion: "t" }).metadata.component.name, "owner/name");
  assert.deepEqual(a.dependencies, [{ ref: "subject", dependsOn: ["crypto:rsa-2048"] }]);
  assert.deepEqual(a.components[0].evidence.occurrences, [{ location: "192.168.1.1:443" }]);
});
