import { test } from "node:test";
import assert from "node:assert/strict";
import { addedLines, scanFile } from "../src/scan.ts";
import { buildCbom } from "../src/cbom.ts";
import { checkConclusion, migrationPlan, prComment } from "../src/report.ts";

const algs = (path: string, src: string) => scanFile(path, src).map((f) => `${f.algorithm}@${f.line}`);

test("python: RSA, EC, weak hash, ECB", () => {
  const src = [
    "from cryptography.hazmat.primitives.asymmetric import rsa, ec",
    "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
    "ek = ec.generate_private_key(ec.SECP256R1())",
    "pw = hashlib.md5(password).hexdigest()",
    "c = Cipher(algorithms.AES(k), modes.ECB())",
    "x = X25519PrivateKey.generate()",
  ].join("\n");
  assert.deepEqual(algs("app/crypto.py", src), ["RSA@2", "ECDSA@3", "MD5@4", "ECB mode@5", "X25519@6"]);
});

test("python: short RSA key is weak now", () => {
  const [f] = scanFile("a.py", "RSA.generate(1024)");
  assert.equal(f.risk, "weak-now");
  assert.equal(f.keySize, 1024);
});

test("js/ts: node crypto, webcrypto, jwt", () => {
  const src = [
    "const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 4096 });",
    "const ecdh = crypto.createECDH('prime256v1');",
    "await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);",
    "jwt.sign(payload, key, { algorithm: 'RS256' });",
    "crypto.createHash('sha1').update(password);",
    "crypto.createCipheriv('des-ede3-cbc', k, iv);",
    "crypto.createHash('sha256');",
  ].join("\n");
  assert.deepEqual(algs("src/auth.ts", src), ["RSA@1", "ECDH@2", "ECDSA@3", "RSA signature@4", "SHA-1@5", "3DES@6"]);
});

test("go: rsa, ecdh, md5, old tls", () => {
  const src = [
    "k, _ := rsa.GenerateKey(rand.Reader, 2048)",
    "c := ecdh.X25519()",
    "sum := md5.Sum([]byte(password))",
    "cfg := &tls.Config{MinVersion: tls.VersionTLS10}",
  ].join("\n");
  assert.deepEqual(algs("main.go", src), ["RSA@1", "X25519@2", "MD5@3", "TLS 1.0/1.1@4"]);
});

test("java: keypair, signature, digest, cipher", () => {
  const src = [
    'KeyPairGenerator g = KeyPairGenerator.getInstance("EC");',
    'Signature s = Signature.getInstance("SHA256withRSA");',
    'MessageDigest pwd = MessageDigest.getInstance("SHA-1");',
    'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");',
    'Cipher r = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");',
    'KeyAgreement ka = KeyAgreement.getInstance("ECDH");',
  ].join("\n");
  assert.deepEqual(algs("Main.java", src), ["ECDSA@1", "RSA signature@2", "SHA-1@3", "ECB mode@4", "RSA encryption@5", "ECDH@6"]);
});

test("rules stay in their language", () => {
  assert.deepEqual(algs("notes.md", "Call rsa.GenerateKey( in Go"), []);
});

test("secrets: specific tokens found and masked, placeholders skipped", () => {
  // Built at runtime so the fixture itself never looks like a real secret.
  const aws = "AKIA" + "ABCDEFGHIJKLMNOP";
  const gh = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
  const src = [`aws_key = "${aws}"`, `token: ${gh}`, 'api_key = "your-api-key-here-please"', "-----BEGIN RSA PRIVATE" + " KEY-----", "MIIEow" + "IBAAKCAQEAq1x2y3z4w5v6u7t8s9r0QpOnMlKjIhGfEdCb"].join("\n");
  const fs = scanFile("config/settings.py", src).filter((f) => f.kind === "secret");
  assert.deepEqual(fs.map((f) => `${f.ruleId}@${f.line}`), ["aws-access-key-id@1", "github-token@2", "private-key@4"]);
  assert.ok(!fs[0].snippet.includes(aws), "secret is masked");
});

test("secrets: a private-key header with placeholder text is not a leak", () => {
  const doc = 'key="-----BEGIN PRIVATE' + ' KEY-----\\nXXXX\\nXXXX\\n-----END PRIVATE KEY-----"';
  assert.deepEqual(scanFile("docs/config.md", doc), []);
});

test("secrets: generic high-entropy assignment", () => {
  const val = "Zq8" + "rT2vLm9XwP4kNb7Hs3Jd";
  const fs = scanFile("app.js", `const DB_PASSWORD = "${val}";`);
  assert.equal(fs[0]?.ruleId, "generic-assignment");
  assert.deepEqual(scanFile("app.js", 'const password = "aaaaaaaaaaaaaaaaaaaa";'), []);
});

test("addedLines reads a unified diff", () => {
  const patch = "@@ -1,3 +1,4 @@\n a\n-b\n+c\n+d\n e\n@@ -10,2 +11,2 @@\n x\n+y";
  assert.deepEqual([...addedLines(patch)], [2, 3, 12]);
});

test("only added lines are reported for a PR", () => {
  const src = "pw = hashlib.md5(password)\n\n\n\n\n\n\n\n\ntok = hashlib.sha1(token)";
  const fs = scanFile("x.py", src, new Set([10]));
  assert.deepEqual(fs.map((f) => f.algorithm), ["SHA-1"]);
});

test("skips vendored and lock files", () => {
  assert.deepEqual(scanFile("node_modules/x/index.js", "createECDH('p')"), []);
  assert.deepEqual(scanFile("yarn.lock", "createECDH('p')"), []);
});

test("cbom, conclusion and report", () => {
  const fs = scanFile("a.py", "rsa.generate_private_key(public_exponent=65537, key_size=2048)\nec.ECDH()\nhashlib.md5(password)");
  const bom = buildCbom(fs, { repo: "acme/api", toolVersion: "0.1.0", timestamp: "2026-11-19T00:00:00Z" });
  assert.equal(bom.specVersion, "1.6");
  assert.deepEqual(bom.components.map((c) => c.name).sort(), ["ECDH", "MD5", "RSA-2048"]);
  assert.equal(checkConclusion(fs), "failure"); // MD5 is weak now
  assert.equal(checkConclusion(fs.filter((f) => f.algorithm !== "MD5")), "neutral");
  assert.equal(checkConclusion([]), "success");
  const plan = migrationPlan(fs);
  assert.deepEqual(plan.map((g) => g.algorithm), ["MD5", "RSA", "ECDH"].sort((a, b) => (a === "MD5" ? -1 : b === "MD5" ? 1 : 0)));
  assert.match(prComment(fs), /hardkeel-quantum-scan/);
});

test("comment: splits fix-now from plan-later and links the line", () => {
  const fs = scanFile("a.py", ["pw = hashlib.md5(password)", "k = ec.generate_private_key(ec.SECP256R1())"].join("\n"));
  const c = prComment(fs, { repo: "o/r", sha: "s1" });
  assert.match(c, /\*\*1 problem to fix before merging\.\*\* 1 more item to plan for\./);
  assert.match(c, /#### Fix before merging[\s\S]*MD5 hash[\s\S]*#### Plan for later/);
  assert.match(c, /\(https:\/\/github\.com\/o\/r\/blob\/s1\/a\.py#L1\)/);
  assert.doesNotMatch(c, /\.\./);
});

test("tuning: test code, examples and look-alike values are not flagged", () => {
  const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAwhvqCC+37A+UXgcvDl+7nbVjDI3QErdZBkI1VypVBMkKKWHM\n-----END RSA PRIVATE KEY-----";
  assert.equal(scanFile("tests/certs/server.key", key).length, 0);
  assert.equal(scanFile("docs/usage.rst", key).length, 0);
  assert.equal(scanFile("test/sign.test.js", "generateKeyPairSync('rsa', { modulusLength: 1024 })").length, 0);
  assert.equal(scanFile("lib/auth.py", "return hashlib.md5(x, usedforsecurity=False).hexdigest()").length, 0);
  const lookAlikes = [
    'SECRET_KEY_INSECURE_PREFIX = "django-insecure-abc123XYZ"',
    'MSG_USERAUTH_GSSAPI_TOKEN: "userauth-gssapi-token",',
    '"hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$wagCPXjifgvUFBzq4hqe3w",',
    'val usernameAndPassword = "$username:$password"',
    'private const val TOKEN = "([a-zA-Z0-9-!#$%&\'*+.^_`{|}~]+)"',
  ].join("\n");
  assert.equal(scanFile("src/app.kt", lookAlikes).length, 0);
});

test("tuning: real token formats still count in tests and examples", () => {
  const fs = scanFile("samples/Demo.java", 'String GOOGLE_API_KEY = "AIzaSyD9f8sKq2LmN4pR7tV1wX3yZ5aB6cD8eF0";');
  assert.deepEqual(fs.map((f) => f.algorithm), ["Google API key"]);
});

test("MD5 and SHA-1: flagged for passwords and signing, not for checksums, cache keys or ETags", () => {
  const weak = (path: string, src: string) => scanFile(path, src).filter((f) => f.risk === "weak-now").map((f) => `${f.algorithm}@${f.line}`);
  assert.deepEqual(weak("a.py", "digest = hashlib.md5(password.encode()).hexdigest()"), ["MD5@1"]);
  assert.deepEqual(weak("a.go", "func hashPassword(p string) string {\n  h := sha1.Sum([]byte(p))\n  return hex(h)\n}"), ["SHA-1@2"]);
  assert.deepEqual(weak("a.js", "const sig = crypto.createHmac('sha1', key).update(body)"), ["SHA-1@1"]);
  assert.deepEqual(weak("a.ts", 'export const etag = (body: string) => createHash("sha1").update(body).digest("hex");'), []);
  assert.deepEqual(weak("a.go", "hasher := sha1.New() // #nosec"), []);
  assert.deepEqual(weak("a.py", "cache_key = hashlib.md5(url.encode()).hexdigest()"), []);
  assert.deepEqual(weak("a.go", "func fileChecksum(b []byte) string {\n  sum := md5.Sum(b)\n  return hex(sum)\n}"), []);
  assert.deepEqual(weak("a.py", "h = hashlib.md5(data).hexdigest()"), []);
});
