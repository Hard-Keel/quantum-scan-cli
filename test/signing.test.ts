import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/scan.ts";
import { findSecrets } from "../src/secrets.ts";

const algs = (path: string, src: string) => scanFile(path, src).map((f) => `${f.algorithm}@${f.line}`);

test("js: signing and key encryption the way JWT and auth libraries write it", () => {
  const src = [
    "const signer = crypto.createSign('RSA-SHA' + bits);", // jwa
    "const sign = crypto.createSign('RSA-SHA256');", // google-auth-library
    "const v = crypto.createVerify('ecdsa-with-SHA256');",
    "const out = crypto.publicEncrypt({ key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, buf);",
    "const SUPPORTED_ALGS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'HS256'];", // jsonwebtoken
    "case 'RSA-OAEP-256':", // jose
    "case 'ECDH-ES+A256KW':",
    "const jwk = { kty: 'EC', crv: 'P-256', x, y };",
    "const ec = new EC('secp256k1');", // elliptic
    "import { secp256k1 } from '@noble/curves/secp256k1';",
    "const kp = nacl.sign.keyPair();",
    "crypto.createHmac('sha256', key); jwt.sign(p, k, { algorithm: 'HS256' });",
  ].join("\n");
  assert.deepEqual(algs("lib/sign.js", src), [
    "RSA signature@1", "RSA signature@2", "ECDSA@3", "RSA encryption@4",
    "RSA signature@5", "RSA encryption@6", "ECDH@7", "EC@8", "ECDSA@9", "ECDSA@10", "Ed25519@11",
  ]);
});

test("python, go and java: JWT algorithms and RSA libraries", () => {
  assert.deepEqual(algs("app/auth.py", 'token = jwt.encode(claims, key, algorithm="RS256")\nsig = key.sign(data, ec.ECDSA(hashes.SHA256()))\n(pub, priv) = rsa.newkeys(1024)'), ["RSA signature@1", "ECDSA@2", "RSA@3"]);
  assert.equal(scanFile("app/auth.py", "(pub, priv) = rsa.newkeys(1024)")[0].risk, "weak-now");
  assert.deepEqual(algs("auth/token.go", "t := jwt.NewWithClaims(jwt.SigningMethodES256, claims)\nt2 := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)"), ["ECDSA@1"]);
  assert.deepEqual(algs("src/Auth.java", "Jwts.builder().signWith(key, SignatureAlgorithm.RS256);\nAlgorithm a = Algorithm.ECDSA256(pub, priv);\nAlgorithm h = Algorithm.HMAC256(secret);"), ["RSA signature@1", "ECDSA@2"]);
});

test("look-alikes stay quiet", () => {
  const src = [
    "const h = crypto.createSign('SHA256');", // key type unknown from this line
    "const alg = 'HS256';",
    "const id = 'RS2560';",
    "// jwt.sign(payload, key, { algorithm: 'RS256' })",
    " * @param alg 'RS256' or 'ES256'",
    "const kp = nacl.secretbox(msg, nonce, key);",
  ].join("\n");
  assert.deepEqual(algs("lib/x.js", src), []);
  assert.deepEqual(algs("types/index.d.ts", "export type Alg = 'RS256' | 'ES256';"), []);
  assert.deepEqual(algs("app/x.py", '# algorithm="RS256" was the old default'), []);
});

test("secrets: a constant named for its own value is not a secret", () => {
  assert.deepEqual(findSecrets('const X_AWS_EC2_METADATA_TOKEN = "x-aws-ec2-metadata-token";'), []);
  assert.equal(findSecrets('const API_TOKEN = "x9fK2mQ7pL4vR8tZ1wB6nD3s";')[0]?.rule.id, "generic-assignment");
});

test("secrets: word-only names and commented examples are not secrets", () => {
  assert.deepEqual(findSecrets("const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';"), []);
  assert.deepEqual(findSecrets('  UpdateClientTokenVaultAccess: "update:client_token_vault_privileged_access",'), []);
  assert.deepEqual(scanFile("src/apis/kms.ts", ' *   //   "sharedSecretCrc32c": "my_sharedSecretCrc32c9f3a",').filter((f) => f.kind === "secret"), []);
  assert.equal(scanFile("src/ngrok.js", "  authToken: '5W1bR3h8kQ2pX7vN4mZ9tL6c',").filter((f) => f.kind === "secret").length, 1);
});
