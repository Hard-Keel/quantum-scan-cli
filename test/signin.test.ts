import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ActivityLog } from "../src/map-activity.ts";
import { emptyResult } from "../src/map-types.ts";
import { checkSignin, joseAlg, samlFindings, signinFindings, type HttpGet } from "../src/map-signin.ts";
import { parseTarget, runWeb, type Handshake } from "../src/map-web.ts";

const T = { host: "login.ours.com", port: 443, kind: "tls" as const, label: "login.ours.com:443" };

test("signin: JOSE names map to what they are", () => {
  assert.equal(joseAlg("RS256")?.algorithm, "RSA signature");
  assert.equal(joseAlg("ES384")?.algorithm, "ECDSA");
  assert.equal(joseAlg("EdDSA")?.algorithm, "Ed25519");
  assert.ok(joseAlg("HS256")?.symmetric);
  assert.ok(joseAlg("none")?.unsigned);
  assert.ok(joseAlg("ML-DSA-65")?.quantumSafe);
  assert.equal(joseAlg("XYZ"), null);
});

test("signin: discovery document with RSA and ECDSA, alg none, and a small JWKS key", () => {
  const n = generateKeyPairSync("rsa", { modulusLength: 1024 }).publicKey.export({ format: "jwk" }).n!;
  const r = signinFindings("login.ours.com:443 (sign-in)", { issuer: "https://login.ours.com", id_token_signing_alg_values_supported: ["RS256", "PS256", "ES256", "HS256", "none"] }, { keys: [{ kty: "RSA", n, alg: "RS256" }] });
  const ids = r.findings.map((f) => `${f.ruleId}:${f.algorithm}`).sort();
  assert.deepEqual(ids, ["web-signin-signature:ECDSA", "web-signin-signature:RSA signature", "web-signin-small-rsa:RSA signature", "web-signin-unsigned:Unsigned sign-in tokens"]);
  assert.equal(r.findings.find((f) => f.algorithm === "RSA signature" && f.ruleId === "web-signin-signature")!.title, "Sign-in tokens are signed with PS256, RS256");
  assert.equal(r.findings.find((f) => f.ruleId === "web-signin-small-rsa")!.keySize, 1024);
  assert.ok(r.findings.every((f) => f.internetFacing));
});

test("signin: ML-DSA is credited and HMAC alone gives nothing to fix", () => {
  const r = signinFindings("x", { issuer: "i", id_token_signing_alg_values_supported: ["ML-DSA-65", "HS256"] });
  assert.equal(r.findings.length, 0);
  assert.deepEqual(r.strengths.map((s) => s.algorithm), ["ML-DSA"]);
});

const tmp = mkdtempSync(join(tmpdir(), "qs-saml-"));
let certs: { small: string; ok: string } | null = null;
try {
  const mk = (name: string, bits: number) => {
    execFileSync("openssl", ["req", "-x509", "-nodes", "-newkey", `rsa:${bits}`, "-keyout", join(tmp, `${name}.key`), "-out", join(tmp, `${name}.pem`), "-days", "1", "-subj", "/CN=idp"], { stdio: "ignore" });
    return readFileSync(join(tmp, `${name}.pem`), "utf8").replace(/-----[^-]+-----|\s/g, "");
  };
  certs = { small: mk("small", 1024), ok: mk("ok", 2048) };
} catch {
  certs = null;
}
const metadata = (cert: string, method = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256") =>
  `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.ours.com"><ds:Signature><ds:SignedInfo><ds:SignatureMethod Algorithm="${method}"/></ds:SignedInfo></ds:Signature><md:IDPSSODescriptor><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>\n${cert}\n</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor></md:IDPSSODescriptor></md:EntityDescriptor>`;

test("signin: SAML metadata reports the signing key and SHA-1 signatures", { skip: !certs && "needs the openssl command" }, () => {
  const ok = samlFindings("idp:443/metadata (SAML)", metadata(certs!.ok));
  assert.deepEqual(ok.findings.map((f) => [f.ruleId, f.keySize, f.longLived]), [["web-saml-signature", 2048, true]]);
  assert.equal(ok.findings[0].title, "SAML assertions are signed with RSA 2048");
  const bad = samlFindings("x", metadata(certs!.small, "http://www.w3.org/2000/09/xmldsig#rsa-sha1"));
  assert.deepEqual(bad.findings.map((f) => f.ruleId).sort(), ["web-saml-sha1", "web-saml-small-rsa"]);
});

test("signin: a site with no sign-in setup gives nothing and asks once", async () => {
  const urls: string[] = [];
  const get: HttpGet = async (u) => (urls.push(u), { status: 404, body: "" });
  const res = emptyResult("web");
  await checkSignin(T, [], ["ours.com"], new ActivityLog(), res, get);
  assert.deepEqual(urls, ["https://login.ours.com/.well-known/openid-configuration"]);
  assert.equal(res.findings.length + res.skipped.length + res.errors.length, 0);
});

test("signin: keys are read only from a proved domain", async () => {
  const urls: string[] = [];
  const disc = (jwks: string) => JSON.stringify({ issuer: "https://login.ours.com", jwks_uri: jwks, id_token_signing_alg_values_supported: ["RS256"] });
  const get = (jwks: string): HttpGet => async (u) => (urls.push(u), u.endsWith("openid-configuration") ? { status: 200, body: disc(jwks) } : { status: 200, body: JSON.stringify({ keys: [] }) });
  const a = emptyResult("web");
  await checkSignin(T, [], ["ours.com"], new ActivityLog(), a, get("https://keys.ours.com/jwks.json"));
  assert.deepEqual(urls, ["https://login.ours.com/.well-known/openid-configuration", "https://keys.ours.com/jwks.json"]);
  urls.length = 0;
  const b = emptyResult("web");
  await checkSignin(T, [], ["ours.com"], new ActivityLog(), b, get("https://ours.vendor-idp.com/jwks"));
  assert.deepEqual(urls, ["https://login.ours.com/.well-known/openid-configuration"]);
  assert.match(b.skipped[0].reason, /vendor-idp\.com.*isn't a proved domain/);
  assert.equal(b.findings[0].ruleId, "web-signin-signature");
});

test("signin: a listed SAML metadata URL keeps its case and is read as SAML", { skip: !certs && "needs the openssl command" }, async () => {
  const p = parseTarget("https://adfs.ours.com/FederationMetadata/2007-06/FederationMetadata.xml?x=1");
  assert.ok(!("error" in p));
  if ("error" in p) return;
  assert.equal(p.path, "/FederationMetadata/2007-06/FederationMetadata.xml");
  assert.equal(p.label, "adfs.ours.com:443");
  assert.equal((parseTarget("ssh://git.ours.com/x") as { path?: string }).path, undefined);

  const urls: string[] = [];
  const get: HttpGet = async (u) => (urls.push(u), { status: 200, body: metadata(certs!.ok) });
  const hs = async (_h: string, _p: number, o: Record<string, unknown>): Promise<Handshake> => (o.ecdhCurve || o.maxVersion ? { ok: false, error: "tls" } : { ok: true, protocol: "TLSv1.3", keyExchange: "X25519" });
  const res = await runWeb(["adfs.ours.com", "https://adfs.ours.com/FederationMetadata/2007-06/FederationMetadata.xml"], new ActivityLog(), { token: "tok", lookup: async () => [["hardkeel-scan-verify=tok"]], handshake: hs, gapMs: 0, cipherProbe: async () => false, hybridTestable: true, http: get });
  assert.deepEqual(urls, ["https://adfs.ours.com/FederationMetadata/2007-06/FederationMetadata.xml"]); // the listed URL instead of discovery, and the TLS checks ran once
  assert.ok(res.findings.some((f) => f.ruleId === "web-saml-signature"));
  assert.equal(res.checked.length, 1);
});

test("signin: nothing is fetched for a host that isn't proved or didn't answer", async () => {
  let fetched = 0;
  const get: HttpGet = async () => (fetched++, { status: 404, body: "" });
  await runWeb(["theirs.com"], new ActivityLog(), { token: "tok", lookup: async () => [], http: get, gapMs: 0 });
  await runWeb(["down.ours.com"], new ActivityLog(), { token: "tok", lookup: async () => [["hardkeel-scan-verify=tok"]], handshake: async () => ({ ok: false, error: "refused" }), http: get, gapMs: 0 });
  assert.equal(fetched, 0);
});
