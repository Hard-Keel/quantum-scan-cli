// Sign-in setup on a proved website: the signing algorithm of OAuth, OpenID Connect and SAML.
// Sign-in tokens and assertions are signed with RSA or elliptic curves almost everywhere, and a
// quantum computer that can forge them can sign in as anyone. This reads the public setup a sign-in
// client reads, nothing else: one GET for the OpenID Connect discovery document, one for its key set
// when that's on a proved domain, or one for a SAML metadata URL the person lists. No logins.

import { X509Certificate } from "node:crypto";
import type { ActivityLog } from "./map-activity.ts";
import type { AreaResult, MapFinding } from "./map-types.ts";
import { coveringDomain, type WebTarget } from "./map-web.ts";

export interface HttpResponse {
  status: number;
  body: string;
}
export type HttpGet = (url: string) => Promise<HttpResponse | { error: string }>;

const MAX_BODY = 512 * 1024;
const TIMEOUT_MS = 8000;

/** A plain GET: no cookies, no redirects followed, a short timeout, and at most 512 KB read. */
export function httpGet(version: string): HttpGet {
  return async (url) => {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, { redirect: "manual", signal: ctl.signal, headers: { accept: "application/json, application/samlmetadata+xml, application/xml;q=0.9, */*;q=0.1", "user-agent": `hardkeel-quantum-scan/${version}` } });
      if (res.status !== 200) return { status: res.status, body: "" };
      const reader = res.body?.getReader();
      let body = "";
      const dec = new TextDecoder();
      if (reader) {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          body += dec.decode(value, { stream: true });
          if (body.length > MAX_BODY) {
            await reader.cancel();
            return { error: "response too large" };
          }
        }
      }
      return { status: 200, body };
    } catch (e) {
      return { error: ctl.signal.aborted ? "timed out" : ((e as { cause?: { code?: string } }).cause?.code ?? (e instanceof Error ? e.message : String(e))) };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** What a JOSE "alg" name means here. */
export function joseAlg(alg: string): { algorithm: string; quantumSafe?: boolean; unsigned?: boolean; symmetric?: boolean } | null {
  const a = alg.trim();
  if (/^none$/i.test(a)) return { algorithm: "Unsigned sign-in tokens", unsigned: true };
  if (/^(RS|PS)(256|384|512)$/.test(a)) return { algorithm: "RSA signature" };
  if (/^ES(256|384|512|256K)$/.test(a)) return { algorithm: "ECDSA" };
  if (/^(EdDSA|Ed25519|Ed448)$/.test(a)) return { algorithm: a === "Ed448" ? "Ed448" : "Ed25519" };
  if (/^HS(256|384|512)$/.test(a)) return { algorithm: "HMAC", symmetric: true };
  if (/^ML-DSA-(44|65|87)$/.test(a)) return { algorithm: "ML-DSA", quantumSafe: true };
  if (/^SLH-DSA/i.test(a)) return { algorithm: "SLH-DSA", quantumSafe: true };
  return null;
}

const SIG_FIX = "Plan to move sign-in signing to ML-DSA (FIPS 204) once your identity provider and its clients support it, and keep signing keys short-lived so they're easy to rotate.";

/** Bits in an RSA modulus given as base64url. */
function rsaBits(n: string): number | undefined {
  try {
    const b = Buffer.from(n, "base64url");
    let i = 0;
    while (i < b.length && b[i] === 0) i++;
    return (b.length - i) * 8;
  } catch {
    return undefined;
  }
}

/** Findings from an OpenID Connect or OAuth discovery document and, when given, its key set. */
export function signinFindings(label: string, discovery: Record<string, unknown>, jwks?: { keys?: { kty?: string; crv?: string; n?: string; alg?: string }[] }): { findings: MapFinding[]; strengths: { algorithm: string; title: string }[] } {
  const base = { area: "web" as const, target: label, internetFacing: true };
  const findings: MapFinding[] = [];
  const strengths: { algorithm: string; title: string }[] = [];
  const algs = new Set<string>();
  for (const k of ["id_token_signing_alg_values_supported", "userinfo_signing_alg_values_supported", "request_object_signing_alg_values_supported", "token_endpoint_auth_signing_alg_values_supported", "authorization_signing_alg_values_supported", "introspection_signing_alg_values_supported"]) {
    const v = discovery[k];
    if (Array.isArray(v)) for (const a of v) if (typeof a === "string") algs.add(a);
  }
  for (const k of jwks?.keys ?? []) if (typeof k.alg === "string") algs.add(k.alg);

  const vulnerable = new Map<string, string[]>();
  for (const a of algs) {
    const m = joseAlg(a);
    if (!m) continue;
    if (m.unsigned) {
      findings.push({ ...base, ruleId: "web-signin-unsigned", title: "Sign-in setup allows unsigned tokens (alg none)", algorithm: m.algorithm, primitive: "signature", risk: "weak-now", severity: "high", fix: "Remove \"none\" from the allowed signing algorithms. Anyone can forge an unsigned token." });
    } else if (m.quantumSafe) {
      if (!strengths.some((s) => s.algorithm === m.algorithm)) strengths.push({ algorithm: m.algorithm, title: `Sign-in tokens can be signed with ${m.algorithm}` });
    } else if (!m.symmetric) {
      vulnerable.set(m.algorithm, [...(vulnerable.get(m.algorithm) ?? []), a]);
    }
  }
  for (const [algorithm, names] of vulnerable) {
    findings.push({ ...base, ruleId: "web-signin-signature", title: `Sign-in tokens are signed with ${names.sort().join(", ")}`, algorithm, primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: SIG_FIX });
  }
  for (const k of jwks?.keys ?? []) {
    if (k.kty !== "RSA" || !k.n) continue;
    const bits = rsaBits(k.n);
    if (bits && bits < 2048) {
      findings.push({ ...base, ruleId: "web-signin-small-rsa", title: `Sign-in signing key is RSA ${bits}`, algorithm: "RSA signature", primitive: "signature", risk: "weak-now", severity: "high", keySize: bits, fix: "Rotate to a key of at least RSA 2048 (3072 for keys meant to last), then plan the move to ML-DSA." });
      break;
    }
  }
  return { findings, strengths };
}

const SAML_SIG = /SignatureMethod\s+Algorithm\s*=\s*["']([^"']+)["']/g;
const SAML_CERT = /<(?:[A-Za-z0-9_]+:)?X509Certificate>\s*([A-Za-z0-9+/=\s]{100,}?)\s*<\/(?:[A-Za-z0-9_]+:)?X509Certificate>/g;

/** Findings from SAML metadata: the signing certificates' keys and any signature method it names. */
export function samlFindings(label: string, xml: string): { findings: MapFinding[]; strengths: { algorithm: string; title: string }[] } {
  const base = { area: "web" as const, target: label, internetFacing: true };
  const findings: MapFinding[] = [];
  const strengths: { algorithm: string; title: string }[] = [];
  const keys = new Map<string, number | undefined>();
  for (const m of xml.matchAll(SAML_CERT)) {
    try {
      const c = new X509Certificate(Buffer.from(m[1].replace(/\s+/g, ""), "base64"));
      const k = c.publicKey;
      const type = k.asymmetricKeyType ?? "unknown";
      const bits = k.asymmetricKeyDetails?.modulusLength;
      const had = keys.get(type);
      keys.set(type, bits === undefined ? had : had === undefined ? bits : Math.min(had, bits)); // the weakest key counts
    } catch {
      // Not a certificate we can read; leave it out.
    }
  }
  for (const [type, bits] of keys) {
    if (/^ml-dsa/i.test(type)) {
      strengths.push({ algorithm: "ML-DSA", title: "SAML signing certificate uses ML-DSA" });
      continue;
    }
    const algorithm = type === "rsa" || type === "rsa-pss" ? "RSA signature" : type === "ec" ? "ECDSA" : type === "ed25519" ? "Ed25519" : null;
    if (!algorithm) continue;
    if (algorithm === "RSA signature" && bits && bits < 2048) {
      findings.push({ ...base, ruleId: "web-saml-small-rsa", title: `SAML signing certificate is RSA ${bits}`, algorithm, primitive: "signature", risk: "weak-now", severity: "high", keySize: bits, fix: "Replace the signing certificate with at least RSA 2048 (3072 for long-lived), then plan the move to ML-DSA." });
    } else {
      findings.push({ ...base, ruleId: "web-saml-signature", title: `SAML assertions are signed with ${algorithm === "RSA signature" ? `RSA${bits ? ` ${bits}` : ""}` : algorithm}`, algorithm, primitive: "signature", risk: "quantum-vulnerable", severity: "medium", longLived: true, ...(bits ? { keySize: bits } : {}), fix: SIG_FIX });
    }
  }
  const methods = new Set([...xml.matchAll(SAML_SIG)].map((m) => m[1]));
  if ([...methods].some((u) => /(rsa|dsa|ecdsa)-sha1$/i.test(u))) {
    findings.push({ ...base, ruleId: "web-saml-sha1", title: "SAML metadata is signed with SHA-1", algorithm: "SHA-1", primitive: "hash", risk: "weak-now", severity: "high", fix: "Sign with SHA-256 (rsa-sha256 or ecdsa-sha256)." });
  }
  return { findings, strengths };
}

/**
 * The sign-in check for one website. With no path: the OpenID Connect discovery document, if the
 * site has one (most don't, and that's fine). With a path the person listed: that URL, read as
 * OpenID Connect discovery or SAML metadata, whichever it is.
 */
export async function checkSignin(t: WebTarget, paths: string[], proved: string[], log: ActivityLog, res: AreaResult, get: HttpGet): Promise<void> {
  const origin = `https://${t.host}${t.port === 443 ? "" : `:${t.port}`}`;
  const asked = paths.length > 0;
  for (const path of asked ? paths : ["/.well-known/openid-configuration"]) {
    const url = origin + path;
    log.record("web", t.label, `HTTPS GET ${path} (public sign-in setup)`);
    const r = await get(url);
    if ("error" in r) {
      if (asked) res.errors.push({ area: "web", target: `${t.label}${path}`, kind: /timed out/.test(r.error) ? "timeout" : "other", message: `couldn't read the sign-in setup: ${r.error}` });
      continue;
    }
    if (r.status !== 200) {
      if (asked) res.skipped.push({ target: `${t.label}${path}`, reason: `sign-in setup not found (HTTP ${r.status})` });
      continue;
    }
    const body = r.body.trim();
    let out: { findings: MapFinding[]; strengths: { algorithm: string; title: string }[] } | null = null;
    if (body.startsWith("{")) {
      let doc: Record<string, unknown>;
      try {
        doc = JSON.parse(body);
      } catch {
        if (asked) res.skipped.push({ target: `${t.label}${path}`, reason: "not a sign-in setup document" });
        continue;
      }
      if (typeof doc.issuer !== "string") {
        if (asked) res.skipped.push({ target: `${t.label}${path}`, reason: "not a sign-in setup document" });
        continue;
      }
      let jwks: { keys?: { kty?: string; crv?: string; n?: string; alg?: string }[] } | undefined;
      const ju = typeof doc.jwks_uri === "string" ? doc.jwks_uri : null;
      if (ju) {
        let host: string | null = null;
        try {
          const u = new URL(ju);
          host = u.protocol === "https:" ? u.hostname.toLowerCase() : null;
        } catch {
          host = null;
        }
        if (host && coveringDomain(host, proved)) {
          log.record("web", t.label, `HTTPS GET ${new URL(ju).pathname} (public sign-in keys)`);
          const k = await get(ju);
          if (!("error" in k) && k.status === 200) {
            try {
              jwks = JSON.parse(k.body);
            } catch {
              jwks = undefined;
            }
          }
        } else if (host) {
          res.skipped.push({ target: t.label, reason: `sign-in keys are on ${host}, which isn't a proved domain, so they weren't read. The listed algorithms were still checked.` });
        }
      }
      out = signinFindings(`${t.label} (sign-in)`, doc, jwks);
    } else if (/<(?:[A-Za-z0-9_]+:)?EntityDescriptor\b|<(?:[A-Za-z0-9_]+:)?EntitiesDescriptor\b/.test(body)) {
      out = samlFindings(`${t.label}${path} (SAML)`, body);
    } else if (asked) {
      res.skipped.push({ target: `${t.label}${path}`, reason: "not OpenID Connect discovery or SAML metadata" });
    }
    if (out) {
      res.findings.push(...out.findings);
      for (const s of out.strengths) res.strengths.push({ area: "web", target: t.label, ...s });
    }
  }
}
