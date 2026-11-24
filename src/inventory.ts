// The full encryption inventory: every algorithm the code uses, not only the ones to fix.
// Findings cover what quantum computers will break or what is weak now. This records the rest
// (AES, ChaCha20, SHA-2, SHA-3, HMAC, key derivation, and post-quantum algorithms) with key length,
// mode and what it's used for, so the CBOM is a complete list. Nothing here changes the grade.

import { langFor, type Lang } from "./rules.ts";

export type InventoryPrimitive = "block-cipher" | "ae" | "hash" | "mac" | "kdf" | "kem" | "signature";
/** CycloneDX 1.6 cryptoFunctions. */
export type CryptoFunction = "encrypt" | "decrypt" | "digest" | "tag" | "keyderive" | "encapsulate" | "decapsulate" | "sign" | "verify" | "keygen";

export interface InventoryItem {
  algorithm: string; // "AES-256-GCM", "SHA-256", "HMAC-SHA256", "PBKDF2-SHA256", "ML-KEM-768"
  family: string; // "AES", "SHA-2", "HMAC", "PBKDF2", "ML-KEM"
  primitive: InventoryPrimitive;
  functions: CryptoFunction[];
  keySize?: number; // key length in bits (ciphers), or output length (hashes), when the code says
  mode?: string; // "gcm", "cbc", "ctr", "ccm"
  /** NIST post-quantum security category (1-5) where one is defined for this algorithm and size. */
  nistQuantumLevel?: number;
  note?: string;
  file: string;
  line: number; // 1-based
}

interface InvRule {
  id: string;
  langs: Lang[];
  pattern: RegExp;
  item: (m: RegExpMatchArray, line: string) => Omit<InventoryItem, "file" | "line"> | null;
}

const CIPHER_FNS: CryptoFunction[] = ["encrypt", "decrypt"];

/** AES with a known key size and mode. */
function aes(bits: number | undefined, mode: string | undefined): Omit<InventoryItem, "file" | "line"> | null {
  const m = mode?.toLowerCase();
  if (m === "ecb") return null; // a finding already covers ECB
  const ae = m === "gcm" || m === "ccm" || m === "siv" || m === "ocb" || m === "gcm-siv";
  const name = `AES${bits ? `-${bits}` : ""}${m ? `-${m.toUpperCase()}` : ""}`;
  return {
    algorithm: name,
    family: "AES",
    primitive: ae ? "ae" : "block-cipher",
    functions: CIPHER_FNS,
    ...(bits ? { keySize: bits, nistQuantumLevel: bits === 128 ? 1 : bits === 192 ? 3 : bits === 256 ? 5 : undefined } : {}),
    ...(m ? { mode: m } : {}),
    ...(bits === 128 ? { note: "Fine today. Prefer AES-256 for data that must stay secret for decades." } : {}),
    ...(!ae && m === "cbc" ? { note: "CBC has no built-in integrity check. Prefer GCM, or add an HMAC." } : {}),
  };
}

/** SHA-2 and SHA-3 by any common spelling: sha256, SHA-384, sha3_256, SHA3-512. */
function sha(word: string): Omit<InventoryItem, "file" | "line"> | null {
  const w = word.toLowerCase().replace(/[^a-z0-9]/g, "");
  const s3 = w.match(/^sha3(224|256|384|512)$/);
  if (s3) {
    const bits = Number(s3[1]);
    return { algorithm: `SHA3-${bits}`, family: "SHA-3", primitive: "hash", functions: ["digest"], keySize: bits, ...level(bits) };
  }
  const s2 = w.match(/^sha(224|256|384|512)(?:224|256)?$/);
  if (s2) {
    const bits = Number(s2[1]);
    const name = /^sha512(224|256)$/.test(w) ? `SHA-512/${w.slice(6)}` : `SHA-${bits}`;
    return { algorithm: name, family: "SHA-2", primitive: "hash", functions: ["digest"], keySize: bits, ...level(bits) };
  }
  if (/^blake2[bs]/.test(w)) return { algorithm: w.startsWith("blake2b") ? "BLAKE2b" : "BLAKE2s", family: "BLAKE2", primitive: "hash", functions: ["digest"] };
  if (w === "blake3") return { algorithm: "BLAKE3", family: "BLAKE3", primitive: "hash", functions: ["digest"] };
  return null;
}

/** NIST defines categories 2 and 4 by SHA-256 and SHA-384 collision search. */
function level(bits: number): { nistQuantumLevel?: number } {
  return bits === 256 ? { nistQuantumLevel: 2 } : bits === 384 ? { nistQuantumLevel: 4 } : {};
}

/** "SHA-256" -> "SHA256" as HMAC and PBKDF2 names spell it; "SHA3-256" stays. */
const short = (alg: string) => alg.replace(/^SHA-/, "SHA");

function hmac(hashWord: string): Omit<InventoryItem, "file" | "line"> | null {
  const h = sha(hashWord);
  if (!h) return null; // HMAC-MD5 and HMAC-SHA1 are findings already
  return { algorithm: `HMAC-${short(h.algorithm)}`, family: "HMAC", primitive: "mac", functions: ["tag"] };
}

function kdf(name: string, hashWord?: string): Omit<InventoryItem, "file" | "line"> {
  const h = hashWord ? sha(hashWord) : null;
  return { algorithm: h ? `${name}-${short(h.algorithm)}` : name, family: name, primitive: "kdf", functions: ["keyderive"] };
}

const CHACHA: Omit<InventoryItem, "file" | "line"> = { algorithm: "ChaCha20-Poly1305", family: "ChaCha20", primitive: "ae", functions: CIPHER_FNS, keySize: 256 };

/** "aes-256-gcm", "aes256", "aes-128-cbc", "id-aes256-GCM" */
function aesName(s: string): Omit<InventoryItem, "file" | "line"> | null {
  const m = s.toLowerCase().match(/aes[-_]?(128|192|256)?(?:[-_/](gcm-siv|gcm|cbc|ctr|ccm|cfb|ofb|ecb|siv|ocb|wrap))?/);
  if (!m) return null;
  return aes(m[1] ? Number(m[1]) : undefined, m[2]);
}

const NUM = (s: string | undefined) => (s ? Number(s) : undefined);

export const INVENTORY_RULES: InvRule[] = [
  // ---------- Python ----------
  { id: "py-hash", langs: ["python"], pattern: /\bhashlib\.(sha224|sha256|sha384|sha512|sha3_\d{3}|blake2[bs])\s*\(|hashlib\.new\s*\(\s*['"](sha\d{3}|sha3_\d{3}|sha512_\d{3})['"]|\bhashes\.(SHA224|SHA256|SHA384|SHA512|SHA3_\d{3}|BLAKE2[bs])\s*\(/, item: (m) => sha(m[1] ?? m[2] ?? m[3]) },
  { id: "py-hmac", langs: ["python"], pattern: /\bhmac\.(?:new|digest)\s*\([^)]*(?:hashlib\.|['"])(sha\d{3}|sha3_\d{3})/, item: (m) => hmac(m[1]) },
  { id: "py-aesgcm", langs: ["python"], pattern: /\bAESGCM\s*\(|\bAESCCM\s*\(|\bAESGCMSIV\s*\(|\bAESSIV\s*\(|\bAESOCB3\s*\(/, item: (m) => aes(undefined, m[0].match(/AES(GCMSIV|GCM|CCM|SIV|OCB3)/)![1].replace("GCMSIV", "gcm-siv").replace("OCB3", "ocb")) },
  { id: "py-aes-modes", langs: ["python"], pattern: /\balgorithms\.AES(?:128|256)?\s*\(.*\bmodes\.(GCM|CBC|CTR|CFB|OFB)\s*\(|\bAES\.new\s*\(.*\bAES\.MODE_(GCM|CBC|CTR|CCM|EAX|SIV|OCB|CFB|OFB)\b/, item: (m, line) => aes(NUM(line.match(/AES(128|256)\s*\(/)?.[1]), (m[1] ?? m[2]).toLowerCase()) },
  { id: "py-chacha", langs: ["python"], pattern: /\bChaCha20Poly1305\s*\(|\bChaCha20_Poly1305\.new\s*\(/, item: () => CHACHA },
  { id: "py-kdf", langs: ["python"], pattern: /\bPBKDF2HMAC\s*\(|\bhashlib\.pbkdf2_hmac\s*\(\s*['"](sha\d{3})['"]|\bScrypt\s*\(|\bhashlib\.scrypt\s*\(|\bHKDF\s*\(|\bargon2\.|\bPasswordHasher\s*\(|\bbcrypt\.(?:hashpw|gensalt|kdf)\s*\(/, item: (m, line) => {
    const t = m[0];
    if (/PBKDF2HMAC|pbkdf2_hmac/.test(t)) return kdf("PBKDF2", m[1] ?? line.match(/hashes\.(SHA\d{3})\s*\(/)?.[1]);
    if (/[Ss]crypt/.test(t)) return kdf("scrypt");
    if (/HKDF/.test(t)) return kdf("HKDF", line.match(/hashes\.(SHA\d{3})\s*\(/)?.[1]);
    if (/bcrypt/.test(t)) return kdf("bcrypt");
    return kdf("Argon2");
  } },

  // ---------- JavaScript / TypeScript ----------
  { id: "js-hash", langs: ["js"], pattern: /\bcreateHash\s*\(\s*['"`](sha224|sha256|sha384|sha512|sha3-\d{3}|sha512-\d{3}|blake2[bs]\d*)['"`]/i, item: (m) => sha(m[1]) },
  { id: "js-hmac", langs: ["js"], pattern: /\bcreateHmac\s*\(\s*['"`](sha\d{3}|sha3-\d{3})['"`]/i, item: (m) => hmac(m[1]) },
  { id: "js-cipher", langs: ["js"], pattern: /\bcreate(?:Cipher|Decipher)iv\s*\(\s*['"`](aes[-_a-z0-9]*|chacha20-poly1305)['"`]/i, item: (m) => (/chacha/i.test(m[1]) ? CHACHA : aesName(m[1])) },
  { id: "js-subtle-digest", langs: ["js"], pattern: /\bdigest\s*\(\s*['"`](SHA-256|SHA-384|SHA-512)['"`]/, item: (m) => sha(m[1]) },
  { id: "js-webcrypto-aes", langs: ["js"], pattern: /name\s*:\s*['"`](AES-GCM|AES-CBC|AES-CTR|AES-KW)['"`]/, item: (m, line) => aes(NUM(line.match(/length\s*:\s*(128|192|256)\b/)?.[1]), m[1].slice(4).toLowerCase().replace("kw", "wrap")) },
  { id: "js-webcrypto-hmac", langs: ["js"], pattern: /name\s*:\s*['"`]HMAC['"`].*hash\s*:\s*(?:\{\s*name\s*:\s*)?['"`](SHA-256|SHA-384|SHA-512)['"`]/, item: (m) => hmac(m[1]) },
  { id: "js-kdf", langs: ["js"], pattern: /\bpbkdf2(?:Sync)?\s*\([^)]*['"`](sha\d{3})['"`]|\bscrypt(?:Sync)?\s*\(|\bhkdf(?:Sync)?\s*\(\s*['"`](sha\d{3})['"`]|\bargon2\.hash\s*\(|\bbcrypt\.(?:hash|genSalt)(?:Sync)?\s*\(|name\s*:\s*['"`](PBKDF2|HKDF)['"`]/, item: (m) => {
    const t = m[0];
    if (/pbkdf2|PBKDF2/.test(t)) return kdf("PBKDF2", m[1]);
    if (/hkdf|HKDF/.test(t)) return kdf("HKDF", m[2]);
    if (/scrypt/.test(t)) return kdf("scrypt");
    if (/bcrypt/.test(t)) return kdf("bcrypt");
    return kdf("Argon2");
  } },

  // ---------- Go ----------
  { id: "go-hash", langs: ["go"], pattern: /\b(sha256|sha512|sha3)\.(New|New224|New384|New512_224|New512_256|Sum256|Sum224|Sum384|Sum512|Sum512_256|New256)\s*\(/, item: (m) => {
    if (m[1] === "sha3") return sha(`sha3${m[2].match(/\d{3}/)?.[0] ?? "256"}`);
    const d = m[2].match(/\d{3}(?:_\d{3})?/)?.[0];
    if (m[1] === "sha256") return sha(d === "224" ? "sha224" : "sha256");
    return sha(d ? `sha${d.replace("_", "")}` : "sha512");
  } },
  { id: "go-hmac", langs: ["go"], pattern: /\bhmac\.New\s*\(\s*(sha256|sha512|sha3)\.(New\w*)/, item: (m) => hmac(m[1] === "sha3" ? "sha3256" : m[1] === "sha512" && /384/.test(m[2]) ? "sha384" : m[1]) },
  { id: "go-aes", langs: ["go"], pattern: /\baes\.NewCipher\s*\(/, item: () => aes(undefined, undefined) },
  { id: "go-gcm", langs: ["go"], pattern: /\bcipher\.NewGCM(?:WithNonceSize|WithTagSize|WithRandomNonce)?\s*\(/, item: () => aes(undefined, "gcm") },
  { id: "go-chacha", langs: ["go"], pattern: /\bchacha20poly1305\.NewX?\s*\(/, item: () => CHACHA },
  { id: "go-kdf", langs: ["go"], pattern: /\bpbkdf2\.Key\s*\([^)]*\b(sha256|sha512)\.New|\bscrypt\.Key\s*\(|\bargon2\.I?D?Key\s*\(|\bbcrypt\.GenerateFromPassword\s*\(|\bhkdf\.(?:New|Key|Extract)\s*\(\s*(sha256|sha512)\.New/, item: (m) => {
    const t = m[0];
    if (t.startsWith("pbkdf2")) return kdf("PBKDF2", m[1]);
    if (t.startsWith("hkdf")) return kdf("HKDF", m[2]);
    if (t.startsWith("scrypt")) return kdf("scrypt");
    if (t.startsWith("bcrypt")) return kdf("bcrypt");
    return kdf("Argon2");
  } },

  // ---------- Java / Kotlin ----------
  { id: "java-hash", langs: ["java"], pattern: /MessageDigest\.getInstance\s*\(\s*"(SHA-?224|SHA-?256|SHA-?384|SHA-?512|SHA3-\d{3})"/, item: (m) => sha(m[1]) },
  { id: "java-hmac", langs: ["java"], pattern: /Mac\.getInstance\s*\(\s*"Hmac(SHA\d{3}|SHA3-\d{3})"/, item: (m) => hmac(m[1]) },
  { id: "java-cipher", langs: ["java"], pattern: /Cipher\.getInstance\s*\(\s*"(AES(?:_(?:128|256))?\/(?:GCM|CBC|CTR|CCM)[^"]*|ChaCha20-Poly1305)"/, item: (m) => (/ChaCha/.test(m[1]) ? CHACHA : aes(NUM(m[1].match(/AES_(128|256)/)?.[1]), m[1].split("/")[1].toLowerCase())) },
  { id: "java-kdf", langs: ["java"], pattern: /SecretKeyFactory\.getInstance\s*\(\s*"PBKDF2WithHmac(SHA\d{3})"|\bBCrypt\.(?:hashpw|gensalt)\s*\(|\bArgon2PasswordEncoder\b|\bSCryptPasswordEncoder\b|\bBCryptPasswordEncoder\b/, item: (m) => (m[1] ? kdf("PBKDF2", m[1]) : /Argon2/.test(m[0]) ? kdf("Argon2") : /SCrypt/.test(m[0]) ? kdf("scrypt") : kdf("bcrypt")) },
  { id: "java-aes-keygen", langs: ["java"], pattern: /KeyGenerator\.getInstance\s*\(\s*"AES"/, item: () => aes(undefined, undefined) },
  { id: "java-aes-keysize", langs: ["java"], pattern: /\b\w*(?:keyGen|KeyGen|generator|Generator)\w*\.init\s*\(\s*(128|192|256)\s*\)/, item: (m) => aes(Number(m[1]), undefined) },

  // ---------- Post-quantum (any of the languages above, and config) ----------
  { id: "pqc-mlkem", langs: ["python", "js", "go", "java", "config"], pattern: /\b(?:ML[-_]?KEM|MLKEM)[-_]?(512|768|1024)\b|\bKyber(512|768|1024)\b/i, item: (m, line) => (/(?:X25519|SecP256r1|SecP384r1)[-_]?MLKEM/i.test(line) ? null : { algorithm: `ML-KEM-${m[1] ?? m[2]}`, family: "ML-KEM", primitive: "kem", functions: ["keygen", "encapsulate", "decapsulate"], nistQuantumLevel: { 512: 1, 768: 3, 1024: 5 }[Number(m[1] ?? m[2])] }) },
  { id: "pqc-hybrid", langs: ["python", "js", "go", "java", "config"], pattern: /\b(X25519|SecP256r1|SecP384r1)[-_]?MLKEM[-_]?(768|1024)\b/i, item: (m) => ({ algorithm: `${m[1]}MLKEM${m[2]}`, family: "ML-KEM", primitive: "kem", functions: ["keygen", "encapsulate", "decapsulate"], nistQuantumLevel: m[2] === "1024" ? 5 : 3, note: "Hybrid: classical and ML-KEM together." }) },
  { id: "pqc-mldsa", langs: ["python", "js", "go", "java", "config"], pattern: /\b(?:ML[-_]?DSA|MLDSA)[-_]?(44|65|87)\b|\bDilithium([235])\b/i, item: (m) => {
    const p = m[1] ?? { "2": "44", "3": "65", "5": "87" }[m[2]];
    return { algorithm: `ML-DSA-${p}`, family: "ML-DSA", primitive: "signature", functions: ["sign", "verify"], nistQuantumLevel: { "44": 2, "65": 3, "87": 5 }[p as "44"] };
  } },
  { id: "pqc-slhdsa", langs: ["python", "js", "go", "java", "config"], pattern: /\bSLH[-_]?DSA(?:[-_](SHA2|SHAKE)[-_](128|192|256)[sf])?\b|\bSPHINCS\+/i, item: (m) => ({ algorithm: m[2] ? `SLH-DSA-${m[1].toUpperCase()}-${m[2]}` : "SLH-DSA", family: "SLH-DSA", primitive: "signature", functions: ["sign", "verify"], ...(m[2] ? { nistQuantumLevel: { 128: 1, 192: 3, 256: 5 }[Number(m[2])] } : {}) }) },
];

const CODE_OR_CONFIG_LANGS = new Set<Lang>(["python", "js", "go", "java", "config"]);
const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*(?:\s|\/|$)|#(?![!\[]))/;

/** Every non-weak algorithm used in one file. Comments and documentation are ignored. */
export function findInventory(path: string, content: string): InventoryItem[] {
  const lang = langFor(path);
  if (!lang || !CODE_OR_CONFIG_LANGS.has(lang) || content.includes("\u0000")) return [];
  const rules = INVENTORY_RULES.filter((r) => r.langs.includes(lang));
  const out: InventoryItem[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i];
    if (text.length > 2000 || COMMENT_LINE.test(text)) continue;
    const seen = new Set<string>();
    for (const r of rules) {
      const m = text.match(r.pattern);
      if (!m) continue;
      const item = r.item(m, text);
      if (!item || seen.has(item.algorithm)) continue;
      // A rule that only knows the family (AES with no size) adds nothing next to a fuller one on the same line.
      if ([...seen].some((s) => s.startsWith(item.algorithm + "-"))) continue;
      seen.add(item.algorithm);
      out.push({ ...item, file: path, line: i + 1 });
    }
  }
  // Drop a bare "AES" or "AES-GCM" when the same line also named the full one.
  // Likewise a bare hash that is part of an HMAC or key derivation named on the same line.
  return out.filter(
    (x) =>
      !out.some(
        (y) =>
          y !== x &&
          y.line === x.line &&
          (y.algorithm.startsWith(x.algorithm + "-") || (x.primitive === "hash" && (y.primitive === "mac" || y.primitive === "kdf") && y.algorithm.endsWith("-" + short(x.algorithm)))),
      ),
  );
}

/** Counts by algorithm, for the text summary. */
export function inventoryCounts(items: InventoryItem[]): [string, number][] {
  const c = new Map<string, number>();
  for (const i of items) c.set(i.algorithm, (c.get(i.algorithm) ?? 0) + 1);
  return [...c.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}
