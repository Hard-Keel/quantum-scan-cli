// CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) from crypto findings.
import { randomUUID } from "node:crypto";
/** What each kind of finding is used for, as CycloneDX names it. */
const FUNCTIONS = {
    "key-agreement": ["keygen"],
    "public-key-encryption": ["encrypt", "decrypt"],
    signature: ["sign", "verify"],
    hash: ["digest"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
};
/** Object identifiers for the algorithms named here, where one OID covers the family. */
const OID = {
    RSA: "1.2.840.113549.1.1.1",
    "RSA signature": "1.2.840.113549.1.1.1",
    "RSA encryption": "1.2.840.113549.1.1.1",
    EC: "1.2.840.10045.2.1",
    DH: "1.2.840.10046.2.1",
    X25519: "1.3.101.110",
    X448: "1.3.101.111",
    Ed25519: "1.3.101.112",
    Ed448: "1.3.101.113",
    DSA: "1.2.840.10040.4.1",
    MD5: "1.2.840.113549.2.5",
    "SHA-1": "1.3.14.3.2.26",
    DES: "1.3.14.3.2.7",
    "3DES": "1.2.840.113549.3.7",
    RC4: "1.2.840.113549.3.4",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "SHA3-384": "2.16.840.1.101.3.4.2.9",
    "SHA3-512": "2.16.840.1.101.3.4.2.10",
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
};
const oid = (name) => (OID[name] ? { oid: OID[name] } : {});
/**
 * Which protocol a protocol finding is about. A problem with a certificate or a setting (an expired
 * certificate, an open port) isn't an encryption method, so it returns null and stays out of the inventory.
 */
function protocolOf(algorithm) {
    if (algorithm === "TLS 1.0/1.1")
        return { type: "tls", version: "1.0/1.1" };
    if (/^(Weak TLS ciphers|Static RSA key exchange|TLS key exchange)$/.test(algorithm))
        return { type: "tls" };
    if (/^SSH\b|SSH key exchange$/.test(algorithm))
        return { type: "ssh" };
    return null;
}
const CDX_MODES = new Set(["cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"]);
const CDX_PRIMITIVE = {
    "key-agreement": "key-agree",
    "public-key-encryption": "pke",
    signature: "signature",
    hash: "hash",
    "block-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    protocol: "other",
    credential: "other",
    setting: "other",
};
/**
 * The CBOM: one component per algorithm (and key size). Findings are the ones to fix; inventory is
 * everything else the code uses (AES, SHA-2, HMAC, key derivation, post-quantum), so the list is complete.
 */
export function buildCbom(findings, opts, inventory = []) {
    const crypto = findings.filter((f) => f.kind === "crypto" && (f.primitive !== "protocol" || protocolOf(f.algorithm)));
    const byAlg = new Map();
    for (const f of crypto) {
        const key = f.keySize ? `${f.algorithm}-${f.keySize}` : f.algorithm;
        byAlg.set(key, [...(byAlg.get(key) ?? []), f]);
    }
    const components = [...byAlg.entries()].map(([name, fs]) => {
        const first = fs[0];
        const isProtocol = first.primitive === "protocol";
        const cryptoProperties = isProtocol
            ? { assetType: "protocol", protocolProperties: protocolOf(first.algorithm) }
            : {
                assetType: "algorithm",
                algorithmProperties: {
                    primitive: CDX_PRIMITIVE[first.primitive],
                    // 0 = no security against a quantum attacker (NIST category scale).
                    nistQuantumSecurityLevel: 0,
                    ...(first.keySize ? { parameterSetIdentifier: String(first.keySize) } : {}),
                    ...(FUNCTIONS[first.primitive] ? { cryptoFunctions: FUNCTIONS[first.primitive] } : {}),
                },
                ...oid(first.algorithm),
            };
        return {
            type: "cryptographic-asset",
            "bom-ref": `crypto:${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
            name,
            cryptoProperties,
            properties: [
                { name: "hardkeel:risk", value: first.risk },
                { name: "hardkeel:occurrences", value: String(fs.length) },
            ],
            evidence: {
                // CycloneDX lines start at 1; a place with no line (a device, a website) gives its location alone.
                occurrences: fs.map((f) => ({ location: f.file, ...(f.line > 0 ? { line: f.line } : {}) })),
            },
        };
    });
    const taken = new Set(components.map((c) => c["bom-ref"]));
    const byInv = new Map();
    for (const i of inventory)
        byInv.set(i.algorithm, [...(byInv.get(i.algorithm) ?? []), i]);
    for (const [name, items] of byInv) {
        const first = items[0];
        const ref = `crypto:${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
        if (taken.has(ref))
            continue;
        components.push({
            type: "cryptographic-asset",
            "bom-ref": ref,
            name,
            cryptoProperties: {
                assetType: "algorithm",
                algorithmProperties: {
                    primitive: first.primitive,
                    ...(first.nistQuantumLevel !== undefined ? { nistQuantumSecurityLevel: first.nistQuantumLevel } : {}),
                    ...(first.keySize ? { parameterSetIdentifier: String(first.keySize) } : {}),
                    ...(first.mode ? { mode: CDX_MODES.has(first.mode) ? first.mode : "other" } : {}),
                    cryptoFunctions: first.functions,
                },
                ...oid(name),
            },
            properties: [
                { name: "hardkeel:risk", value: first.family.startsWith("ML-") || first.family === "SLH-DSA" ? "quantum-safe" : "ok" },
                { name: "hardkeel:occurrences", value: String(items.length) },
                ...(first.note ? [{ name: "hardkeel:note", value: first.note }] : []),
            ],
            evidence: { occurrences: items.map((i) => ({ location: i.file, ...(i.line > 0 ? { line: i.line } : {}) })) },
        });
    }
    // A local folder is named by its last part, so the inventory doesn't carry the path on this computer.
    const name = /^([a-zA-Z]:)?[\\/]/.test(opts.repo) ? opts.repo.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || opts.repo : opts.repo;
    return {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        // A fresh id for each inventory, so tools that track BOMs can tell two runs apart.
        serialNumber: `urn:uuid:${randomUUID()}`,
        version: 1,
        metadata: {
            timestamp: opts.timestamp ?? new Date().toISOString(),
            tools: { components: [{ type: "application", name: "Hard Keel Quantum Scan", version: opts.toolVersion }] },
            component: { type: "application", "bom-ref": "subject", name, ...(opts.ref ? { version: opts.ref } : {}) },
        },
        components,
        // What was checked uses every algorithm listed.
        dependencies: [{ ref: "subject", dependsOn: components.map((c) => c["bom-ref"]) }],
    };
}
