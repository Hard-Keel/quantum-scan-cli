// CycloneDX 1.6 Cryptographic Bill of Materials (CBOM): every encryption method found, where it was
// found, and how much protection it gives against a quantum attacker.
import { randomUUID } from "node:crypto";
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
/** Object identifiers for the algorithms the scanner names, where one OID covers the family. */
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
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
};
/** What the scanner can tell about a protocol finding. Anything not listed is a problem with a setting, not an asset. */
function protocolOf(algorithm) {
    if (algorithm === "TLS 1.0/1.1")
        return { type: "tls", version: "1.0/1.1" };
    if (/^(Weak TLS ciphers|Static RSA key exchange|TLS key exchange)$/.test(algorithm))
        return { type: "tls" };
    if (/^SSH\b|SSH key exchange$/.test(algorithm))
        return { type: "ssh" };
    return null;
}
/** NIST quantum security category for the post-quantum methods, from the parameter set where the code names it. */
function pqcLevel(name) {
    const m = name.match(/(?:ML-KEM|Kyber)[-_]?(512|768|1024)|ML-DSA[-_]?(44|65|87)|FN-DSA[-_]?(512|1024)|Falcon[-_]?(512|1024)/i);
    if (!m)
        return undefined;
    const n = m[1] ?? m[2] ?? m[3] ?? m[4];
    return { "512": 1, "768": 3, "1024": 5, "44": 2, "65": 3, "87": 5 }[n];
}
const ref = (name) => `crypto:${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
const occurrence = (location, line) => (line && line >= 1 ? { location, line } : { location });
export function buildCbom(findings, opts) {
    const byAlg = new Map();
    for (const f of findings) {
        if (f.kind !== "crypto")
            continue;
        // A problem with a certificate (expired, wrong name) is not an encryption method, so it stays in the report only.
        if (f.primitive === "protocol" && !protocolOf(f.algorithm))
            continue;
        const key = f.keySize ? `${f.algorithm}-${f.keySize}` : f.algorithm;
        byAlg.set(key, [...(byAlg.get(key) ?? []), f]);
    }
    const components = [...byAlg.entries()].map(([name, fs]) => {
        const first = fs[0];
        const proto = first.primitive === "protocol" ? protocolOf(first.algorithm) : null;
        const oid = OID[first.algorithm];
        const cryptoProperties = proto
            ? { assetType: "protocol", protocolProperties: proto }
            : {
                assetType: "algorithm",
                algorithmProperties: {
                    primitive: CDX_PRIMITIVE[first.primitive],
                    ...(first.keySize ? { parameterSetIdentifier: String(first.keySize) } : {}),
                    // 0: no protection against a quantum attacker on NIST's category scale.
                    nistQuantumSecurityLevel: 0,
                },
                ...(oid ? { oid } : {}),
            };
        return {
            type: "cryptographic-asset",
            "bom-ref": ref(name),
            name,
            cryptoProperties,
            properties: [
                { name: "hardkeel:risk", value: first.risk },
                { name: "hardkeel:severity", value: first.severity },
                { name: "hardkeel:occurrences", value: String(fs.length) },
                { name: "hardkeel:fix", value: first.fix },
            ],
            evidence: { occurrences: fs.map((f) => occurrence(f.file, f.line)) },
        };
    });
    const safe = new Map();
    for (const q of opts.quantumSafe ?? [])
        safe.set(q.algorithm, [...(safe.get(q.algorithm) ?? []), q]);
    for (const [name, qs] of safe) {
        const level = pqcLevel(name);
        const oid = OID[name];
        components.push({
            type: "cryptographic-asset",
            "bom-ref": ref(name),
            name,
            cryptoProperties: {
                assetType: "algorithm",
                algorithmProperties: {
                    primitive: qs[0].use === "signature" ? "signature" : /hybrid/i.test(name) ? "combiner" : "kem",
                    ...(level !== undefined ? { nistQuantumSecurityLevel: level } : {}),
                },
                ...(oid ? { oid } : {}),
            },
            properties: [
                { name: "hardkeel:risk", value: "quantum-safe" },
                { name: "hardkeel:occurrences", value: String(qs.length) },
            ],
            evidence: { occurrences: qs.map((q) => occurrence(q.location, q.line)) },
        });
    }
    const app = "application";
    return {
        $schema: "http://cyclonedx.org/schema/bom-1.6.schema.json",
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        serialNumber: opts.serialNumber ?? `urn:uuid:${randomUUID()}`,
        version: 1,
        metadata: {
            timestamp: opts.timestamp ?? new Date().toISOString(),
            tools: { components: [{ type: "application", author: "Hard Keel", name: "Hard Keel Quantum Scan", version: opts.toolVersion }] },
            component: { type: "application", "bom-ref": app, name: opts.repo, ...(opts.ref ? { version: opts.ref } : {}) },
        },
        components,
        dependencies: [{ ref: app, dependsOn: components.map((c) => c["bom-ref"]) }],
    };
}
