// CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) from crypto findings.

import type { Finding, Primitive } from "./types.ts";

const CDX_PRIMITIVE: Record<Primitive, string> = {
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

export interface CbomOptions {
  repo: string; // owner/name
  ref?: string; // commit sha
  toolVersion: string;
  timestamp?: string;
}

export function buildCbom(findings: Finding[], opts: CbomOptions) {
  const crypto = findings.filter((f) => f.kind === "crypto");
  const byAlg = new Map<string, Finding[]>();
  for (const f of crypto) {
    const key = f.keySize ? `${f.algorithm}-${f.keySize}` : f.algorithm;
    byAlg.set(key, [...(byAlg.get(key) ?? []), f]);
  }

  const components = [...byAlg.entries()].map(([name, fs]) => {
    const first = fs[0];
    const isProtocol = first.primitive === "protocol";
    const cryptoProperties = isProtocol
      ? { assetType: "protocol", protocolProperties: { type: "tls", version: "1.0/1.1" } }
      : {
          assetType: "algorithm",
          algorithmProperties: {
            primitive: CDX_PRIMITIVE[first.primitive],
            // 0 = no security against a quantum attacker (NIST category scale).
            nistQuantumSecurityLevel: 0,
            ...(first.keySize ? { parameterSetIdentifier: String(first.keySize) } : {}),
          },
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
        occurrences: fs.map((f) => ({ location: f.file, line: f.line })),
      },
    };
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      timestamp: opts.timestamp ?? new Date().toISOString(),
      tools: { components: [{ type: "application", name: "Hard Keel Quantum Scan", version: opts.toolVersion }] },
      component: { type: "application", name: opts.repo, ...(opts.ref ? { version: opts.ref } : {}) },
    },
    components,
  };
}
