// Detects post-quantum encryption already in use (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, hybrids).
// Used only by the readiness score, to credit migration work. Never reported as a problem.
// Order matters: the first rule that matches a line wins, so hybrids come before plain ML-KEM.
const PQC_RULES = [
    { pattern: /\b(?:X25519|SecP256r1|SecP384r1)[-_]?MLKEM[-_]?(?:768|1024)\b|\bX25519Kyber768\b/i, algorithm: "Hybrid ML-KEM key exchange", use: "key-establishment" },
    { pattern: /\b(?:ML[-_]?KEM|MLKEM)(?:[-_]?(?:512|768|1024))?\b|\bcrypto\/mlkem\b/i, algorithm: "ML-KEM", use: "key-establishment" },
    { pattern: /\bKyber(?:512|768|1024)\b/, algorithm: "ML-KEM", use: "key-establishment" },
    { pattern: /\b(?:ML[-_]?DSA|MLDSA)(?:[-_]?(?:44|65|87))?\b/i, algorithm: "ML-DSA", use: "signature" },
    { pattern: /\bDilithium[2-5]\b/, algorithm: "ML-DSA", use: "signature" },
    { pattern: /\bSLH[-_]?DSA\b|\bSPHINCS\+/i, algorithm: "SLH-DSA", use: "signature" },
    { pattern: /\bFN[-_]?DSA\b|\bFalcon[-_]?(?:512|1024)\b/, algorithm: "FN-DSA", use: "signature" },
];
const CODE_OR_CONFIG = /\.(py|pyw|js|mjs|cjs|jsx|ts|mts|cts|tsx|go|java|kt|kts|scala|rs|c|cc|cpp|h|hpp|cs|rb|php|swift|conf|cfg|ini|ya?ml|toml|tf|hcl|json|properties)$|(^|\/)(nginx|httpd)[^/]*$/i;
/** Post-quantum algorithms used in one source or config file. Documentation is ignored. */
export function findPqc(path, content) {
    if (!CODE_OR_CONFIG.test(path) || content.includes("\u0000"))
        return [];
    const out = [];
    const lines = content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const text = lines[i];
        if (text.length > 2000)
            continue;
        for (const r of PQC_RULES) {
            if (r.pattern.test(text)) {
                out.push({ algorithm: r.algorithm, use: r.use, file: path, line: i + 1 });
                break;
            }
        }
    }
    return out;
}
