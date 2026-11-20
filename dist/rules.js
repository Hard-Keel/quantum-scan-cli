// Detection rules for quantum-vulnerable and already-weak cryptography.
// Each rule is a line-level regex scoped to a set of file languages.
const KEM_FIX = "Move key exchange to ML-KEM (FIPS 203), or hybrid X25519 + ML-KEM-768 for TLS.";
const SIG_FIX = "Move to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) signatures.";
const HASH_FIX = "Switch to SHA-256 or SHA-3, unless it is only a non-security checksum.";
const CIPHER_FIX = "Switch to AES-256-GCM.";
const TLS_FIX = "Require TLS 1.2 or later, ideally TLS 1.3.";
// Classification of every algorithm the rules can emit.
export const ALGORITHMS = {
    RSA: { primitive: "public-key-encryption", risk: "quantum-vulnerable", severity: "high", fix: `${KEM_FIX} For signatures, use ML-DSA (FIPS 204).` },
    "RSA signature": { primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: SIG_FIX },
    "RSA encryption": { primitive: "public-key-encryption", risk: "quantum-vulnerable", severity: "high", fix: KEM_FIX },
    ECDSA: { primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: SIG_FIX },
    EC: { primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: `${SIG_FIX} For key exchange, use ML-KEM (FIPS 203).` },
    ECDH: { primitive: "key-agreement", risk: "quantum-vulnerable", severity: "high", fix: KEM_FIX },
    DH: { primitive: "key-agreement", risk: "quantum-vulnerable", severity: "high", fix: KEM_FIX },
    X25519: { primitive: "key-agreement", risk: "quantum-vulnerable", severity: "high", fix: KEM_FIX },
    X448: { primitive: "key-agreement", risk: "quantum-vulnerable", severity: "high", fix: KEM_FIX },
    Ed25519: { primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: SIG_FIX },
    Ed448: { primitive: "signature", risk: "quantum-vulnerable", severity: "medium", fix: SIG_FIX },
    DSA: { primitive: "signature", risk: "weak-now", severity: "high", fix: `DSA is no longer approved. ${SIG_FIX}` },
    MD5: { primitive: "hash", risk: "weak-now", severity: "medium", fix: HASH_FIX },
    "SHA-1": { primitive: "hash", risk: "weak-now", severity: "medium", fix: HASH_FIX },
    DES: { primitive: "block-cipher", risk: "weak-now", severity: "high", fix: CIPHER_FIX },
    "3DES": { primitive: "block-cipher", risk: "weak-now", severity: "high", fix: CIPHER_FIX },
    RC4: { primitive: "stream-cipher", risk: "weak-now", severity: "high", fix: CIPHER_FIX },
    "ECB mode": { primitive: "block-cipher", risk: "weak-now", severity: "high", fix: CIPHER_FIX },
    "TLS 1.0/1.1": { primitive: "protocol", risk: "weak-now", severity: "high", fix: TLS_FIX },
    "Weak TLS ciphers": { primitive: "protocol", risk: "weak-now", severity: "high", fix: "Allow only AES-GCM and ChaCha20 cipher suites." },
};
// Maps a key-type word used by many APIs to an algorithm name.
function keyType(word) {
    const w = word.toLowerCase().replace(/[^a-z0-9]/g, "");
    if (w.startsWith("rsa"))
        return "RSA";
    if (w === "ec" || w === "ecdsa")
        return "ECDSA";
    if (w === "ecdh")
        return "ECDH";
    if (w === "dsa")
        return "DSA";
    if (w === "dh" || w === "diffiehellman")
        return "DH";
    if (w === "ed25519")
        return "Ed25519";
    if (w === "ed448")
        return "Ed448";
    if (w === "x25519")
        return "X25519";
    if (w === "x448")
        return "X448";
    if (w === "xdh")
        return "X25519";
    return null;
}
function hashOrCipher(word) {
    const w = word.toLowerCase();
    if (w === "md5")
        return "MD5";
    if (w === "sha1" || w === "sha-1")
        return "SHA-1";
    if (w.startsWith("des-ede") || w === "desede" || w.startsWith("des3") || w === "3des")
        return "3DES";
    if (w.startsWith("des"))
        return "DES";
    if (w.startsWith("rc4") || w === "arc4" || w === "arcfour")
        return "RC4";
    if (/ecb/.test(w))
        return "ECB mode";
    return null;
}
export const CRYPTO_RULES = [
    // ---------- Python ----------
    { id: "py-rsa-generate", langs: ["python"], pattern: /\brsa\.generate_private_key\s*\(|\bRSA\.generate\s*\(/, algorithm: "RSA", keySize: /(?:key_size\s*=\s*|RSA\.generate\s*\(\s*)(\d{3,5})/ },
    { id: "py-rsa-padding", langs: ["python"], pattern: /\bPKCS1_OAEP\b|\bpadding\.OAEP\s*\(/, algorithm: "RSA encryption" },
    { id: "py-rsa-sign", langs: ["python"], pattern: /\bpadding\.PSS\s*\(|\bpadding\.PKCS1v15\s*\(|\bpkcs1_15\.new\s*\(/, algorithm: "RSA signature" },
    { id: "py-ec-generate", langs: ["python"], pattern: /\bec\.generate_private_key\s*\(|\bECC\.generate\s*\(|\bSigningKey\.generate\s*\(/, algorithm: "ECDSA" },
    { id: "py-ecdh", langs: ["python"], pattern: /\bec\.ECDH\s*\(/, algorithm: "ECDH" },
    { id: "py-dsa", langs: ["python"], pattern: /\bdsa\.generate_private_key\s*\(|\bDSA\.generate\s*\(/, algorithm: "DSA" },
    { id: "py-dh", langs: ["python"], pattern: /\bdh\.generate_parameters\s*\(/, algorithm: "DH" },
    { id: "py-ed25519", langs: ["python"], pattern: /\bEd25519PrivateKey\b/, algorithm: "Ed25519" },
    { id: "py-x25519", langs: ["python"], pattern: /\bX25519PrivateKey\b/, algorithm: "X25519" },
    { id: "py-weak-hash", langs: ["python"], pattern: /\bhashlib\.(md5|sha1)\s*\(|\bhashes\.(MD5|SHA1)\s*\(|hashlib\.new\s*\(\s*['"](md5|sha1)['"]/, algorithm: (m) => hashOrCipher(m[1] ?? m[2] ?? m[3] ?? "") },
    { id: "py-weak-cipher", langs: ["python"], pattern: /\balgorithms\.(TripleDES|ARC4)\s*\(|\b(DES3|DES|ARC4)\.new\s*\(/, algorithm: (m) => hashOrCipher((m[1] ?? m[2] ?? "").replace("TripleDES", "3des")) },
    { id: "py-ecb", langs: ["python"], pattern: /\bmodes\.ECB\s*\(|\bMODE_ECB\b/, algorithm: "ECB mode" },
    // ---------- JavaScript / TypeScript ----------
    { id: "js-generate-keypair", langs: ["js"], pattern: /\bgenerateKeyPair(?:Sync)?\s*\(\s*['"`]([a-z0-9-]+)['"`]/i, algorithm: (m) => keyType(m[1]), keySize: /modulusLength\s*:\s*(\d{3,5})/ },
    { id: "js-ecdh", langs: ["js"], pattern: /\bcreateECDH\s*\(/, algorithm: "ECDH" },
    { id: "js-dh", langs: ["js"], pattern: /\bcreateDiffieHellman(?:Group)?\s*\(/, algorithm: "DH" },
    { id: "js-webcrypto", langs: ["js"], pattern: /name\s*:\s*['"`](RSA-OAEP|RSASSA-PKCS1-v1_5|RSA-PSS|ECDSA|ECDH|Ed25519|X25519)['"`]/, algorithm: (m) => ({ "RSA-OAEP": "RSA encryption", "RSASSA-PKCS1-v1_5": "RSA signature", "RSA-PSS": "RSA signature" }[m[1]] ?? keyType(m[1])), keySize: /modulusLength\s*:\s*(\d{3,5})/ },
    { id: "js-jwt-alg", langs: ["js"], pattern: /\balgorithms?\s*:\s*\[?\s*['"`]((?:RS|PS|ES)(?:256|384|512)|EdDSA)['"`]/, algorithm: (m) => (m[1].startsWith("ES") ? "ECDSA" : m[1] === "EdDSA" ? "Ed25519" : "RSA signature") },
    { id: "js-forge-rsa", langs: ["js"], pattern: /\bpki\.rsa\.generateKeyPair\s*\(/, algorithm: "RSA", keySize: /generateKeyPair\s*\(\s*(?:\{\s*bits\s*:\s*)?(\d{3,5})/ },
    { id: "js-weak-hash", langs: ["js"], pattern: /\bcreateHash\s*\(\s*['"`](md5|sha1)['"`]|\bcreateHmac\s*\(\s*['"`](md5|sha1)['"`]/i, algorithm: (m) => hashOrCipher(m[1] ?? m[2]) },
    { id: "js-weak-cipher", langs: ["js"], pattern: /\bcreateCipheriv\s*\(\s*['"`]((?:des[a-z0-9-]*)|(?:rc4[a-z0-9-]*)|(?:aes-\d+-ecb))['"`]/i, algorithm: (m) => hashOrCipher(m[1]) },
    // ---------- Go ----------
    { id: "go-rsa", langs: ["go"], pattern: /\brsa\.GenerateKey\s*\(/, algorithm: "RSA", keySize: /GenerateKey\s*\([^,]+,\s*(\d{3,5})/ },
    { id: "go-rsa-encrypt", langs: ["go"], pattern: /\brsa\.Encrypt(?:OAEP|PKCS1v15)\s*\(/, algorithm: "RSA encryption" },
    { id: "go-rsa-sign", langs: ["go"], pattern: /\brsa\.Sign(?:PSS|PKCS1v15)\s*\(/, algorithm: "RSA signature" },
    { id: "go-ecdsa", langs: ["go"], pattern: /\becdsa\.(?:GenerateKey|Sign|SignASN1)\s*\(/, algorithm: "ECDSA" },
    { id: "go-ecdh", langs: ["go"], pattern: /\becdh\.(P256|P384|P521|X25519)\s*\(/, algorithm: (m) => (m[1] === "X25519" ? "X25519" : "ECDH") },
    { id: "go-ed25519", langs: ["go"], pattern: /\bed25519\.(?:GenerateKey|Sign|NewKeyFromSeed)\s*\(/, algorithm: "Ed25519" },
    { id: "go-dsa", langs: ["go"], pattern: /\bdsa\.GenerateKey\s*\(/, algorithm: "DSA" },
    { id: "go-weak-hash", langs: ["go"], pattern: /\b(md5|sha1)\.(?:New|Sum)\s*\(/, algorithm: (m) => hashOrCipher(m[1]) },
    { id: "go-weak-cipher", langs: ["go"], pattern: /\bdes\.(NewCipher|NewTripleDESCipher)\s*\(|\brc4\.NewCipher\s*\(/, algorithm: (m) => (m[1] === "NewTripleDESCipher" ? "3DES" : m[1] ? "DES" : "RC4") },
    { id: "go-tls-old", langs: ["go"], pattern: /\bMinVersion\s*:\s*tls\.VersionTLS1[01]\b/, algorithm: "TLS 1.0/1.1" },
    // ---------- Java / Kotlin ----------
    { id: "java-keypairgen", langs: ["java"], pattern: /KeyPairGenerator\.getInstance\s*\(\s*"([A-Za-z0-9]+)"/, algorithm: (m) => keyType(m[1]) },
    { id: "java-keyagreement", langs: ["java"], pattern: /KeyAgreement\.getInstance\s*\(\s*"([A-Za-z0-9]+)"/, algorithm: (m) => (keyType(m[1]) === "ECDSA" ? "ECDH" : keyType(m[1])) },
    { id: "java-signature", langs: ["java"], pattern: /Signature\.getInstance\s*\(\s*"[A-Za-z0-9]*with(RSA|ECDSA|DSA)[A-Za-z0-9/]*"/, algorithm: (m) => (m[1] === "RSA" ? "RSA signature" : m[1]) },
    { id: "java-signature-ed", langs: ["java"], pattern: /Signature\.getInstance\s*\(\s*"(Ed25519|Ed448|EdDSA)"/, algorithm: (m) => (m[1] === "Ed448" ? "Ed448" : "Ed25519") },
    { id: "java-cipher-rsa", langs: ["java"], pattern: /Cipher\.getInstance\s*\(\s*"RSA[^"]*"/, algorithm: "RSA encryption" },
    { id: "java-weak-cipher", langs: ["java"], pattern: /Cipher\.getInstance\s*\(\s*"((?:DESede|DES|RC4|ARCFOUR)[^"]*|AES\/ECB[^"]*|AES")/, algorithm: (m) => (m[1] === 'AES"' || m[1] === "AES" ? "ECB mode" : hashOrCipher(m[1].split("/")[0]) ?? hashOrCipher(m[1])) },
    { id: "java-weak-hash", langs: ["java"], pattern: /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"/, algorithm: (m) => hashOrCipher(m[1]) },
    { id: "java-keysize", langs: ["java"], pattern: /\.initialize\s*\(\s*(\d{3,4})\s*[,)]/, algorithm: (m) => (Number(m[1]) < 2048 && Number(m[1]) >= 512 ? "RSA" : null), keySize: /\.initialize\s*\(\s*(\d{3,4})/ },
    // ---------- Config, keys, certificates (any file) ----------
    { id: "ssh-public-key", langs: ["any"], pattern: /\b(ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|ssh-ed25519) AAAA[0-9A-Za-z+/]{20,}/, algorithm: (m) => ({ "ssh-rsa": "RSA signature", "ssh-dss": "DSA", "ssh-ed25519": "Ed25519" }[m[1]] ?? "ECDSA") },
];
export function langFor(path) {
    const p = path.toLowerCase();
    if (/\.(py|pyw)$/.test(p))
        return "python";
    if (/\.(js|mjs|cjs|jsx|ts|mts|cts|tsx)$/.test(p))
        return "js";
    if (/\.go$/.test(p))
        return "go";
    if (/\.(java|kt|kts|scala)$/.test(p))
        return "java";
    if (/(\.conf|\.cfg|\.ini|\.ya?ml|\.toml|\.tf|\.json|\.env|nginx[^/]*|httpd[^/]*|dockerfile[^/]*|containerfile[^/]*|\.hcl|\.tfvars|\.template|\.properties)$/.test(p))
        return "config";
    if (/\.(pem|key|crt|cer|pub|txt|sh|md)$/.test(p) || /(^|\/)(authorized_keys|known_hosts|id_[a-z0-9]+)$/.test(p))
        return "any";
    return null;
}
