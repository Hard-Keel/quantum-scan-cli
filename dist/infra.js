// Infrastructure config checks: Terraform/OpenTofu, CloudFormation, Kubernetes, Dockerfiles,
// and nginx/Apache/HAProxy configs. Finds weak TLS, non-quantum-safe key settings, encryption
// turned off, storage or ports open to the internet, and secrets written into config.
import { ALGORITHMS } from "./rules.js";
import { mask } from "./secrets.js";
/**
 * Whether a pull request should read the whole file, not just the diff, for infrastructure checks.
 * Settings like a security group's direction or ports sit a few lines away from the line that changed.
 */
export function wantsFullFile(path, patch) {
    const p = path.toLowerCase();
    if (/(\.tf|\.tfvars|\.hcl|\.template)$/.test(p))
        return true;
    if (/(^|\/)(dockerfile|containerfile)[^/]*$|\.dockerfile$/.test(p))
        return true;
    if (/\.ya?ml$|\.json$/.test(p))
        return /AWS::|AWSTemplateFormatVersion|SecurityGroup|apiVersion:|kind:\s*Secret|cert-manager/.test(patch);
    return false;
}
export function infraType(path, lines) {
    const p = path.toLowerCase();
    const name = p.split("/").pop() ?? p;
    if (/\.(tf|tfvars|hcl)$/.test(p))
        return "terraform";
    if (/^(dockerfile|containerfile)([.-].*)?$/.test(name) || /\.(dockerfile|containerfile)$/.test(name))
        return "docker";
    if (/\.(ya?ml|json|template)$/.test(p)) {
        if (lines.some((l) => /AWSTemplateFormatVersion|["']?Type["']?\s*:\s*["']?AWS::/.test(l.text)))
            return "cloudformation";
        return /\.json$/.test(p) ? "json" : "yaml";
    }
    if (/\.(conf|cfg)$/.test(p) || /(^|\/)(nginx|apache2?|httpd|haproxy)[^/]*$/.test(p) || name === ".htaccess" || /(^|\/)sites-(available|enabled)\//.test(p))
        return "webserver";
    if (/\.(sh|bash)$/.test(p))
        return "shell";
    if (/\.(ini|toml|properties|env|cnf)$/.test(p))
        return "config";
    return null;
}
// ---------- shared helpers ----------
const SENSITIVE_PORTS = [21, 22, 23, 445, 1433, 1521, 2375, 2376, 2379, 3306, 3389, 5432, 5601, 5900, 5984, 6379, 7001, 8020, 9042, 9092, 9200, 9300, 11211, 27017];
const PORT_NAMES = { 22: "SSH", 3389: "remote desktop", 3306: "MySQL", 5432: "PostgreSQL", 1433: "SQL Server", 1521: "Oracle", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 2375: "Docker", 2376: "Docker", 2379: "etcd", 23: "Telnet", 21: "FTP", 445: "SMB", 5900: "VNC", 11211: "Memcached", 5601: "Kibana" };
const PLACEHOLDER = /(example|sample|dummy|changeme|change_me|placeholder|your[_-]|xxxx|\*\*\*\*|<[^>]+>|\$\{|\{\{|redacted|test|password|secret|var\.|local\.|module\.|data\.|todo|replace)/i;
function trim(t) {
    const s = t.trim();
    return s.length > 160 ? `${s.slice(0, 157)}...` : s;
}
/** Ports covered by a range, by name. Null when nothing sensitive is in range. */
function exposedPorts(from, to, allProtocols) {
    if (allProtocols || (from === 0 && (to === 65535 || to === 0)))
        return "all ports";
    if (from === null || to === null || Number.isNaN(from) || Number.isNaN(to))
        return null;
    if (to - from >= 1000)
        return "a wide port range";
    const hit = SENSITIVE_PORTS.filter((p) => p >= from && p <= to);
    if (!hit.length)
        return null;
    const names = hit.map((p) => (PORT_NAMES[p] ? `${PORT_NAMES[p]} (${p})` : `port ${p}`));
    return names.slice(0, 2).join(" and ");
}
function portRange(s) {
    const t = s.trim().replace(/["']/g, "");
    if (t === "*" || t === "Any")
        return [0, 65535];
    const m = t.match(/^(\d{1,5})(?:\s*-\s*(\d{1,5}))?$/);
    return m ? [Number(m[1]), Number(m[2] ?? m[1])] : null;
}
/** Innermost { } block around lines[idx], for HCL. Returns line indexes, inclusive. */
function hclBlock(lines, idx) {
    let depth = 0;
    let start = -1;
    outer: for (let j = idx - 1; j >= 0; j--) {
        const t = stripStrings(lines[j].text);
        for (let k = t.length - 1; k >= 0; k--) {
            if (t[k] === "}")
                depth++;
            else if (t[k] === "{") {
                if (depth === 0) {
                    start = j;
                    break outer;
                }
                depth--;
            }
        }
    }
    if (start < 0)
        return null;
    depth = 0;
    for (let j = start; j < lines.length; j++) {
        for (const ch of stripStrings(lines[j].text)) {
            if (ch === "{")
                depth++;
            else if (ch === "}") {
                depth--;
                if (depth === 0)
                    return { start, end: j };
            }
        }
    }
    return { start, end: lines.length - 1 };
}
/** The resource-level block (first line starts with resource/data/module) around lines[idx]. */
function hclResource(lines, idx) {
    let b = hclBlock(lines, idx);
    while (b && !/^\s*(resource|data|module)\b/.test(lines[b.start].text)) {
        b = hclBlock(lines, b.start);
    }
    return b;
}
function stripStrings(s) {
    return s.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/#.*$|\/\/.*$/, "");
}
function textOf(lines, b) {
    return lines.slice(b.start, b.end + 1).map((l) => l.text).join("\n");
}
function hclValue(block, key) {
    const m = block.match(new RegExp(`^\\s*${key}\\s*=\\s*("?)([^"\\n]*)\\1\\s*(?:#.*)?$`, "m"));
    return m ? m[2].trim() : null;
}
// ---------- TLS versions and ciphers ----------
/** TLS minor version named in a value like "TLSv1.2_2021", "TLS1_0", "Policy-Min-TLS-1-0-2019-07". */
export function tlsMinVersionIsWeak(value) {
    const v = value.trim();
    if (/^SSLv?[23]$/i.test(v))
        return true;
    if (/^ELBSecurityPolicy-20(1[56])-\d\d$/i.test(v))
        return true; // old ALB defaults that allow TLS 1.0
    const m = v.match(/TLS[-_ v]?1(?:[-._]?([0-3])(?!\d))?/i);
    if (m)
        return Number(m[1] ?? 0) < 2;
    if (/^1[._]([01])$/.test(v))
        return true;
    return false;
}
const MIN_TLS_KEY = /(?:^|[\s"'{,.])(min_?tls_?version|minimum_tls_version|tls_min_version|min_tls|minimum_protocol_version|MinimumProtocolVersion|MinTlsVersion|MinimumTlsVersion|minimalTlsVersion|minTlsVersion|ssl_minimum_version|tls_security_policy|TLSSecurityPolicy|ssl_policy|SslPolicy|security_policy|SecurityPolicy|ssl-min-ver)["']?\s*[:=\s]\s*["']?([A-Za-z0-9._-]+)/i;
const PROTOCOL_LIST = /(?:^|[\s"'/])(ssl_protocols|SSLProtocol|ssl-protocols)["']?\s*[:=\s]\s*["']?([^;"'#\n]+)/i;
const CIPHER_LIST = /(?:^|[\s"'/])(ssl_ciphers|SSLCipherSuite|ssl-default-bind-ciphers|ssl-default-server-ciphers|ssl-ciphers)["']?\s*[:=\s]\s*["']?([^;"'#\n]+)/i;
function weakProtocols(directive, list) {
    const tokens = list.split(/[\s,]+/).filter(Boolean);
    const on = new Set();
    const norm = (t) => t.replace(/^[+-]/, "").replace(/^TLSv1\.0$/i, "TLSv1").toUpperCase();
    for (const t of tokens) {
        if (/^all$/i.test(t.replace(/^\+/, "")))
            ["SSLV3", "TLSV1", "TLSV1.1", "TLSV1.2", "TLSV1.3"].forEach((x) => on.add(x));
        else if (t.startsWith("-") || t.startsWith("!"))
            on.delete(norm(t.slice(1)));
        else
            on.add(norm(t));
    }
    if (/SSLProtocol/i.test(directive) && !tokens.length)
        return [];
    return [...on].filter((t) => /^(SSLV2|SSLV3|TLSV1|TLSV1\.1)$/.test(t));
}
function weakCiphers(list) {
    const out = [];
    for (const raw of list.split(/[:\s,]+/)) {
        if (!raw || /^[!-]/.test(raw))
            continue;
        const m = raw.match(/(?:^|[-_+])(RC4|3DES|DES|DES-CBC3|CBC3|MD5|NULL|EXPORT|EXP|aNULL|eNULL|ADH|AECDH)(?:[-_+]|$)/i);
        if (m)
            out.push(raw);
    }
    return out;
}
const FIX = {
    atRest: "Turn on encryption at rest, ideally with a customer-managed key.",
    transit: "Require HTTPS or TLS for every connection.",
    verify: "Keep certificate checks on. Add the right CA certificate instead of skipping verification.",
    publicStore: "Block public access. Share files through signed links or a CDN with access control.",
    publicDb: "Keep the database off the public internet and reach it through a private network.",
    openPort: "Limit the source to known addresses or a VPN, or put it behind a private network.",
    ciphers: "Allow only AES-GCM and ChaCha20 cipher suites.",
    tls: "Require TLS 1.2 or later, ideally TLS 1.3.",
    secret: "Move it to a secret store and reference it from there. Deleting it from the code leaves it in git history.",
};
function cryptoHit(line, algorithm, keySize) {
    const info = ALGORITHMS[algorithm];
    if (!info)
        return null;
    let { risk, severity, fix } = info;
    let title = `${algorithm} is ${risk === "weak-now" ? "weak today" : "breakable by quantum computers"}`;
    if (keySize !== undefined && algorithm.startsWith("RSA") && keySize < 2048) {
        risk = "weak-now";
        severity = "high";
        title = `RSA-${keySize} is weak today and breakable by quantum computers`;
        fix = "Use 3072-bit keys or larger now, then plan the move to post-quantum methods.";
    }
    return { line, kind: "crypto", algorithm, risk, severity, primitive: info.primitive, title, fix, keySize };
}
function exposed(line, algorithm, title, fix, severity = "high") {
    return { line, kind: "config", algorithm, risk: "exposed", severity, primitive: "setting", title, fix };
}
function secretHit(line, value, name = "Hardcoded secret") {
    return {
        line,
        kind: "secret",
        algorithm: name,
        risk: "secret",
        severity: "critical",
        primitive: "credential",
        title: `${name} committed to the repository`,
        fix: FIX.secret,
        snippet: trim(line.text.split(value).join(mask(value))),
    };
}
function keyAlgorithm(word) {
    const w = word.toUpperCase();
    if (/^RSA_(SIGN)/.test(w))
        return "RSA signature";
    if (/^RSA_(DECRYPT)/.test(w))
        return "RSA encryption";
    if (/^RSA/.test(w))
        return "RSA";
    if (/^(EC|ECC|ECDSA|EC_SIGN|P-?\d{3})/.test(w))
        return "ECDSA";
    if (/^ED25519$/.test(w))
        return "Ed25519";
    if (/^DSA$/.test(w))
        return "DSA";
    return null;
}
function rsaBitsOf(word) {
    const m = word.match(/RSA[_A-Z]*?_(\d{4})/i);
    return m ? Number(m[1]) : undefined;
}
export function scanInfra(path, lines) {
    const type = infraType(path, lines);
    const hits = [];
    const add = (h) => h && hits.push(h);
    // Kubernetes Secret manifests: track the current YAML document's kind.
    let docKind = "";
    let inSecretData = -1;
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const t = line.text;
        if (t.length > 2000)
            continue;
        if (/^\s*(#|\/\/)/.test(t)) {
            continue;
        }
        // --- TLS settings (any infra or config file) ---
        if (type) {
            const mm = t.match(MIN_TLS_KEY);
            if (mm && tlsMinVersionIsWeak(mm[2]) && !(/^(ssl_policy|SslPolicy|security_policy|SecurityPolicy)$/i.test(mm[1]) && !/^(ELBSecurityPolicy|Policy-Min|TLS)/i.test(mm[2]))) {
                add(cryptoHit(line, "TLS 1.0/1.1"));
            }
            const pl = t.match(PROTOCOL_LIST);
            if (pl && weakProtocols(pl[1], pl[2]).length)
                add(cryptoHit(line, "TLS 1.0/1.1"));
            const cl = t.match(CIPHER_LIST);
            if (cl && weakCiphers(cl[2]).length)
                add(cryptoHit(line, "Weak TLS ciphers"));
        }
        // --- Commands that run in containers or provisioning scripts ---
        if (type === "docker" || type === "shell" || type === "yaml") {
            if (/\bcurl\s(?:[^|;&\n]*\s)?(-[a-zA-Z]*k[a-zA-Z]*|--insecure)(\s|$)/.test(t) || /\bwget\s[^\n]*--no-check-certificate/.test(t) || /\bnpm\s+config\s+set\s+strict-ssl\s+false/.test(t) || /http\.sslVerify\s+false/i.test(t)) {
                add(exposed(line, "TLS verification off", "Certificate checks turned off", FIX.verify, "medium"));
            }
            const kg = t.match(/\bssh-keygen\b[^\n]*\s-t\s+(rsa|dsa|ecdsa|ed25519)\b/i);
            if (kg) {
                const b = t.match(/\s-b\s+(\d{3,5})\b/);
                add(cryptoHit(line, kg[1].toLowerCase() === "ed25519" ? "Ed25519" : kg[1].toLowerCase() === "dsa" ? "DSA" : kg[1].toLowerCase() === "ecdsa" ? "ECDSA" : "RSA", b ? Number(b[1]) : undefined));
            }
            const os = t.match(/\bopenssl\s+(genrsa|req\b[^\n]*-newkey\s+(rsa|ec))/i);
            if (os) {
                const b = t.match(/(?:genrsa\b[^\n]*?\s|rsa:)(\d{3,5})\b/);
                add(cryptoHit(line, os[2]?.toLowerCase() === "ec" ? "ECDSA" : "RSA", b ? Number(b[1]) : undefined));
            }
        }
        if (type === "docker") {
            const env = t.match(/^\s*(?:ENV|ARG)\s+([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)(?:=|\s+)["']?([^\s"'$]{8,})["']?/i);
            if (env && !PLACEHOLDER.test(env[2]) && !/_(FILE|PATH|URL|NAME|URI|DIR|HOME)$/i.test(env[1]) && !/^(\/|\.{1,2}\/|~\/)/.test(env[2]))
                add(secretHit(line, env[2]));
        }
        // --- Kubernetes ---
        if (type === "yaml") {
            if (/^---/.test(t)) {
                docKind = "";
                inSecretData = -1;
            }
            const k = t.match(/^kind:\s*["']?(\w+)/);
            if (k)
                docKind = k[1];
            if (/insecure-skip-tls-verify:\s*true\b/.test(t))
                add(exposed(line, "TLS verification off", "Certificate checks turned off", FIX.verify, "medium"));
            const alg = t.match(/^\s*algorithm:\s*["']?(RSA|ECDSA|Ed25519)["']?\s*$/);
            if (alg && lines.some((l) => /^\s*(privateKey|issuerRef|secretName):/.test(l.text) || /cert-manager\.io/.test(l.text)))
                add(cryptoHit(line, keyAlgorithm(alg[1])));
            const top = t.match(/^(data|stringData):\s*$/);
            if (top)
                inSecretData = docKind === "Secret" ? 0 : -1;
            else if (inSecretData >= 0 && /^\S/.test(t))
                inSecretData = -1;
            else if (inSecretData >= 0) {
                const kv = t.match(/^\s+([A-Za-z0-9_.-]+):\s*["']?([^\s"'#]+)["']?\s*$/);
                if (kv && kv[2].length >= 8 && !PLACEHOLDER.test(kv[2]) && !PLACEHOLDER.test(decode(kv[2])))
                    add(secretHit(line, kv[2], "Kubernetes Secret value"));
            }
        }
        // --- Terraform / OpenTofu ---
        if (type === "terraform") {
            let m;
            if ((m = t.match(/^\s*(algorithm|key_algorithm|customer_master_key_spec|key_spec|key_type)\s*=\s*"([A-Za-z0-9_-]+)"/))) {
                const word = m[2].replace(/-HSM$/i, "");
                const isKeyContext = m[1] !== "algorithm" || /^(RSA|ECDSA|ED25519|RSA_|EC_SIGN|EC_P)/i.test(word);
                const a = isKeyContext ? keyAlgorithm(word) : null;
                if (a && !/^(SYMMETRIC|HMAC|GOOGLE_SYMMETRIC)/i.test(word)) {
                    const block = hclBlock(lines, i);
                    const bits = rsaBitsOf(word) ?? (block ? Number(hclValue(textOf(lines, block), "(?:rsa_bits|key_size)") ?? NaN) : NaN);
                    add(cryptoHit(line, a, Number.isFinite(bits) ? bits : undefined));
                }
            }
            if ((m = t.match(/^\s*(storage_encrypted|encrypted|encryption_at_rest_enabled|at_rest_encryption_enabled|kms_encrypted|enable_encryption|server_side_encryption_enabled|enable_blob_encryption|enable_file_encryption)\s*=\s*false\b/))) {
                add(exposed(line, "Encryption at rest off", "Stored data is not encrypted", FIX.atRest));
            }
            if (/^\s*enabled\s*=\s*false\b/.test(t)) {
                const b = hclBlock(lines, i);
                if (b && /^\s*(encrypt_at_rest|encryption_at_rest|server_side_encryption|node_to_node_encryption)\b/.test(lines[b.start].text)) {
                    add(exposed(line, /node_to_node/.test(lines[b.start].text) ? "Unencrypted traffic allowed" : "Encryption at rest off", "Encryption turned off", /node_to_node/.test(lines[b.start].text) ? FIX.transit : FIX.atRest));
                }
            }
            if (/^\s*viewer_protocol_policy\s*=\s*"allow-all"/.test(t) || /^\s*(enable_https_traffic_only|https_traffic_only_enabled|https_only|transit_encryption_enabled|require_ssl)\s*=\s*false\b/.test(t) || /^\s*ssl_mode\s*=\s*"ALLOW_UNENCRYPTED_AND_ENCRYPTED"/.test(t)) {
                add(exposed(line, "Unencrypted traffic allowed", "Plain, unencrypted connections are allowed", FIX.transit));
            }
            if (/^\s*(insecure|skip_tls_verify|insecure_skip_verify|tls_insecure_skip_verify|skip_cert_verification)\s*=\s*true\b/.test(t)) {
                add(exposed(line, "TLS verification off", "Certificate checks turned off", FIX.verify, "medium"));
            }
            if (/^\s*(acl|predefined_acl|canned_acl)\s*=\s*"(public-read|public-read-write|authenticated-read|publicRead|publicReadWrite)"/.test(t) || /^\s*(block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b/.test(t) || /^\s*(allow_nested_items_to_be_public|allow_blob_public_access)\s*=\s*true\b/.test(t) || /^\s*container_access_type\s*=\s*"(blob|container)"/.test(t) || /^\s*(members?|member)\s*=\s*[^\n]*"(allUsers|allAuthenticatedUsers)"/.test(t)) {
                add(exposed(line, "Public storage", "Storage or a resource is open to the public", FIX.publicStore));
            }
            if (/^\s*publicly_accessible\s*=\s*true\b/.test(t))
                add(exposed(line, "Public database", "Database reachable from the internet", FIX.publicDb));
            if (/^\s*(cidr_blocks|ipv6_cidr_blocks|cidr_ipv4|cidr_ipv6)\s*=\s*[^\n]*"(0\.0\.0\.0\/0|::\/0)"/.test(t))
                add(awsOpenPort(lines, i));
            // A list written over several lines: cidr_blocks = [\n  "0.0.0.0/0"]
            if (/^\s*"(0\.0\.0\.0\/0|::\/0)"/.test(t) && listKeyAbove(lines, i, /(cidr_blocks|ipv6_cidr_blocks)\s*=\s*\[/))
                add(awsOpenPort(lines, i));
            if (/^\s*source_ranges\s*=\s*[^\n]*"0\.0\.0\.0\/0"/.test(t))
                add(gcpOpenPort(lines, i));
            if (/^\s*cidr_block\s*=\s*"0\.0\.0\.0\/0"/.test(t)) {
                const r = hclResource(lines, i);
                if (r && /master_authorized_networks/.test(textOf(lines, r)))
                    add(openPortHit(line, "The Kubernetes API"));
            }
            if (/^\s*value\s*=\s*"0\.0\.0\.0\/0"/.test(t)) {
                const b = hclBlock(lines, i);
                if (b && /^\s*authorized_networks\b/.test(lines[b.start].text))
                    add(exposed(line, "Public database", "Database reachable from the internet", FIX.publicDb));
            }
            if ((/^\s*security_ips\s*=.*"0\.0\.0\.0(\/0)?"/.test(t) || (/^\s*"0\.0\.0\.0(\/0)?"/.test(t) && listKeyAbove(lines, i, /security_ips\s*=\s*\[/)))) {
                add(exposed(line, "Public database", "Database reachable from the internet", FIX.publicDb));
            }
            if (/^\s*source_address_prefix\s*=\s*"(\*|Internet|0\.0\.0\.0\/0|Any)"/.test(t))
                add(azureOpenPort(lines, i));
            if ((m = t.match(/^\s*(password|master_password|admin_password|administrator_login_password|client_secret|secret_key|access_key|api_key|token|auth_token)\s*=\s*"([^"$]{8,})"/)) && !PLACEHOLDER.test(m[2]) && !/^[a-z_.]+$/.test(m[2])) {
                add(secretHit(line, m[2]));
            }
        }
        // --- CloudFormation (YAML or JSON) ---
        if (type === "cloudformation") {
            const kv = (key, val) => new RegExp(`["']?(?:${key})["']?\\s*:\\s*["']?(?:${val})["']?\\s*,?\\s*$`).test(t);
            if (kv("StorageEncrypted|Encrypted|AtRestEncryptionEnabled|KmsEncrypted", "false"))
                add(exposed(line, "Encryption at rest off", "Stored data is not encrypted", FIX.atRest));
            if (kv("ViewerProtocolPolicy", "allow-all") || kv("TransitEncryptionEnabled", "false"))
                add(exposed(line, "Unencrypted traffic allowed", "Plain, unencrypted connections are allowed", FIX.transit));
            if (kv("AccessControl", "PublicRead|PublicReadWrite|AuthenticatedRead") || kv("BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets", "false"))
                add(exposed(line, "Public storage", "Storage is open to the public", FIX.publicStore));
            if (kv("PubliclyAccessible", "true"))
                add(exposed(line, "Public database", "Database reachable from the internet", FIX.publicDb));
            let m;
            if ((m = t.match(/["']?(KeySpec|CustomerMasterKeySpec|KeyAlgorithm)["']?\s*:\s*["']?(RSA_\d+|ECC_[A-Z0-9_]+|EC_[a-z0-9]+)/)))
                add(cryptoHit(line, keyAlgorithm(m[2]), rsaBitsOf(m[2])));
            if (/["']?CidrIp(v6)?["']?\s*:\s*["']?(0\.0\.0\.0\/0|::\/0)/.test(t))
                add(cfnOpenPort(lines, i));
            if ((m = t.match(/["']?(MasterUserPassword|DBPassword|AdminPassword)["']?\s*:\s*["']?([^"'\s!{,]{8,})/)) && !PLACEHOLDER.test(m[2]))
                add(secretHit(line, m[2]));
        }
    }
    const seen = new Set();
    return hits
        .filter((h) => {
        const k = `${h.line.no}:${h.algorithm}`;
        if (seen.has(k))
            return false;
        seen.add(k);
        return true;
    })
        .map((h) => ({
        kind: h.kind,
        ruleId: `infra-${h.algorithm.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
        title: h.title,
        algorithm: h.algorithm,
        primitive: h.primitive,
        risk: h.risk,
        severity: h.severity,
        file: path,
        line: h.line.no,
        snippet: h.snippet ?? trim(h.line.text),
        fix: h.fix,
        keySize: h.keySize,
    }));
}
function decode(v) {
    try {
        return /^[A-Za-z0-9+/=]+$/.test(v) && v.length % 4 === 0 ? atob(v) : v;
    }
    catch {
        return v;
    }
}
function openPortHit(line, ports) {
    return exposed(line, "Open to the internet", `${ports[0].toUpperCase()}${ports.slice(1)} open to the whole internet`, FIX.openPort);
}
function num(v) {
    if (v === null)
        return null;
    return /^-?\d+$/.test(v.trim()) ? Number(v) : NaN;
}
/** Whether line i sits inside a multi-line list opened by a key matching re. */
function listKeyAbove(lines, i, re) {
    for (let j = i - 1; j >= Math.max(0, i - 6); j--) {
        const t = lines[j].text;
        if (re.test(t))
            return !/\]/.test(t);
        if (/\]|=/.test(t))
            return false;
    }
    return false;
}
const ICMP = /^(icmp|icmpv6|1|58)$/i;
const LOAD_BALANCER = /load.?balancer|\b(alb|elb|nlb|lb)\b|(alb|elb|nlb|lb)(sg|_sg|-sg|securitygroup)\b/i;
/** Text that names the security group around line i: its resource name, name and description. */
function groupLabel(lines, i) {
    const out = [];
    for (let j = i; j >= Math.max(0, i - 80); j--) {
        const t = lines[j].text;
        if (/\b(description|name|GroupDescription|GroupName)\b\s*[=:]/i.test(t))
            out.push(t);
        const tf = t.match(/^\s*resource\s+"[^"]+"\s+"([^"]+)"/);
        if (tf)
            return [tf[1], ...out].join(" ");
        const cfn = t.match(/^\s{2,4}"?([A-Za-z0-9]+)"?\s*:\s*\{?\s*$/);
        if (cfn && /Type"?\s*:\s*"?AWS::EC2::SecurityGroup/.test(lines.slice(j, j + 4).map((l) => l.text).join(" "))) {
            for (let k = j; k <= Math.min(lines.length - 1, j + 12); k++)
                if (/GroupDescription/.test(lines[k].text))
                    out.push(lines[k].text);
            return [cfn[1], ...out].join(" ");
        }
    }
    return out.join(" ");
}
/** A load balancer's group usually opens everything because the listeners pick the ports. */
function lbAllPorts(lines, i, ports) {
    return ports === "all ports" && LOAD_BALANCER.test(groupLabel(lines, i));
}
function awsOpenPort(lines, i) {
    const b = hclBlock(lines, i);
    if (!b)
        return null;
    const header = lines[b.start].text;
    const body = textOf(lines, b);
    const isRule = /resource\s+"aws_security_group_rule"/.test(header);
    if (!(/^\s*ingress\s*\{/.test(header) || /resource\s+"aws_vpc_security_group_ingress_rule"/.test(header) || (isRule && /^\s*type\s*=\s*"ingress"/m.test(body))))
        return null;
    const proto = hclValue(body, "(?:protocol|ip_protocol)");
    if (proto && ICMP.test(proto))
        return null;
    const all = proto === "-1" || proto === "all";
    const ports = exposedPorts(num(hclValue(body, "from_port")), num(hclValue(body, "to_port")), all);
    if (!ports || lbAllPorts(lines, i, ports))
        return null;
    return openPortHit(lines[i], ports);
}
function gcpOpenPort(lines, i) {
    const r = hclResource(lines, i);
    if (!r || !/resource\s+"google_compute_firewall"/.test(lines[r.start].text))
        return null;
    const body = textOf(lines, r);
    if (/^\s*direction\s*=\s*"EGRESS"/m.test(body))
        return null;
    const allowBlocks = [...body.matchAll(/allow\s*\{([^}]*)\}/g)].map((m) => m[1]);
    for (const a of allowBlocks) {
        const proto = hclValue(a, "protocol");
        const portsList = a.match(/ports\s*=\s*\[([^\]]*)\]/);
        if (proto === "all" || ((proto === "tcp" || proto === "udp") && !portsList))
            return openPortHit(lines[i], "all ports");
        for (const p of portsList?.[1].split(",") ?? []) {
            const pr = portRange(p);
            const hit = pr && exposedPorts(pr[0], pr[1], false);
            if (hit)
                return openPortHit(lines[i], hit);
        }
    }
    return null;
}
function azureOpenPort(lines, i) {
    const b = hclBlock(lines, i);
    if (!b)
        return null;
    const body = textOf(lines, b);
    if (!/^\s*direction\s*=\s*"Inbound"/m.test(body) || !/^\s*access\s*=\s*"Allow"/m.test(body))
        return null;
    const ranges = [];
    const single = hclValue(body, "destination_port_range");
    if (single)
        ranges.push(single);
    const multi = body.match(/destination_port_ranges\s*=\s*\[([^\]]*)\]/);
    if (multi)
        ranges.push(...multi[1].split(","));
    for (const p of ranges) {
        const pr = portRange(p);
        const hit = pr && exposedPorts(pr[0], pr[1], false);
        if (hit)
            return openPortHit(lines[i], hit);
    }
    return null;
}
function cfnOpenPort(lines, i) {
    // Look at the list item around the CidrIp line, bounded by neighbouring CidrIp lines.
    const near = [];
    for (let j = i - 1; j >= Math.max(0, i - 6); j--) {
        if (/CidrIp|^\s*-\s|\{\s*$/.test(lines[j].text) && j !== i) {
            near.push(lines[j].text);
            if (/CidrIp/.test(lines[j].text) || /^\s*-\s/.test(lines[j].text))
                break;
            continue;
        }
        near.push(lines[j].text);
    }
    for (let j = i + 1; j <= Math.min(lines.length - 1, i + 6); j++) {
        if (/CidrIp|^\s*-\s/.test(lines[j].text))
            break;
        near.push(lines[j].text);
    }
    const ctx = near.join("\n") + "\n" + lines[i].text;
    // The nearest section or resource type above says whether this is an inbound rule.
    let dir = null;
    for (let j = i; j >= Math.max(0, i - 60) && !dir; j--) {
        const m = lines[j].text.match(/SecurityGroup(Ingress|Egress)/);
        if (m)
            dir = m[1];
    }
    if (dir !== "Ingress")
        return null;
    const val = (k) => {
        const m = ctx.match(new RegExp(`["']?${k}["']?\\s*:\\s*["']?(-?\\w+)`));
        return m ? m[1] : null;
    };
    const proto = val("IpProtocol");
    if (proto && ICMP.test(proto))
        return null;
    const ports = exposedPorts(num(val("FromPort")), num(val("ToPort")), proto === "-1" || proto === "all");
    if (!ports || lbAllPorts(lines, i, ports))
        return null;
    return openPortHit(lines[i], ports);
}
