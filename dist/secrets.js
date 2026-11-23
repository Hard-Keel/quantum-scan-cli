// Leaked-credential detection. A bonus check that rides along with the crypto scan.
export const SECRET_RULES = [
    { id: "private-key", name: "Private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
    { id: "aws-access-key-id", name: "AWS access key", pattern: /\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b/, group: 1 },
    { id: "github-token", name: "GitHub token", pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/, group: 1 },
    { id: "github-fine-grained-pat", name: "GitHub token", pattern: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/, group: 1 },
    { id: "gitlab-pat", name: "GitLab token", pattern: /\b(glpat-[A-Za-z0-9_-]{20,})\b/, group: 1 },
    { id: "slack-token", name: "Slack token", pattern: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/, group: 1 },
    { id: "slack-webhook", name: "Slack webhook", pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+)/, group: 1 },
    { id: "stripe-secret", name: "Stripe secret key", pattern: /\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b/, group: 1 },
    { id: "google-api-key", name: "Google API key", pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/, group: 1 },
    { id: "anthropic-key", name: "Anthropic API key", pattern: /\b(sk-ant-[A-Za-z0-9_-]{32,})\b/, group: 1 },
    { id: "openai-key", name: "OpenAI API key", pattern: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{32,})\b/, group: 1 },
    { id: "sendgrid-key", name: "SendGrid key", pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/, group: 1 },
    { id: "npm-token", name: "npm token", pattern: /\b(npm_[A-Za-z0-9]{36})\b/, group: 1 },
    { id: "db-url-password", name: "Database password in URL", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/'"]+:([^@\s'"]{6,})@/, group: 1, minEntropy: 2.5 },
    {
        id: "generic-assignment",
        name: "Hardcoded secret",
        pattern: /\b[A-Za-z0-9_]*(?:api[_-]?key|secret|token|passwd|password|private[_-]?key)[A-Za-z0-9_]*["']?\s*[:=]\s*["']([^"'\s]{16,})["']/i,
        group: 1,
        minEntropy: 3.5,
    },
];
const PLACEHOLDER = /(example|sample|dummy|changeme|change_me|placeholder|your[_-]|^your|xxxx|\*\*\*\*|<[^>]+>|\$\{|\{\{|process\.env|os\.environ|getenv|redacted|test)/i;
// Documentation tokens like "xoxb-1234567890-abcdefghij".
const FAKE_SEQUENCE = /1234567890|0123456789|abcdefghij/;
// Names that hold something about a secret, not the secret itself (SECRET_KEY_PREFIX, password_template).
const NOT_A_SECRET_NAME = /(template|prefix|suffix|header|_name|name_|field|path|url|label|message|_msg|_type|type_|format|pattern|regex|tokeniz|hashed|token_?(?:roles_?)?key|_uid|invalid|not_?found|expir|permission|^\W*has_|repo|class|checksum|params?\b|req_?(?:query|body))/i;
/** The generic "name = value" rule is noisy; drop the shapes that are almost never real secrets. */
function looksLikeSecretAssignment(match, value, line) {
    const name = match.split(/["']?\s*[:=]/)[0];
    if (NOT_A_SECRET_NAME.test(name))
        return false;
    if (/^\s*(>>>|\.\.\.)\s/.test(line))
        return false; // doctest example
    if (/^[a-z_-]+$/.test(value))
        return false; // an identifier, like "userauth-gssapi-token"
    if (value.toLowerCase().startsWith(name.replace(/^\W+/, "").replace(/_/g, "-").toLowerCase()))
        return false; // a constant named for its own value, like a header name
    if (!/^[\x21-\x7e]+$/.test(value))
        return false; // text in another script, like a translated "Password" label
    if (!/\d/.test(value) && value.length < 32)
        return false;
    if (!/\d/.test(value) && /^[A-Za-z]+(?:[:._/-]+[A-Za-z]+)+$/.test(value))
        return false; // a long name made of words, like "urn:ietf:params:oauth:grant-type:token-exchange" or a scope // words, like "excludedRequestDomains:", not a random value
    if (/^\$?[a-z0-9_]+\$/.test(value))
        return false; // a stored password hash, like "pbkdf2_sha256$..." or "$argon2id$..."
    if (/\$\{?[A-Za-z_]|\$\(|\{\}|%[sd]|^var\(/.test(value))
        return false; // interpolation or a format string, like "$user:$password" or "$(Build.Secret)"
    if (/^(bao|vault|secret|op|sm|ref\+[a-z]+|arn):/i.test(value))
        return false; // a reference to a secret store, not the secret
    if (/^(phc_|pk_(live|test)_)/.test(value))
        return false; // a public client key (PostHog, Stripe publishable), safe to ship
    if (/^[([^]/.test(value))
        return false; // a regular expression
    if (/\\(x[0-9a-f]{2}|u[0-9a-f]{4}|0)/i.test(value))
        return false; // a binary magic string, like "openssh-key-v1\x00"
    if (/^[a-z]+(?:[A-Z][a-z]*)+$/.test(value))
        return false; // a camelCase identifier, like "challengePassword"
    if (/\{\{/.test(line))
        return false; // a Helm or Go template line
    if (/^[a-z][A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+)+$/.test(value))
        return false; // a settings key, like "webhook.github.secret"
    if (/^[A-Z][A-Z0-9_]{5,}$/.test(value))
        return false; // the name of an environment variable, like "ARGOCD_AUTH_TOKEN"
    if (/^(\/|\.{1,2}\/|~\/|[A-Za-z]:\\)/.test(value))
        return false; // a file path, like "/var/run/secrets/token"
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value))
        return false; // a URL, like "https://oauth2.googleapis.com/token"
    return true;
}
export function entropy(s) {
    const counts = new Map();
    for (const ch of s)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let h = 0;
    for (const c of counts.values()) {
        const p = c / s.length;
        h -= p * Math.log2(p);
    }
    return h;
}
export function mask(value) {
    if (value.length <= 8)
        return "****";
    return `${value.slice(0, 4)}${"*".repeat(Math.min(12, value.length - 4))}`;
}
export function findSecrets(line) {
    const hits = [];
    for (const rule of SECRET_RULES) {
        const m = line.match(rule.pattern);
        if (!m)
            continue;
        const value = m[rule.group ?? 0] ?? m[0];
        if (rule.id !== "private-key" && (PLACEHOLDER.test(value) || FAKE_SEQUENCE.test(value)))
            continue;
        if (rule.minEntropy !== undefined && entropy(value) < rule.minEntropy)
            continue;
        if (rule.id === "generic-assignment" && !looksLikeSecretAssignment(m[0], value, line))
            continue;
        if (rule.id === "db-url-password" && /^(pass(word)?|passwd|pwd|secret)$/i.test(value))
            continue;
        // A database on this machine (CI services, local dev) has a throwaway password.
        if (rule.id === "db-url-password" && /@(localhost|127\.0\.0\.1|\[::1\])[:/]/.test(m[0] + line.slice((m.index ?? 0) + m[0].length, (m.index ?? 0) + m[0].length + 12)))
            continue;
        hits.push({ rule, value });
    }
    // The generic rule only counts when nothing specific matched the line.
    const specific = hits.filter((h) => h.rule.id !== "generic-assignment");
    return specific.length ? specific : hits;
}
