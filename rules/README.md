# Community detection rules

Each file in `community/` is one rule: a pattern that finds one kind of encryption in one kind of source file. Rules are plain JSON, so you can add one without writing TypeScript.

## A rule

```json
{
  "id": "rust-rsa-crate",
  "title": "RSA key generation with the rsa crate",
  "extensions": [".rs"],
  "pattern": "\\bRsaPrivateKey::new\\s*\\(",
  "algorithm": "RSA",
  "keySize": "RsaPrivateKey::new\\s*\\([^,]+,\\s*(\\d{3,5})",
  "examples": {
    "match": ["let key = RsaPrivateKey::new(&mut rng, 2048)?;"],
    "noMatch": ["let pk = RsaPublicKey::from(&key);"]
  },
  "references": ["https://docs.rs/rsa"],
  "author": "Your name or GitHub handle"
}
```

| Field | What it is |
| --- | --- |
| `id` | Language, then library, then what it finds, joined by hyphens. The file is named `<id>.json`. |
| `title` | What the rule finds, in plain words, 10 to 80 characters. |
| `extensions` | File extensions the rule runs on. |
| `pattern` | A JavaScript regular expression, matched one line at a time. Escape backslashes for JSON. |
| `flags` | Optional. Only `"i"` (ignore case) is allowed. |
| `algorithm` | What the match uses, as one of the algorithm names the scanner knows: `RSA`, `RSA signature`, `RSA encryption`, `ECDSA`, `EC`, `ECDH`, `DH`, `X25519`, `X448`, `Ed25519`, `Ed448`, `DSA`, `MD5`, `SHA-1`, `DES`, `3DES`, `RC4`, `ECB mode`, `TLS 1.0/1.1`, `Weak TLS ciphers`. If one pattern finds several, map a capture group instead: `{ "groups": [1], "map": { "md5": "MD5", "sha1": "SHA-1" } }` (map keys lowercase). |
| `keySize` | Optional. A regular expression whose first group is the key size in bits, so short RSA keys are flagged as weak today. |
| `examples.match` | Real lines the rule must find. At least one. |
| `examples.noMatch` | Look-alike lines it must not find, such as the safe alternative. At least one. |
| `references` | Links to the library's documentation for the API. |
| `author` | You. |

The scanner already decides how serious each algorithm is, when it is due and what to move to. A rule only says where the algorithm is used.

MD5 and SHA-1 are reported only where the code around the match protects something (a password, signature, token, HMAC and the like); checksums, cache keys and ETags are skipped. So give `MD5` and `SHA-1` rules examples that show a security use, or the end-to-end test will fail.

## Good rules

- **Match the call that creates or uses a key**, not a mention in a comment or an import of a whole library, unless the import only exists for that algorithm.
- **Keep patterns simple.** No nested repeats like `(a+)+`: they can hang on a long line, and the checker rejects them.
- **Put the safe look-alike in `noMatch`.** A rule for `SHA1.Create()` should not fire on `SHA256.Create()`.
- **One algorithm family per rule.** Two short rules beat one clever one.

## Check your rule

```
node scripts/build-rules.mjs
npm test
```

The first command checks every rule (fields, pattern, examples, known algorithm, no duplicate id) and bundles them into the scanner. The tests then run each example through the real scanner.
