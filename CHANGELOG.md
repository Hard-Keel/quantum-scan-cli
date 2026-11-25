# Changelog

## Unreleased

- **Find forgotten hostnames.** `quantum-scan hosts example.com` lists the names under a domain from public certificate logs (crt.sh), so old APIs, staging sites and vendor portals on your domain don't get missed. One request to the public log; none of the hosts are contacted. Respects offline mode.
- **Fairer grade on older Node.js.** If your Node.js can't offer ML-KEM (it needs OpenSSL 3.5 or later), a TLS 1.3 website is no longer marked down for "no quantum-safe option". The map lists it as not tested instead.
- **Full encryption inventory.** The CBOM (`--cbom`, and `map.cbom.json` from `map`) now lists every algorithm in use, not only the ones to fix: AES with key size and mode, ChaCha20-Poly1305, SHA-2, SHA-3, HMAC, PBKDF2, scrypt, Argon2, bcrypt and HKDF, plus ML-KEM, ML-DSA and SLH-DSA with their NIST security level. Each entry says what it's used for (encrypt, digest, sign and so on). `--format json` includes it as `inventory`, and the text summary names the top ones. It never changes the grade.
- **Sign-in signing check.** For proved websites, `map` reads the OpenID Connect discovery document (and its signing keys) or listed SAML metadata, and reports the algorithm sign-in tokens and assertions are signed with. RSA and ECDSA are quantum-breakable; unsigned tokens, RSA under 2048 bits and SHA-1 signatures are broken now. Only domains you proved are read.
- **High, medium and low ratings.** Every `map` finding now carries a plain rating, shown in the terminal, as a label in `map.html`, and as `rating` and `ratings` in `map.json`. Internet-facing systems and long-lived keys rank first. The tiers and the grade are unchanged.
- **SARIF and CycloneDX everywhere.** `map` now also writes `map.sarif.json`, its findings in SARIF 2.1.0 with the rating, tier and area on each, for security tools that read SARIF. Code findings point at their file and line; websites, network and machine findings name the place they were found. `--format cyclonedx` prints the encryption inventory, the same CBOM as `--cbom`. For GitHub code scanning, upload the code scan's `--format sarif` output, since GitHub only shows results tied to a file.
- The website check now accepts either hybrid ML-KEM key exchange, X25519MLKEM768 or SecP256r1MLKEM768, in the same single handshake.
- **Better results in GitHub code scanning.** Encryption quantum computers will break is now scored Medium or lower, so it lands in the plan rather than ahead of what is broken now. Rules have help text with the fix and a link. Paths start at the repository root when you scan a subfolder, so code scanning can place them. Rule ids for exposed settings no longer change with the ports found (for example `exposed/open-to-the-internet`), so those alerts keep their history from this version on. A sample workflow is in `docs/examples/code-scanning.yml`.
- **A more accurate encryption inventory.** SSH findings are now SSH protocol assets instead of TLS 1.0/1.1, certificate problems (expired, wrong name) are no longer listed as encryption methods, and common algorithms carry their object identifier.
- "SSH key exchange" no longer reads "SSH key exchange key exchange" in reports.

## 0.3.2

- **Finds encryption in signing and token libraries.** Recognizes JWT and JOSE algorithm names (RS256, ES256, EdDSA, RSA-OAEP, ECDH-ES and the rest) in JavaScript, TypeScript, Python, Go and Java; Node's RSA and ECDSA signing names; RSA public-key encryption; JWK key types and curves; elliptic, @noble/curves and tweetnacl; golang-jwt signing methods; Java JWT constants; and python-rsa and paramiko key generation. On 259 popular npm packages that handle encryption or tokens, the scanner finds quantum-breakable encryption in 52.
- Type declaration files (`.d.ts`) and comment lines no longer count as encryption in use.
- Shorter, plainer wording for the anonymized sharing notice, with "files" added to what is never sent.
- Fewer false leaked-key alarms: constants whose value is their own name (like a header name), and long names made only of words (like `urn:ietf:params:oauth:grant-type:token-exchange`), no longer count.

## 0.3.1

- **A report you can hand to someone.** `map.html` is now a clean, branded report: the grade up top, a short "Start here" list, findings ranked by what breaks first with how to fix each one, and the same problem in many places shown once with its list of places. It prints well, with page numbers, so your browser's Save as PDF gives a ready PDF. Still one file, with no web fonts or scripts from anywhere else, so it works offline.
- At the end of `quantum-scan map`, the tool prints where the report is and, in a terminal, offers to open it.

## 0.3.0

New in `quantum-scan map`:

- **Network and connected equipment.** Looks at routers, switches, printers, cameras, storage boxes and smart devices on your own private network: about 30 common ports, the title of any web page they serve, the certificate on secure admin pages, and the router's list of automatic port forwards (UPnP). Flags Telnet and plain FTP, open remote desktop, VNC and remote support tools, devices still on their setup page, admin pages without encryption or with the factory certificate, open print ports, camera and recorder ports, unencrypted MQTT, open databases, the Docker API, and router forwards from the internet. It never logs in, tries a password or changes a setting.
- **Who can read your cloud data.** Notes cloud storage, databases, disks and backups in Terraform and CloudFormation whose encryption keys the provider holds, and how to keep the keys yourself. Advice only; it doesn't change the score.
- **People and process.** 18 optional yes/no questions about what no scan can see, from phishing training and call-back checks to backups and a breach plan. Scored on their own, kept on your machine and never shared.

Code scan:

- Finds Go TLS settings that list curves without the hybrid ML-KEM group, which turns off Go's post-quantum key exchange.
- Far fewer false leaked-key alarms. Translated "password" labels, editor token names, keys and fake tokens in test code, CI databases on localhost, `.env.example` files, API spec examples, secret-store references and public client keys no longer count, so they no longer pull the grade down. Real token formats and private keys in shipped code still do.

## 0.2.0

First public release: code and infrastructure config scan, encryption inventory (CycloneDX CBOM), SARIF, migration report, readiness score and badge, and `quantum-scan map` for code, websites and this machine, with one readiness grade across areas, accepted leftovers in `.quantum-scan-ignore`, a public resolver fallback for the ownership record, and an HTML report that reads in light and dark mode and prints cleanly.
