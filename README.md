# Hard Keel Quantum Scan

Finds encryption that quantum computers will break, weak encryption, exposed infrastructure settings, and leaked keys or passwords in your code and infrastructure config. Writes an encryption inventory and a plan for moving to quantum-safe methods.

Free and open source under the Apache 2.0 licence. No account and no dependencies. Your code and results stay on your machine; see [Anonymized sharing](#anonymized-sharing) for the one small summary it sends, and how to turn it off.

## Run it

```sh
npx @hardkeel/quantum-scan
```

Scans the current folder and prints what to fix now and what to plan for:

```
Hard Keel Quantum Scan · 4 files scanned

Quantum readiness: C (75/100, Hard Keel method v1). Weak encryption or exposed settings hold the grade at C or lower until they are fixed.

Found 2 uses of weak encryption and 1 use of encryption quantum computers will break.

Fix now
  payments.py:6  RSA-1024 key
    Use 3072-bit keys or larger now, then plan the move to post-quantum methods.
  payments.py:10  ECB mode
    Switch to AES-256-GCM.

Plan for later
  Safe today, but quantum computers will be able to break these. NIST plans to phase them out between 2030 and 2035.
  auth.ts:6  ECDH key exchange
    Move key exchange to ML-KEM (FIPS 203), or hybrid X25519 + ML-KEM-768 for TLS.
```

## Options

| Option | What it does |
| --- | --- |
| `--cbom <file>` | Write the encryption inventory as a CycloneDX 1.6 CBOM |
| `--report <file>` | Write the migration report, in the order to fix things |
| `--badge <file>` | Write a quantum readiness badge (SVG) to put on your README |
| `--format text\|json\|sarif` | What to print. SARIF works with GitHub code scanning |
| `--output <file>` | Write that output to a file |
| `--fail-on <list>` | Exit with 1 on `secret`, `weak-now`, `exposed`, `quantum-vulnerable`, or `none`. Default `secret,weak-now,exposed` |
| `--quiet` | Leave out the closing line about installing on GitHub |
| `--offline` | Send nothing to Hard Keel |

## Quantum readiness score

Every scan ends with a grade from A+ to F and a score out of 100. The method is open and versioned: [how the score works](https://hardkeel.com/learn/quantum-readiness-score/).

- **A+:** nothing to fix, and post-quantum encryption (ML-KEM, ML-DSA, SLH-DSA) is already in use.
- **A:** nothing to fix now, or only signatures left to move before 2035.
- **B:** key exchange that quantum computers will break, due to move by 2030.
- **C or lower:** weak encryption or exposed settings to fix now. A leaked key or password holds the grade at D or lower.

Put the grade on your README with `--badge quantum-readiness.svg`, or install Hard Keel Quantum Scan on GitHub to keep a live badge current for public repositories.

## What it looks for

- **Encryption quantum computers will break:** RSA, elliptic-curve (ECDSA, ECDH, Ed25519, X25519) and Diffie-Hellman.
- **Weak encryption:** MD5, SHA-1, DES, 3DES, RC4, ECB mode, DSA, RSA under 2048 bits, TLS 1.0 and 1.1.
- **Exposed infrastructure settings:** storage or databases open to the public, admin and database ports open to the whole internet, encryption at rest turned off, unencrypted traffic allowed, and certificate checks turned off.
- **Weak TLS in config:** old TLS versions and weak cipher suites in nginx, Apache, HAProxy, load balancer and CDN settings.
- **Leaked keys and passwords:** private keys, cloud and API tokens, passwords in connection strings, Terraform, CloudFormation, Dockerfiles and Kubernetes Secrets. They are masked in all output.

It reads Python, JavaScript and TypeScript, Go, Java, plus Rust, C#, PHP, Ruby, Swift and C or C++ with OpenSSL through community rules, and Terraform and OpenTofu, CloudFormation, Kubernetes manifests, Dockerfiles, and nginx, Apache and HAProxy configs. A plain scan looks at files only. To check live websites and this machine too, use `quantum-scan map`.

## Encryption map

```sh
npx @hardkeel/quantum-scan map
```

Checks more than code, one area at a time, and asks before each one. For every area it says what it will touch, what it reads and what it never does. The answer is no unless you type yes.

- **Code and config:** the same checks as a plain scan.
- **Websites and public services:** the encryption your sites, APIs and SSH servers offer, from about six normal connections each, a quarter second apart. It never logs in or sends attack traffic. It checks only domains you've proved are yours, with one DNS record that covers the domain and everything under it:

  ```sh
  npx @hardkeel/quantum-scan prove example.com
  ```

- **Network and connected equipment:** routers, switches, printers, cameras, storage boxes and smart devices on your own network. For each address it checks whether about 30 common ports answer, reads the title of any web page they serve and the certificate on secure admin pages, and reads the router's list of automatic port forwards (UPnP) if it publishes one. It flags Telnet and plain FTP, open remote desktop, VNC and remote support tools, devices still on their setup page, admin pages without encryption or with the factory certificate, open print ports, camera and recorder ports, unencrypted MQTT, open databases and Docker, and router forwards from the internet. It never logs in, tries a password, sends commands to equipment or changes a setting. Only private address ranges this computer is on (or other segments of your own network that you confirm), at most 1,024 addresses, one connection at a time per device. List fragile equipment, like older industrial or medical controllers, under `exclude` and it's never touched:

  ```json
  "network": { "ranges": ["192.168.1.0/24"], "routed": ["192.168.20.0/24"], "exclude": ["192.168.1.250"] }
  ```

- **This machine:** SSH server settings and host keys, OpenSSL settings, certificates on disk, and on Windows the TLS settings and machine certificate store. Read only. It changes nothing and never reads private key files.

Two more parts of the report aren't scans:

- **Who can read your cloud data:** where your Terraform or CloudFormation stores data in cloud storage, databases, disks or backups with keys the provider holds, or with your key in the provider's key service. Those keys protect against a stolen disk, not against the provider, someone working there, or a legal demand made to them. For data no third party should be able to read, it recommends encrypting before upload or keeping the keys in an external key store you hold. Listed as advice, not scored.
- **People and process:** 18 optional yes/no questions about what no scan can see: phishing and social-engineering training, call-back checks on payment and password requests, multi-factor sign-in, admin accounts, leavers, vendor access, default passwords, firmware, printer job storage, guest and payment network separation, containment, sandboxing, cloud keys, backups, a breach plan and logs. Your answers get their own score next to the technical findings. They're saved in `quantum-scan-map/people.json`, kept out of the scope file, and never sent anywhere.

Results get the same readiness grade as a code scan, and are ranked by when to act: broken now, at risk from data recorded now and read later, long-lived signatures, then the rest. The map is written to `quantum-scan-map/` as `map.html` (a report you can open in any browser and save as a PDF), `map.json`, a CycloneDX CBOM and `activity.log`, which lists every connection and every file read, with the time and the reason. Nothing leaves your machine except the summary below.

For pipelines, save your answers to `quantum-scan.scope.json` when asked, then run `quantum-scan map --scope quantum-scan.scope.json`. It checks only what the file lists. Add `--fail-on broken` to fail the build when anything is broken now.

## Leaving out findings you've reviewed

Add a `.quantum-scan-ignore` file to the scanned folder:

```
# a check everywhere
rule:py-weak-hash
# a folder or a file
legacy/
tools/migrate.py
# one check in one file
src/hash.py:py-weak-hash
```

A leaked key or password can only be left out by naming its file, never by check alone.

For `quantum-scan map`, the same file in the folder you run it from can accept a known leftover on a website or this machine, for example a setting your host won't let you change:

```
# one check on one site
example.com:443:web-tls-static-rsa
# everything on one site, any port
legacy.example.com
```

Accepted items still appear in the report, in their own section, but don't count toward the score.

## Anonymized sharing

We collect anonymized, aggregated information about how our checks perform and what kinds of encryption they find. It never includes your code, keys, server names, IP addresses or company name. We use it to improve and build our products and to understand encryption trends across the industry. You can turn this off at any time, or run fully offline.

Each run sends one small summary: which checks fired and how often (rounded to bands like 2-5), which encryption types were found, which errors happened, the tool version, operating system and a random ID that is linked to nothing. Industry and company size are optional, and asked once. Details: [hardkeel.com/privacy](https://hardkeel.com/privacy/).

| Command | What it does |
| --- | --- |
| `quantum-scan config show-shared` | Shows exactly what the last run sent, or would have sent |
| `quantum-scan config sharing off` | Turns sharing off (or set `QUANTUM_SCAN_SHARING=off`) |
| `--offline` | Sends nothing at all (or set `QUANTUM_SCAN_OFFLINE=1`, or `quantum-scan config offline on`) |

`DO_NOT_TRACK=1` is respected too.

## In GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: Hard-Keel/quantum-scan-cli@v0
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: quantum-scan.sarif
```

The migration report goes to the job summary. Code scanning results need a public repository or GitHub Advanced Security. To send nothing from your pipeline, set `QUANTUM_SCAN_SHARING: off` in the job's `env`.

## Contributing rules

Detection rules for new languages and libraries are plain JSON files in [`rules/community/`](rules/community), each with examples it must and must not match. See [rules/README.md](rules/README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## On every pull request

[Install Hard Keel Quantum Scan on GitHub](https://github.com/apps/hard-keel-quantum-scan) to run the same checks on every pull request with nothing to set up. It comments on the pull request, posts a check result, and keeps a report link for each repository that stays current.

Built by [Hard Keel](https://hardkeel.com). Questions: contact@hardkeel.com. Security reports: security@hardkeel.com.
