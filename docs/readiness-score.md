# Hard Keel quantum readiness score

Method version 1. Published by Hard Keel under CC BY 4.0, so anyone may use, cite or adapt it with credit.

The score answers one question about a code repository: how much of its encryption is ready for the move to post-quantum methods, and what is left to do first. It gives a grade from A+ to F and a score from 0 to 100. The code that computes it is `src/score.ts`, open source under Apache 2.0, so anyone can check a grade by running the free command-line scanner.

## What it measures

The scanner reads source code and infrastructure config in the repository. It finds four kinds of problem, and notes post-quantum encryption that is already in use.

| Category | What counts | Why |
| --- | --- | --- |
| Leaked keys and passwords | Private keys, cloud and API tokens, passwords in code and config | Usable by anyone who reads the repository, today |
| Weak encryption | MD5, SHA-1, DES, 3DES, RC4, ECB mode, DSA, RSA under 2048 bits, TLS 1.0 and 1.1, weak cipher suites | Already broken or no longer approved |
| Exposed settings | Public storage, open admin or database ports, encryption at rest off, unencrypted traffic, certificate checks off | Exposes data without any quantum computer |
| Quantum-breakable key exchange | RSA encryption, ECDH, X25519, X448, Diffie-Hellman | Traffic recorded today can be decrypted once a large quantum computer exists |
| Quantum-breakable signatures | RSA signatures, ECDSA, Ed25519, Ed448 | Can be forged once a large quantum computer exists, but not in hindsight |

An RSA or elliptic-curve key whose use the scanner can't tell from the line counts in the stricter of the two: RSA keys as key exchange, elliptic-curve keys as signatures.

Test code, test vectors, fixtures, examples and documentation are left out of the score, the same way they are left out of pull request checks. What counts is the code that ships.

## The dates behind it

NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* (final, October 2026), deprecates quantum-vulnerable public-key algorithms after 2030 and disallows them after 2035, for both key establishment and signatures, at every security strength. US federal policy asks for post-quantum key establishment on high-value systems by the end of 2030 and signatures by the end of 2031.

The score turns that into three due dates:

- **Now:** leaked keys, weak encryption and exposed settings.
- **2030:** key exchange, because of "record now, decrypt later" and the federal key-establishment deadline.
- **2035:** signatures, when NIST disallows them.

## How the score is computed

1. **Group.** Findings are grouped by category and algorithm (or setting). Ten files that all use ECDH are one group, not ten problems.
2. **Base points.** Each group takes points off a starting score of 100.

   | Category | Points per group |
   | --- | --- |
   | Leaked key or password | 25 |
   | Weak encryption | 10 if high severity (DES, RC4, ECB, DSA, short RSA, old TLS), 6 otherwise (MD5, SHA-1) |
   | Exposed setting | 12 critical, 8 high, 5 medium, 2 low |
   | Quantum-breakable key exchange | 5 |
   | Quantum-breakable signature | 2 |

3. **Use multiplier.** A group used in more places counts more, but not without limit: points × (1 + 0.25 × log2(uses)), at most double. One use counts once, 4 uses count 1.5 times, 16 or more count twice.
4. **Migration credit.** If the repository already uses post-quantum key exchange (ML-KEM, or a hybrid such as X25519 + ML-KEM-768), quantum-breakable key exchange counts half. The same applies to signatures when ML-DSA, SLH-DSA or FN-DSA is in use. Hybrids are allowed under IR 8547, so moving to one is real progress.
5. **Category caps.** No category can take off more than its cap, so one area cannot hide every other.

   | Category | Cap |
   | --- | --- |
   | Leaked keys and passwords | 50 |
   | Weak encryption | 30 |
   | Exposed settings | 30 |
   | Quantum-breakable key exchange | 20 |
   | Quantum-breakable signatures | 8 |

6. **Score.** 100 minus the capped total, rounded to a whole number, never below 0.

## How the grade is set

The grade comes from the score, then is held down by the most serious problem left.

| Score | Grade from score |
| --- | --- |
| 90 to 100 | A |
| 75 to 89 | B |
| 60 to 74 | C |
| 40 to 59 | D |
| 0 to 39 | F |

| While the repository has any... | Best grade possible |
| --- | --- |
| Leaked key or password | D |
| Weak encryption or exposed setting | C |
| Quantum-breakable key exchange | B |
| Quantum-breakable signature | A |

**A+** is for repositories with nothing left to fix that already use post-quantum encryption.

So a repository with clean, modern classical encryption (TLS with X25519, ECDSA signatures) gets a B. It reaches A by moving key exchange to ML-KEM, and A+ when signatures move too. A single MD5 call drops it to C until it is replaced or marked as a non-security checksum.

## Worked example

A repository with RSA-1024 in one file, AES in ECB mode in one file, and ECDH in one file:

| Group | Points |
| --- | --- |
| RSA-1024 (weak, high) | 10 |
| ECB mode (weak, high) | 10 |
| ECDH (key exchange) | 5 |
| **Total** | **25** |

Score 75, which is a B from the score, held to **C** by the weak encryption. Replace the short RSA key and ECB mode and it becomes a B at 95.

## The badge

The free command-line scanner writes the badge as a file: `npx @hardkeel/quantum-scan --badge quantum-readiness.svg`.

The Hard Keel Quantum Scan GitHub app keeps a live badge for public repositories, refreshed after merges to the default branch:

```
[![Quantum readiness](https://scan.hardkeel.com/badge/OWNER/REPO.svg)](https://hardkeel.com/learn/quantum-readiness-score/)
```

The badge shows only the grade and score. Private repositories never get a public badge, and a repository nobody has scanned shows "not scanned". A shields.io endpoint is available at the same address ending in `.json`.

## What the score does not cover

- Compiled dependencies, running services, certificates in use and hardware. A library the code calls may still negotiate quantum-breakable key exchange.
- Whether a use is reachable or matters. The scanner matches patterns line by line; it does not follow data flow.
- Intent. Libraries that implement legacy algorithms on purpose, for compatibility, score low. The score describes what the code contains.

A self-run score is a self-assessment. Pattern matching can be gamed by anyone who controls the code, so treat a badge as the owner's own claim.

## Versioning

Every score names its method version. Weights, caps and thresholds change only in a new version, published here with a changelog, and old versions stay available so a past score can always be reproduced.

### Changelog

- **v1 (November 2026):** first version, aligned with the final NIST IR 8547.
