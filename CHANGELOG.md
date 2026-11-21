# Changelog

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
