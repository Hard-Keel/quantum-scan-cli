import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ActivityLog } from "../src/map-activity.ts";
import { cloudKeyAdvice } from "../src/map-cloud-keys.ts";
import { deviceFindings, hostsOf, isPrivateRange, NET_ALGORITHMS, parseMapping, parseRange, runNetwork, upnpService, type CertPeek, type HttpPeek, type NetIO, type ProbeState, type UpnpMapping } from "../src/map-network.ts";
import { parseAnswers, QUESTIONS, readAnswer, scorePeople } from "../src/map-people.ts";
import { parseScope, runMap } from "../src/map-run.ts";
import { MAP_ALGORITHMS, buildPayload } from "../src/share.ts";
import { loadSettings } from "../src/share-config.ts";

const range = (s: string) => {
  const r = parseRange(s);
  if ("error" in r) throw new Error(r.error);
  return r;
};

test("ranges: private only, /20 or smaller, network and broadcast left out", () => {
  assert.equal(hostsOf(range("192.168.1.0/24")).length, 254);
  assert.equal(hostsOf(range("10.0.0.5")).length, 1);
  assert.ok(isPrivateRange(range("172.20.0.0/24")));
  assert.ok(!isPrivateRange(range("8.8.8.0/24")));
  assert.ok(!isPrivateRange(range("172.32.0.0/24")));
  assert.ok("error" in parseRange("10.0.0.0/8"));
  assert.ok("error" in parseRange("example.com"));
});

interface Device {
  open: number[];
  closed?: boolean; // answers with refusals only
  pages?: Record<number, HttpPeek>;
  certs?: Record<number, CertPeek>;
}

function fakeNet(devices: Record<string, Device>, opts: { cidr?: string; upnp?: { host: string; mappings: UpnpMapping[] } | null } = {}) {
  const touched = new Set<string>();
  const io: NetIO = {
    interfaces: () => [{ address: "192.168.1.50", cidr: opts.cidr ?? "192.168.1.50/24" }],
    async probe(host, port): Promise<ProbeState> {
      touched.add(host);
      const d = devices[host];
      if (!d) return "timeout";
      return d.open.includes(port) ? "open" : "closed";
    },
    async http(host, port) {
      touched.add(host);
      return devices[host]?.pages?.[port] ?? { status: 200 };
    },
    async cert(host, port) {
      touched.add(host);
      return devices[host]?.certs?.[port] ?? null;
    },
    upnp: async (allowed) => (opts.upnp && !allowed(opts.upnp.host) ? { host: opts.upnp.host, mappings: [], outside: true } : (opts.upnp ?? null)),
    sleep: async () => {},
  };
  return { io, touched };
}

const lan: Record<string, Device> = {
  "192.168.1.1": { open: [80, 443], pages: { 80: { status: 200, title: "TP-Link Router Login" }, 443: { status: 200, title: "TP-Link Router Login" } }, certs: { 443: { subject: "CN=tplinkwifi.net", issuer: "CN=tplinkwifi.net", selfSigned: true } } },
  "192.168.1.20": { open: [80, 9100, 631], pages: { 80: { status: 200, title: "HP LaserJet Pro M404" } } },
  "192.168.1.30": { open: [80, 554, 37777], pages: { 80: { status: 200, title: "Device Activation" } } },
  "192.168.1.40": { open: [23, 2375] },
  "192.168.1.41": { open: [2375], pages: { 2375: { status: 404, server: "Docker/27.3.1 (linux)" } } },
  "192.168.1.60": { open: [], closed: true },
  "192.168.1.70": { open: [80], pages: { 80: { status: 301, location: "https://192.168.1.70/", title: "Synology DiskStation" } } },
};

test("network: look-only findings for routers, printers, cameras and open services", async () => {
  const { io, touched } = fakeNet(lan, { upnp: { host: "192.168.1.1", mappings: [{ externalPort: 8080, internalClient: "192.168.1.30", internalPort: 80, protocol: "TCP", description: "camera", enabled: true }] } });
  const res = await runNetwork({ ranges: ["192.168.1.0/24"], exclude: ["192.168.1.99"] }, new ActivityLog(), { io, gapMs: 0 });
  const ids = (ip: string) => res.findings.filter((f) => f.target.startsWith(`${ip}:`) || f.target.includes(`-> ${ip}:`)).map((f) => f.ruleId).sort();
  assert.deepEqual(ids("192.168.1.1"), ["net-admin-http", "net-vendor-cert"]);
  assert.deepEqual(ids("192.168.1.20"), ["net-admin-http", "net-printer-raw"]);
  assert.ok(ids("192.168.1.30").includes("net-setup-page"));
  assert.ok(ids("192.168.1.30").includes("net-camera-dvr"));
  assert.ok(ids("192.168.1.30").includes("net-upnp-forward"));
  assert.deepEqual(ids("192.168.1.40"), ["net-docker-port", "net-telnet"]); // something on 2375, not shown to be Docker
  assert.deepEqual(ids("192.168.1.41"), ["net-docker-api"]); // Docker names itself
  assert.deepEqual(ids("192.168.1.70"), []); // plain HTTP that sends you to HTTPS is fine
  assert.ok(res.findings.some((f) => f.ruleId === "net-upnp-on"));
  assert.ok(res.findings.find((f) => f.ruleId === "net-upnp-forward")!.internetFacing);
  assert.ok(res.checked.some((c) => c.startsWith("192.168.1.60")), "a device that only refuses still counts as there");
  assert.ok(!touched.has("192.168.1.99"), "excluded addresses are never touched");
  assert.ok([...touched].every((h) => h.startsWith("192.168.1.")));
});

test("network: public ranges and networks this computer isn't on are refused, unless listed as routed", async () => {
  const { io, touched } = fakeNet({ "10.9.0.5": { open: [23] } });
  const res = await runNetwork({ ranges: ["8.8.8.0/24", "10.9.0.0/28"] }, new ActivityLog(), { io, gapMs: 0 });
  assert.equal(touched.size, 0);
  assert.equal(res.skipped.length, 2);
  const routed = await runNetwork({ ranges: [], routed: ["10.9.0.0/28"] }, new ActivityLog(), { io, gapMs: 0 });
  assert.ok(routed.findings.some((f) => f.ruleId === "net-telnet"));
});

test("network: a router outside the approved ranges is never asked for its forwards", async () => {
  const { io } = fakeNet({}, { cidr: "192.168.1.50/28", upnp: { host: "192.168.1.1", mappings: [] } });
  const res = await runNetwork({ ranges: ["192.168.1.48/28"] }, new ActivityLog(), { io, gapMs: 0 });
  assert.ok(!res.findings.length);
  assert.match(res.skipped.map((s) => s.reason).join(" "), /outside the approved ranges/);
});

test("network: UPnP replies are read only from the router that answered", () => {
  const xml = `<root><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service></root>`;
  assert.equal(upnpService(xml, "http://192.168.1.1:5000/rootDesc.xml")!.control, "http://192.168.1.1:5000/ctl/IPConn");
  assert.equal(upnpService(xml.replace("/ctl/IPConn", "http://evil.example/x"), "http://192.168.1.1:5000/rootDesc.xml"), null);
  const m = parseMapping("<NewExternalPort>3389</NewExternalPort><NewInternalClient>192.168.1.9</NewInternalClient><NewInternalPort>3389</NewInternalPort><NewProtocol>TCP</NewProtocol><NewEnabled>1</NewEnabled>");
  assert.equal(m!.externalPort, 3389);
});

test("network: a device page that isn't admin equipment gets no plain-HTTP finding", () => {
  const { findings } = deviceFindings({ ip: "192.168.1.5", open: [80], pages: [{ port: 80, tls: false, page: { status: 200, title: "My blog" } }] });
  assert.equal(findings.length, 0);
});

test("network: every finding name is on the shared list, so counts aren't folded into other", () => {
  for (const a of NET_ALGORITHMS) assert.ok(MAP_ALGORITHMS.includes(a), a);
});

test("cloud keys: provider-held keys flagged, your own key in their key service noted, encryption off left to the main check", () => {
  const tf = `
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vault.arn
    }
  }
}
resource "aws_db_instance" "main" {
  storage_encrypted = true
}
resource "aws_db_instance" "off" {
  storage_encrypted = false
}
resource "google_storage_bucket" "files" {
  name = "files"
}
resource "aws_iam_role" "x" {}
`;
  const a = cloudKeyAdvice("infra/main.tf", tf);
  assert.deepEqual(a.map((x) => [x.resource, x.custody]), [
    ["aws_s3_bucket_server_side_encryption_configuration.logs", "provider"],
    ["aws_s3_bucket_server_side_encryption_configuration.vault", "provider-kms"],
    ["aws_db_instance.main", "provider"],
    ["google_storage_bucket.files", "provider"],
  ]);
  assert.equal(a[0].target, "infra/main.tf:2");
  const cfn = cloudKeyAdvice("stack.yaml", "AWSTemplateFormatVersion: 2010-09-09\n  SSEAlgorithm: AES256\n");
  assert.equal(cfn[0].custody, "provider");
});

test("people: optional answers, scored on their own, gaps most important first", () => {
  assert.equal(scorePeople({}), null);
  const answers = parseAnswers({ mfa: "no", backups: "yes", "printer-jobs": "unsure", "made-up": "no", phishing: "maybe" });
  assert.deepEqual(Object.keys(answers).sort(), ["backups", "mfa", "printer-jobs"]);
  const r = scorePeople(answers)!;
  assert.equal(r.answered, 3);
  assert.equal(r.inPlace, 1);
  assert.equal(r.gaps[0].id, "mfa");
  assert.equal(r.total, QUESTIONS.length);
  assert.ok(QUESTIONS.some((q) => q.id === "cloud-keys"));
  assert.deepEqual(["y", "No", "?", "", "x"].map(readAnswer), ["yes", "no", "unsure", null, null]);
});

test("map: network area and people answers in the report; neither addresses nor answers in the summary", async () => {
  const dir = mkdtempSync(join(tmpdir(), "qs-net-"));
  writeFileSync(join(dir, "main.tf"), 'resource "google_storage_bucket" "files" {\n  name = "files"\n}\n');
  const scope = { version: 1, created: "2026-11-20", areas: { code: { folders: ["."] }, network: { ranges: ["192.168.1.0/24"] } }, people: { answers: { mfa: "no", backups: "yes" } } };
  writeFileSync(join(dir, "quantum-scan.scope.json"), JSON.stringify(scope));
  assert.ok(!("error" in parseScope(JSON.stringify(scope))));
  const { io } = fakeNet(lan);
  const s = loadSettings(join(dir, "none.json"));
  const write = process.stdout.write;
  process.stdout.write = (() => true) as typeof process.stdout.write;
  const out = await runMap({ scopePath: join(dir, "quantum-scan.scope.json"), outDir: join(dir, "map"), cwd: dir, version: "0.0.0", settings: s, sharingOn: true, interactive: false, write: () => {}, network: { io, gapMs: 0 } }).finally(() => (process.stdout.write = write));
  assert.equal(out.code, 0);
  const html = readFileSync(join(dir, "map", "map.html"), "utf8");
  assert.match(html, /192\.168\.1\.40/);
  assert.match(html, /People and process/);
  assert.match(html, /Who can read your cloud data/);
  assert.equal(out.report!.people!.inPlace, 1);
  assert.equal(JSON.parse(readFileSync(join(dir, "map", "people.json"), "utf8")).answers.mfa, "no");
  const payload = buildPayload(out.facts!, s, "0.0.0", {}, "linux");
  const sent = JSON.stringify(payload);
  assert.doesNotMatch(sent, /192\.168|TP-Link|LaserJet|mfa|backups|files/);
  assert.ok(payload.areas.includes("network"));
  assert.equal(payload.rules["net-telnet"], "1");
  assert.equal(payload.rules["cloud-provider-held-keys"], "1");
  assert.ok(payload.algorithms["Telnet"]);
});
