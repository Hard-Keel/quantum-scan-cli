// Network and connected equipment: finds what on your own network is exposed or left at its
// defaults. Routers, switches, printers, cameras, storage boxes and smart devices.
//
// Look only. For each address in the approved ranges it checks whether about 30 common ports
// answer, reads the title of any web page they serve and the certificate on secure admin pages,
// and reads the router's list of automatic port forwards (UPnP) if it publishes one.
// It never logs in, tries a password, sends commands to equipment or changes a setting.
//
// Ownership: only private address ranges. A range must be one this computer is connected to,
// unless the person lists it separately as another segment of their own network.
// At most 1,024 addresses per run, one connection at a time per device.
import { createSocket } from "node:dgram";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect } from "node:net";
import { networkInterfaces } from "node:os";
import { connect as tlsConnect } from "node:tls";
import { emptyResult } from "./map-types.js";
export const MAX_NETWORK_ADDRESSES = 1024;
// ---------- addresses ----------
export function ipToInt(ip) {
    const m = ip.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m)
        return null;
    const o = m.slice(1).map(Number);
    if (o.some((x) => x > 255))
        return null;
    return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}
export const intToIp = (n) => [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
/** A network this computer is on, as its interface reports it (any size, e.g. 10.0.0.0/8). */
export function parseCidr(raw) {
    const [ip, bitsRaw] = raw.trim().split("/");
    const base = ipToInt(ip);
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32)
        return null;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const start = (base & mask) >>> 0;
    return { label: raw.trim(), start, end: (start | (~mask >>> 0)) >>> 0 };
}
/** The networks this computer is on. Larger than the /20 limit is fine here: it only decides what counts as "on this network". */
export const machineRanges = (io) => io.interfaces().map((i) => parseCidr(i.cidr)).filter((r) => r !== null);
/** "192.168.1.0/24" or a single address. Only /20 or smaller. */
export function parseRange(raw) {
    const t = raw.trim();
    const [ip, bitsRaw] = t.split("/");
    const base = ipToInt(ip);
    if (base === null)
        return { error: "not an IPv4 address or range" };
    const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32)
        return { error: "not a valid range" };
    if (bits < 20)
        return { error: "too large; list ranges of /20 (4,096 addresses) or smaller" };
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const start = (base & mask) >>> 0;
    const end = (start | (~mask >>> 0)) >>> 0;
    return { label: t, start, end };
}
const PRIVATE = [
    [ipToInt("10.0.0.0"), ipToInt("10.255.255.255")],
    [ipToInt("172.16.0.0"), ipToInt("172.31.255.255")],
    [ipToInt("192.168.0.0"), ipToInt("192.168.255.255")],
];
export const isPrivateRange = (r) => PRIVATE.some(([a, b]) => r.start >= a && r.end <= b);
/** Addresses in a range, leaving out the network and broadcast addresses of a /30 or larger. */
export function hostsOf(r) {
    const out = [];
    const size = r.end - r.start + 1;
    const from = size > 2 ? r.start + 1 : r.start;
    const to = size > 2 ? r.end - 1 : r.end;
    for (let n = from; n <= to; n++)
        out.push(n);
    return out;
}
/** About 30 ports. Chosen for what they reveal about equipment, not to sweep everything. */
export const PORTS = [
    { port: 21, name: "FTP", role: "plain" },
    { port: 22, name: "SSH", role: "remote" },
    { port: 23, name: "Telnet", role: "plain" },
    { port: 80, name: "HTTP", role: "web" },
    { port: 443, name: "HTTPS", role: "web-tls" },
    { port: 515, name: "LPD printing", role: "printer" },
    { port: 554, name: "RTSP video stream", role: "camera" },
    { port: 631, name: "IPP printing", role: "printer" },
    { port: 1883, name: "MQTT", role: "iot" },
    { port: 2375, name: "Docker API", role: "service" },
    { port: 3389, name: "Remote Desktop", role: "remote" },
    { port: 4443, name: "HTTPS (alt)", role: "web-tls" },
    { port: 5000, name: "HTTP (alt)", role: "web" },
    { port: 5001, name: "HTTPS (alt)", role: "web-tls" },
    { port: 5900, name: "VNC", role: "remote" },
    { port: 5901, name: "VNC", role: "remote" },
    { port: 5938, name: "TeamViewer", role: "remote" },
    { port: 6379, name: "Redis", role: "service" },
    { port: 7070, name: "AnyDesk", role: "remote" },
    { port: 8000, name: "HTTP (alt)", role: "web" },
    { port: 8040, name: "ScreenConnect", role: "remote" },
    { port: 8080, name: "HTTP (alt)", role: "web" },
    { port: 8081, name: "HTTP (alt)", role: "web" },
    { port: 8443, name: "HTTPS (alt)", role: "web-tls" },
    { port: 8888, name: "HTTP (alt)", role: "web" },
    { port: 9100, name: "Raw printing", role: "printer" },
    { port: 9200, name: "Elasticsearch", role: "service" },
    { port: 27017, name: "MongoDB", role: "service" },
    { port: 34567, name: "DVR service", role: "camera" },
    { port: 37777, name: "DVR service", role: "camera" },
];
/** Ports tried first to see whether anything is at an address. A refused connection counts as there. */
export const LIVE_PORTS = [80, 443, 22, 445, 139, 3389, 9100, 554, 8080, 5000];
const CLASS_PATTERNS = [
    ["printer", /printer|laserjet|officejet|deskjet|pagewide|embedded web server|\bews\b|brother|epson|canon|xerox|ricoh|kyocera|lexmark|konica|bizhub|sharp mx|cups/i],
    ["camera", /camera|ipcam|ip cam|hikvision|dahua|amcrest|reolink|foscam|\bnvr\b|\bdvr\b|netsurveillance|xmeye|axis communications|lorex|swann/i],
    ["storage", /synology|diskstation|qnap|truenas|freenas|unraid|readynas|\bnas\b|my cloud/i],
    ["router", /router|gateway|switch|access point|ubiquiti|unifi|edgeos|edgerouter|mikrotik|routeros|netgear|tp-?link|linksys|\basus\b|d-link|zyxel|draytek|fortigate|fortinet|sonicwall|pfsense|opnsense|openwrt|dd-wrt|cisco|aruba|meraki|juniper|eero|orbi|arris|technicolor|sagemcom|xfinity|airport|omada|ruckus/i],
    ["smart device", /home assistant|philips hue|hue bridge|sonos|shelly|tasmota|esphome|smartthings|homebridge|ecobee|nest|tuya|roku|chromecast/i],
];
export function classify(text, ports) {
    for (const [c, re] of CLASS_PATTERNS)
        if (re.test(text))
            return c;
    if (ports.some((p) => p === 9100 || p === 631 || p === 515))
        return "printer";
    if (ports.some((p) => p === 554 || p === 37777 || p === 34567))
        return "camera";
    return null;
}
const SETUP_PAGE = /setup wizard|first[- ]?time setup|initial (setup|configuration)|quick setup|getting started|welcome to (the )?setup|create (an )?admin|set (the |an )?admin(istrator)? password|device activation|activate (your )?device|out of box/i;
const VENDOR_CERT = /ubiquiti|unifi|fortinet|fortigate|sonicwall|synology|qnap|hikvision|dahua|tp-?link|netgear|linksys|asus|d-link|zyxel|draytek|mikrotik|pfsense|opnsense|cisco|aruba|meraki|juniper|hewlett|\bhp\b|brother|epson|canon|xerox|ricoh|kyocera|lexmark|axis|router|default|localhost|self-?signed|example/i;
const UA = "HardKeelQuantumScan/1 (look-only; https://hardkeel.com/quantum-scan/)";
function readBody(res, max = 65536) {
    return new Promise((resolve) => {
        let buf = "";
        res.setEncoding?.("utf8");
        res.on("data", (c) => {
            buf += c;
            if (buf.length > max)
                res.destroy();
        });
        res.on("end", () => resolve(buf));
        res.on("close", () => resolve(buf));
        res.on("error", () => resolve(buf));
    });
}
export function pageTitle(html) {
    const m = html.match(/<title[^>]*>([\s\S]{0,300}?)<\/title>/i);
    const t = m?.[1]
        .replace(/<[^>]+>/g, "")
        .replace(/&amp;/g, "&")
        .replace(/&nbsp;|&#160;/g, " ")
        .replace(/\s+/g, " ")
        .trim();
    return t ? t.slice(0, 80) : undefined;
}
function getText(url, timeoutMs = 3000, method = "GET", body, headers = {}) {
    return new Promise((resolve) => {
        let u;
        try {
            u = new URL(url);
        }
        catch {
            return resolve(null);
        }
        const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(u, { method, headers: { "user-agent": UA, ...headers }, timeout: timeoutMs, rejectUnauthorized: false }, async (res) => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: await readBody(res) }));
        req.on("timeout", () => req.destroy());
        req.on("error", () => resolve(null));
        if (body)
            req.write(body);
        req.end();
    });
}
export const realNetIO = {
    interfaces() {
        const out = [];
        for (const list of Object.values(networkInterfaces()))
            for (const i of list ?? [])
                if (i.family === "IPv4" && !i.internal && i.cidr)
                    out.push({ address: i.address, cidr: i.cidr });
        return out;
    },
    probe(host, port, timeoutMs) {
        return new Promise((resolve) => {
            const s = netConnect({ host, port });
            const done = (r) => {
                s.removeAllListeners();
                s.destroy();
                resolve(r);
            };
            s.setTimeout(timeoutMs, () => done("timeout"));
            s.once("connect", () => done("open"));
            s.once("error", (e) => done(e.code === "ECONNREFUSED" ? "closed" : "error"));
        });
    },
    async http(host, port, tls) {
        const r = await getText(`${tls ? "https" : "http"}://${host}:${port}/`);
        if (!r)
            return null;
        const one = (v) => (Array.isArray(v) ? v[0] : v);
        return { status: r.status, location: one(r.headers.location), server: one(r.headers.server)?.slice(0, 80), title: pageTitle(r.body) };
    },
    cert(host, port) {
        return new Promise((resolve) => {
            const s = tlsConnect({ host, port, rejectUnauthorized: false, timeout: 3000 });
            const done = (v) => {
                s.removeAllListeners();
                s.destroy();
                resolve(v);
            };
            s.once("secureConnect", () => {
                const c = s.getPeerX509Certificate();
                done(c ? { subject: c.subject.replace(/\n/g, ", "), issuer: c.issuer.replace(/\n/g, ", "), selfSigned: c.checkIssued(c) } : null);
            });
            s.once("timeout", () => done(null));
            s.once("error", () => done(null));
        });
    },
    async upnp(allowed) {
        const location = await ssdpLocation();
        if (!location)
            return null;
        return readUpnp(location, allowed);
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
};
/**
 * Reads the port-forward list from the router that answered. The answer names its own address, and any
 * device on the network can answer, so the address must be a plain IPv4 address inside the approved ranges
 * before anything is fetched from it.
 */
export async function readUpnp(location, allowed) {
    let host;
    try {
        host = new URL(location).hostname;
    }
    catch {
        return { host: "unknown", mappings: [], outside: true };
    }
    if (ipToInt(host) === null || !allowed(host))
        return { host, mappings: [], outside: true };
    const desc = await getText(location);
    if (!desc)
        return { host, mappings: [] };
    const svc = upnpService(desc.body, location);
    if (!svc)
        return { host, mappings: [] };
    const mappings = [];
    for (let i = 0; i < 64; i++) {
        const body = `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="${svc.type}"><NewPortMappingIndex>${i}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>`;
        const r = await getText(svc.control, 3000, "POST", body, { "content-type": 'text/xml; charset="utf-8"', soapaction: `"${svc.type}#GetGenericPortMappingEntry"` });
        if (!r || r.status !== 200)
            break;
        const m = parseMapping(r.body);
        if (!m)
            break;
        mappings.push(m);
    }
    return { host, mappings };
}
/** Asks the local network, once, whether a router offers UPnP. Read only: M-SEARCH is a question. */
function ssdpLocation(timeoutMs = 2500) {
    return new Promise((resolve) => {
        const sock = createSocket({ type: "udp4", reuseAddr: true });
        const done = (v) => {
            clearTimeout(timer);
            try {
                sock.close();
            }
            catch {
                // already closed
            }
            resolve(v);
        };
        const timer = setTimeout(() => done(null), timeoutMs);
        sock.on("error", () => done(null));
        sock.on("message", (msg) => {
            const loc = msg.toString("utf8").match(/^location:\s*(\S+)/im)?.[1];
            if (loc && /^http:\/\//i.test(loc))
                done(loc);
        });
        const q = ["M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900", 'MAN: "ssdp:discover"', "MX: 2", "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1", "", ""].join("\r\n");
        sock.send(q, 1900, "239.255.255.250", (e) => e && done(null));
    });
}
export function upnpService(xml, location) {
    const services = xml.match(/<service>[\s\S]*?<\/service>/gi) ?? [];
    for (const s of services) {
        const type = s.match(/<serviceType>\s*([^<]+?)\s*<\/serviceType>/i)?.[1];
        const control = s.match(/<controlURL>\s*([^<]+?)\s*<\/controlURL>/i)?.[1];
        if (type && control && /WAN(IP|PPP)Connection/i.test(type)) {
            try {
                const url = new URL(control, location);
                // Only ever talk to the router that answered.
                if (url.hostname !== new URL(location).hostname)
                    return null;
                return { type, control: url.toString() };
            }
            catch {
                return null;
            }
        }
    }
    return null;
}
export function parseMapping(xml) {
    const v = (tag) => xml.match(new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`, "i"))?.[1];
    const ext = Number(v("NewExternalPort"));
    const int = Number(v("NewInternalPort"));
    const client = v("NewInternalClient");
    if (!Number.isInteger(ext) || !client)
        return null;
    return { externalPort: ext, internalClient: client, internalPort: Number.isInteger(int) ? int : ext, protocol: (v("NewProtocol") ?? "").toUpperCase().slice(0, 4), description: (v("NewPortMappingDescription") ?? "").slice(0, 60), enabled: v("NewEnabled") !== "0" };
}
export const NET_RULES = {
    telnet: { ruleId: "net-telnet", algorithm: "Telnet", severity: "high", primitive: "protocol", title: "Telnet is open: logins cross the network in plain text", fix: "Turn Telnet off and use SSH instead." },
    ftp: { ruleId: "net-ftp", algorithm: "Plain FTP", severity: "medium", primitive: "protocol", title: "FTP is open: files and passwords cross the network unencrypted", fix: "Turn FTP off, or switch to SFTP." },
    rdp: { ruleId: "net-rdp", algorithm: "Remote Desktop open", severity: "high", title: "Remote Desktop is open on the network", fix: "Allow Remote Desktop only through a VPN or a gateway with multi-factor sign-in, and only from admin machines." },
    vnc: { ruleId: "net-vnc", algorithm: "VNC open", severity: "high", title: "VNC screen sharing is open", fix: "Turn VNC off, or limit it to admin machines with a strong password and encryption." },
    remoteTool: { ruleId: "net-remote-tool", algorithm: "Remote support tool", severity: "medium", title: "A remote support tool is listening", fix: "Check who installed it. Remove it if it isn't in use, and require multi-factor sign-in on its account." },
    setupPage: { ruleId: "net-setup-page", algorithm: "Setup page open", severity: "critical", title: "A device is still on its first-time setup page", fix: "Finish setup and set a strong admin password now. Until then, anyone on the network can take this device over." },
    adminHttp: { ruleId: "net-admin-http", algorithm: "Admin page over plain HTTP", severity: "medium", title: "Admin page served without encryption", fix: "Use only the HTTPS admin page and turn off HTTP admin access. Keep admin pages reachable from an admin network only." },
    vendorCert: { ruleId: "net-vendor-cert", algorithm: "Vendor default certificate", severity: "low", title: "Admin page uses the factory certificate", fix: "Replace the factory certificate with one from your own certificate authority, so staff can tell the real admin page from a fake." },
    printRaw: { ruleId: "net-printer-raw", algorithm: "Open print port", severity: "medium", title: "Anyone on the network can send jobs to this printer, and many printers keep copies of past jobs", fix: "Route printing through a print server, close raw port 9100 if it isn't needed, and turn off stored jobs or set them to wipe automatically." },
    printLpd: { ruleId: "net-printer-lpd", algorithm: "LPD printing", severity: "low", title: "Old LPD printing is turned on", fix: "Turn off LPD and use IPP over TLS or a print server." },
    rtsp: { ruleId: "net-camera-stream", algorithm: "Camera stream port", severity: "medium", title: "A video stream port is open", fix: "Put cameras on their own network, change any default password, and turn off streams you don't use." },
    dvr: { ruleId: "net-camera-dvr", algorithm: "DVR service port", severity: "high", title: "A camera recorder's service port is open. These ports have a long record of break-ins", fix: "Update the recorder's firmware, put it on its own network, and block this port from staff and guest networks." },
    mqtt: { ruleId: "net-mqtt", algorithm: "MQTT without encryption", severity: "medium", primitive: "protocol", title: "Smart-device messages (MQTT) travel unencrypted", fix: "Use MQTT over TLS (port 8883) with a password for each device." },
    dockerPort: { ruleId: "net-docker-port", algorithm: "Docker API port open", severity: "medium", title: "Something answers on the Docker API port (2375). If it's Docker, anyone who reaches it controls the machine", fix: "Check what listens on port 2375. If it's Docker, bind it to the local socket only, or require TLS with client certificates." },
    docker: { ruleId: "net-docker-api", algorithm: "Docker API open", severity: "critical", title: "The Docker API is open without encryption: anyone who reaches it controls the machine", fix: "Bind Docker to the local socket only, or require TLS with client certificates." },
    database: { ruleId: "net-database-open", algorithm: "Database open on the network", severity: "high", title: "A database answers on the network", fix: "Bind it to localhost or a private app network, and require a password and TLS." },
    upnpOn: { ruleId: "net-upnp-on", algorithm: "UPnP on the router", severity: "low", title: "The router lets any device open ports to the internet (UPnP)", fix: "Turn UPnP off on the router unless a device truly needs it." },
    upnpForward: { ruleId: "net-upnp-forward", algorithm: "Router forward from the internet", severity: "high", internetFacing: true, title: "The router forwards a port from the internet to a device", fix: "Remove forwards you don't need. If a device must be reachable from outside, use a VPN instead." },
};
export const NET_ALGORITHMS = Object.values(NET_RULES).map((r) => r.algorithm);
function finding(rule, target, extraTitle = "") {
    return {
        area: "network",
        target,
        ruleId: rule.ruleId,
        title: rule.title + extraTitle,
        algorithm: rule.algorithm,
        primitive: rule.primitive ?? "setting",
        risk: "exposed",
        severity: rule.severity,
        fix: rule.fix,
        internetFacing: rule.internetFacing ?? false,
    };
}
/** What one device's open ports and pages say, as findings. Pure, so it can be tested. */
export function deviceFindings(d) {
    const text = d.pages.filter((p) => p.port !== 2375).map((p) => `${p.page?.title ?? ""} ${p.page?.server ?? ""} ${p.cert?.subject ?? ""}`).join(" ");
    const cls = classify(text, d.open);
    const title = d.pages.map((p) => p.page?.title).find(Boolean);
    const label = cls ? `${cls}${title ? `: ${title}` : ""}` : (title ?? "");
    const at = (port) => `${d.ip}:${port}${label ? ` (${label})` : ""}`;
    const out = [];
    const has = (p) => d.open.includes(p);
    if (has(23))
        out.push(finding(NET_RULES.telnet, at(23)));
    if (has(21))
        out.push(finding(NET_RULES.ftp, at(21)));
    if (has(3389))
        out.push(finding(NET_RULES.rdp, at(3389)));
    for (const p of [5900, 5901])
        if (has(p))
            out.push(finding(NET_RULES.vnc, at(p)));
    for (const p of [5938, 7070, 8040])
        if (has(p))
            out.push(finding(NET_RULES.remoteTool, at(p), ` (${PORTS.find((x) => x.port === p).name})`));
    if (has(9100))
        out.push(finding(NET_RULES.printRaw, at(9100)));
    if (has(515))
        out.push(finding(NET_RULES.printLpd, at(515)));
    if (has(554))
        out.push(finding(NET_RULES.rtsp, at(554)));
    for (const p of [34567, 37777])
        if (has(p))
            out.push(finding(NET_RULES.dvr, at(p)));
    if (has(1883))
        out.push(finding(NET_RULES.mqtt, at(1883)));
    if (has(2375)) {
        const peek = d.pages.find((p) => p.port === 2375)?.page;
        out.push(finding(peek && /docker/i.test(`${peek.server ?? ""}`) ? NET_RULES.docker : NET_RULES.dockerPort, at(2375)));
    }
    for (const p of [6379, 9200, 27017])
        if (has(p))
            out.push(finding(NET_RULES.database, at(p), ` (${PORTS.find((x) => x.port === p).name})`));
    let setup = false;
    for (const pg of d.pages.filter((x) => x.port !== 2375)) {
        const t = `${pg.page?.title ?? ""}`;
        if (!setup && SETUP_PAGE.test(t)) {
            setup = true;
            out.push(finding(NET_RULES.setupPage, at(pg.port)));
        }
        const redirectsToTls = pg.page && pg.page.status >= 300 && pg.page.status < 400 && /^https:/i.test(pg.page.location ?? "");
        if (!pg.tls && pg.page && !redirectsToTls && cls && cls !== "smart device")
            out.push(finding(NET_RULES.adminHttp, at(pg.port)));
        if (pg.tls && pg.cert && pg.cert.selfSigned && (VENDOR_CERT.test(pg.cert.subject) || /CN=(\d{1,3}\.){3}\d{1,3}\b/.test(pg.cert.subject) || !/CN=/.test(pg.cert.subject)))
            out.push(finding(NET_RULES.vendorCert, at(pg.port)));
    }
    // One plain-HTTP admin finding per device is enough.
    const firstHttp = out.findIndex((f) => f.ruleId === NET_RULES.adminHttp.ruleId);
    return { findings: out.filter((f, i) => f.ruleId !== NET_RULES.adminHttp.ruleId || i === firstHttp), label };
}
export function upnpFindings(host, mappings) {
    const out = [finding(NET_RULES.upnpOn, `${host} (router)`)];
    for (const m of mappings.filter((x) => x.enabled)) {
        out.push(finding(NET_RULES.upnpForward, `internet port ${m.externalPort}/${m.protocol || "TCP"} -> ${m.internalClient}:${m.internalPort}${m.description ? ` (${m.description})` : ""}`));
    }
    return out;
}
// ---------- the run ----------
async function pool(items, n, fn) {
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
        while (i < items.length)
            await fn(items[i++]);
    }));
}
export async function runNetwork(scope, log, o = {}) {
    const io = o.io ?? realNetIO;
    const gap = o.gapMs ?? 250;
    const res = emptyResult("network");
    const mine = machineRanges(io);
    const onThisMachine = (r) => mine.some((m) => r.start >= m.start && r.end <= m.end);
    const ranges = [];
    for (const [raw, routed] of [...(scope.ranges ?? []).map((r) => [r, false]), ...(scope.routed ?? []).map((r) => [r, true])]) {
        const r = parseRange(raw);
        if ("error" in r)
            res.skipped.push({ target: raw, reason: r.error });
        else if (!isPrivateRange(r))
            res.skipped.push({ target: raw, reason: "not a private address range, so it can't be your own internal network" });
        else if (!routed && !onThisMachine(r))
            res.skipped.push({ target: raw, reason: "this computer isn't connected to that network. If it's another segment of your own network, list it under routed" });
        else
            ranges.push(r);
    }
    const excluded = (scope.exclude ?? []).map(parseRange).filter((r) => !("error" in r));
    const isExcluded = (n) => excluded.some((r) => n >= r.start && n <= r.end);
    let hosts = [...new Set(ranges.flatMap(hostsOf))].filter((n) => !isExcluded(n));
    if (hosts.length > MAX_NETWORK_ADDRESSES) {
        res.skipped.push({ target: `${(hosts.length - MAX_NETWORK_ADDRESSES).toLocaleString("en-US")} addresses from ${intToIp(hosts[MAX_NETWORK_ADDRESSES])} on`, reason: `one run checks the first ${MAX_NETWORK_ADDRESSES.toLocaleString("en-US")} addresses. Run again with the rest listed as their own ranges` });
        hosts = hosts.slice(0, MAX_NETWORK_ADDRESSES);
    }
    if (excluded.length)
        res.skipped.push({ target: (scope.exclude ?? []).join(", "), reason: "excluded in the scope file" });
    if (!hosts.length)
        return res;
    const allowed = new Set(hosts.map(intToIp));
    // 1. Which addresses have something at them.
    const live = [];
    await pool(hosts.map(intToIp), 32, async (ip) => {
        log.record("network", ip, "checked whether anything answers");
        for (const port of LIVE_PORTS) {
            const s = await io.probe(ip, port, o.liveTimeoutMs ?? 400);
            if (s === "open" || s === "closed") {
                live.push(ip);
                return;
            }
        }
    });
    live.sort((a, b) => ipToInt(a) - ipToInt(b));
    // 2. Each device, one connection at a time.
    await pool(live, 8, async (ip) => {
        const open = [];
        log.record("network", ip, `checked whether ${PORTS.length} common ports answer`);
        for (const p of PORTS) {
            if ((await io.probe(ip, p.port, o.portTimeoutMs ?? 800)) === "open")
                open.push(p.port);
            await io.sleep(gap);
        }
        const pages = [];
        for (const p of PORTS.filter((x) => open.includes(x.port) && (x.role === "web" || x.role === "web-tls"))) {
            const tls = p.role === "web-tls";
            log.record("network", `${ip}:${p.port}`, tls ? "read the page title and certificate" : "read the page title");
            const page = await io.http(ip, p.port, tls);
            const cert = tls ? await io.cert(ip, p.port) : undefined;
            pages.push({ port: p.port, tls, page, cert });
            await io.sleep(gap);
        }
        if (open.includes(2375)) {
            // Docker names itself in a response header. One plain GET of the front page, nothing else.
            log.record("network", `${ip}:2375`, "read the response headers to see whether it's Docker");
            pages.push({ port: 2375, tls: false, page: await io.http(ip, 2375, false) });
        }
        const { findings, label } = deviceFindings({ ip, open, pages });
        res.findings.push(...findings);
        res.checked.push(`${ip}${label ? ` (${label})` : ""}: ${open.length ? open.map((p) => PORTS.find((x) => x.port === p).name).filter((v, i, a) => a.indexOf(v) === i).join(", ") : "no common ports open"}`);
    });
    // 3. The router's automatic port forwards, only when the router is inside the approved ranges.
    log.record("network", "local network", "asked whether a router offers UPnP");
    const u = await io.upnp((h) => allowed.has(h));
    if (u && !u.outside && allowed.has(u.host)) {
        log.record("network", u.host, `read the router's port-forward list (${u.mappings.length})`);
        res.findings.push(...upnpFindings(u.host, u.mappings));
    }
    else if (u) {
        res.skipped.push({ target: u.host, reason: "a router answered for UPnP, but it's outside the approved ranges" });
    }
    res.checked.sort((a, b) => ipToInt(a.split(/[ :]/)[0]) - ipToInt(b.split(/[ :]/)[0]));
    return res;
}
/** The /24 networks this computer is on, to suggest when asking. */
export function suggestedRanges(io = realNetIO) {
    const out = new Set();
    for (const i of io.interfaces()) {
        const r = parseCidr(i.cidr);
        const n = ipToInt(i.address);
        if (!r || n === null)
            continue;
        // On a big network (a /16, say), suggest the /24 around this computer.
        const around = r.end - r.start + 1 >= 256 ? { label: "", start: (n & 0xffffff00) >>> 0, end: ((n & 0xffffff00) >>> 0) + 255 } : r;
        if (!isPrivateRange(around))
            continue;
        out.add(around === r ? `${intToIp(r.start)}/${32 - Math.log2(r.end - r.start + 1)}` : `${intToIp(around.start)}/24`);
    }
    return [...out];
}
