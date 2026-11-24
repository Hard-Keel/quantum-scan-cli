import { test } from "node:test";
import assert from "node:assert/strict";
import { ctDomain, ctUrl, hostsFromCt, hostsText, lookupCt, type CtFetch } from "../src/map-ct.ts";
import { hostsCommand } from "../src/cli.ts";
import { loadSettings } from "../src/share-config.ts";

const NOW = Date.parse("2026-11-23T00:00:00Z");
const rows = [
  { name_value: "example.com\nwww.example.com", not_after: "2027-02-01T00:00:00" },
  { name_value: "*.api.example.com", not_after: "2027-01-01T00:00:00" },
  { name_value: "staging.example.com", not_after: "2026-06-01T00:00:00" }, // expired this year
  { name_value: "ancient.example.com", not_after: "2019-01-01T00:00:00" }, // expired long ago
  { name_value: "www.example.com", not_after: "2025-01-01T00:00:00" }, // also on an old cert: still current
  { name_value: "admin@example.com\nexample.com.evil.net\nnotexample.com\n10.0.0.1", not_after: "2027-01-01T00:00:00" },
];

test("ct: keeps only names under the domain, splits current from recently expired", () => {
  const h = hostsFromCt("example.com", rows, NOW);
  assert.deepEqual(h.current, ["example.com", "api.example.com", "www.example.com"]);
  assert.deepEqual(h.recentlyExpired, ["staging.example.com"]);
});

test("ct: domain input is cleaned and IPs or junk are refused", () => {
  assert.equal(ctDomain("https://Example.COM/path"), "example.com");
  assert.equal(ctDomain("*.example.com"), "example.com");
  assert.equal(ctDomain("example.com:8443"), "example.com");
  assert.equal(ctDomain("10.0.0.1"), null);
  assert.equal(ctDomain("not a domain"), null);
  assert.equal(ctDomain("."), null);
  assert.equal(ctUrl("example.com"), "https://crt.sh/?q=%25.example.com&output=json");
});

test("ct: one request to crt.sh, plain user agent, nothing personal", async () => {
  const seen: { url: string; headers: Record<string, string> }[] = [];
  const f: CtFetch = async (url, init) => {
    seen.push({ url, headers: init.headers });
    return { ok: true, status: 200, text: async () => JSON.stringify([{ name_value: "api.example.com", not_after: "2099-01-01T00:00:00" }]) };
  };
  const r = await lookupCt("example.com", "9.9.9", f);
  assert.equal(seen.length, 1);
  assert.equal(new URL(seen[0].url).host, "crt.sh");
  assert.deepEqual(Object.keys(seen[0].headers).sort(), ["accept", "user-agent"]);
  assert.equal(seen[0].headers["user-agent"], "hardkeel-quantum-scan/9.9.9");
  assert.ok(!("error" in r));
  if (!("error" in r)) assert.deepEqual(r.current, ["example.com", "api.example.com"]); // the domain itself is always listed
});

test("ct: a busy or broken crt.sh gives a plain error", async () => {
  const busy: CtFetch = async () => ({ ok: false, status: 502, text: async () => "" });
  assert.match(String((await lookupCt("example.com", "1", busy) as { error: string }).error), /502/);
  const html: CtFetch = async () => ({ ok: true, status: 200, text: async () => "<html>busy</html>" });
  assert.ok("error" in (await lookupCt("example.com", "1", html)));
  const down: CtFetch = async () => {
    throw new Error("getaddrinfo ENOTFOUND crt.sh");
  };
  assert.match(String((await lookupCt("example.com", "1", down) as { error: string }).error), /couldn't reach crt\.sh/);
});

test("ct: text says nothing was contacted and gives a list to paste into map", () => {
  const h = hostsFromCt("example.com", rows, NOW);
  const t = hostsText(h, false);
  assert.match(t, /3 with a current certificate/);
  assert.match(t, /None of these hosts were contacted/);
  assert.match(t, /1 more appear only on certificates that expired/);
  assert.match(t, /^ {2}example\.com api\.example\.com www\.example\.com$/m);
  assert.doesNotMatch(t, /staging/);
  assert.match(hostsText(h, true), /staging\.example\.com/);
});

test("ct: the hosts command sends nothing in offline mode", async () => {
  let called = false;
  const f: CtFetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => "[]" };
  };
  const err = console.error;
  const msgs: string[] = [];
  console.error = (m: string) => msgs.push(m);
  try {
    const code = await hostsCommand(["example.com", "--offline"], loadSettings(), f);
    assert.equal(code, 2);
    assert.equal(called, false);
    assert.match(msgs.join(" "), /Offline mode is on/);
    assert.equal(await hostsCommand([], loadSettings(), f), 2);
  } finally {
    console.error = err;
  }
});

test("ct: the hosts command prints JSON with --json", async () => {
  const f: CtFetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify([{ name_value: "a.example.com", not_after: "2099-01-01T00:00:00" }]) });
  const out = process.stdout.write.bind(process.stdout);
  let text = "";
  process.stdout.write = ((c: string) => ((text += c), true)) as typeof process.stdout.write;
  try {
    assert.equal(await hostsCommand(["--json", "example.com"], loadSettings(), f), 0);
  } finally {
    process.stdout.write = out;
  }
  const j = JSON.parse(text);
  assert.deepEqual(j.current, ["example.com", "a.example.com"]);
});
