// The permission card for each area: what it touches, what it reads, what it never does.
// Shown before an area runs. The answer is no unless the person says yes.

import type { AreaName } from "./share.ts";

export interface AreaCard {
  area: AreaName;
  title: string;
  touch: (targets: string[]) => string;
  read: string;
  never: string;
  cost: string;
  warning?: string;
}

const list = (t: string[]) => (t.length <= 4 ? t.join(", ") : `${t.slice(0, 3).join(", ")} and ${t.length - 3} more`);

export const CARDS: Record<"code" | "web" | "host", AreaCard> = {
  code: {
    area: "code",
    title: "Code and config",
    touch: (t) => `the files in ${list(t)}.`,
    read: "source code and infrastructure config, in memory, to find encryption, leaked keys and exposed settings.",
    never: "change a file, run any code, or send code anywhere.",
    cost: "Reads files only. No network connections.",
  },
  web: {
    area: "web",
    title: "Websites and public services",
    touch: (t) => `${t.length} address${t.length === 1 ? "" : "es"} (${list(t)}), each under a domain you proved you own with a DNS record.`,
    read: "the encryption each one offers when connecting, the same handshake a browser makes, and its certificate. For SSH addresses, the settings the server announces before any login.",
    never: "log in, test for vulnerabilities, send attack traffic, or touch any address you haven't proved.",
    cost: "About 6 connections per address, one at a time.",
  },
  host: {
    area: "host",
    title: "This machine",
    touch: () => "this computer only.",
    read: "SSH and TLS settings, Windows encryption settings, the machine's own certificates, and the type and size of public key files.",
    never: "change a setting, read a private key, or connect to anything.",
    cost: "Reads local settings only. No network connections.",
  },
};

export function cardText(card: AreaCard, targets: string[]): string {
  const lines = [
    card.title,
    `  What I'll touch: ${card.touch(targets)}`,
    `  What I read: ${card.read}`,
    `  What I never do: ${card.never}`,
    `  ${card.cost}`,
  ];
  if (card.warning) lines.push(`  ${card.warning}`);
  return lines.join("\n");
}
