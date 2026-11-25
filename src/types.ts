// Shared types for the Hard Keel quantum-readiness scanner.

import type { InventoryItem } from "./inventory.ts";
import type { PqcSignal } from "./pqc.ts";

export type Risk =
  | "quantum-vulnerable" // safe today, broken by a large quantum computer (Shor)
  | "weak-now" // already broken or deprecated today
  | "secret" // a leaked credential
  | "exposed"; // an infrastructure setting that exposes data: encryption off, open to the internet

export type Severity = "critical" | "high" | "medium" | "low";

export type Primitive =
  | "key-agreement"
  | "public-key-encryption"
  | "signature"
  | "hash"
  | "block-cipher"
  | "stream-cipher"
  | "protocol"
  | "credential"
  | "setting";

export interface Finding {
  kind: "crypto" | "secret" | "config";
  ruleId: string;
  title: string;
  algorithm: string; // e.g. "RSA", "ECDSA", "MD5", "AWS access key"
  primitive: Primitive;
  risk: Risk;
  severity: Severity;
  file: string;
  line: number; // 1-based
  snippet: string; // trimmed source line, secrets masked
  fix: string; // what to migrate to
  keySize?: number;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
  pqc: PqcSignal[]; // post-quantum encryption already in use, for the readiness score
  inventory: InventoryItem[]; // every other algorithm in use (AES, SHA-2, ...), for the CBOM; never scored
}
