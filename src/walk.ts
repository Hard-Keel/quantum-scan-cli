// Reads the files in a folder that the scanner looks at.

import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { shouldScan } from "./scan.ts";

export function walk(root: string, base = root, out: { path: string; content: string }[] = []) {
  for (const name of readdirSync(root)) {
    const full = join(root, name);
    const rel = relative(base, full).split("\\").join("/");
    // lstat: symbolic links are skipped, so a broken or looping link can't stop the scan.
    let st;
    try {
      st = lstatSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (name !== ".git" && shouldScan(`${rel}/x`)) walk(full, base, out);
    } else if (st.isFile() && st.size <= 1_000_000 && shouldScan(rel)) {
      out.push({ path: rel, content: readFileSync(full, "utf8") });
    }
  }
  return out;
}
