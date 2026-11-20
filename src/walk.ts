// Reads the files in a folder that the scanner looks at.
// A folder or file that can't be read (no permission, removed mid-scan) is noted and skipped,
// so one locked folder can't stop the whole scan.

import { existsSync, lstatSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { shouldScan } from "./scan.ts";

export interface WalkResult {
  files: { path: string; content: string }[];
  unreadable: { path: string; reason: string }[]; // relative paths, local report only
}

function reasonOf(e: unknown): string {
  const code = String((e as { code?: string })?.code ?? "");
  if (code === "EACCES" || code === "EPERM") return "permission denied";
  if (code === "ENOENT") return "removed during the scan";
  return code || (e instanceof Error ? e.message : String(e));
}

/** Throws a plain-English error when the folder itself is missing or isn't a folder. */
export function walkFolder(root: string): WalkResult {
  if (!existsSync(root)) throw new Error(`Can't scan ${root}: that folder doesn't exist.`);
  if (!statSync(root).isDirectory()) throw new Error(`Can't scan ${root}: that's a file, not a folder.`);
  const res: WalkResult = { files: [], unreadable: [] };
  const visit = (dir: string) => {
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch (e) {
      if (dir === root) throw new Error(`Can't scan ${root}: ${reasonOf(e)}.`);
      res.unreadable.push({ path: relative(root, dir).split("\\").join("/") + "/", reason: reasonOf(e) });
      return;
    }
    for (const name of names) {
      const full = join(dir, name);
      const rel = relative(root, full).split("\\").join("/");
      // lstat: symbolic links are skipped, so a broken or looping link can't stop the scan.
      let st;
      try {
        st = lstatSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        if (name !== ".git" && shouldScan(`${rel}/x`)) visit(full);
      } else if (st.isFile() && st.size <= 1_000_000 && shouldScan(rel)) {
        try {
          res.files.push({ path: rel, content: readFileSync(full, "utf8") });
        } catch (e) {
          res.unreadable.push({ path: rel, reason: reasonOf(e) });
        }
      }
    }
  };
  visit(root);
  return res;
}

export function walk(root: string): { path: string; content: string }[] {
  return walkFolder(root).files;
}
