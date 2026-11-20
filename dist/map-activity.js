// Activity log: every connection and every file the encryption map reads, with time, target and reason.
// Written next to the report, so a customer can hand it to their security team.
import { appendFileSync } from "node:fs";
export class ActivityLog {
    entries = [];
    file;
    constructor(file) {
        this.file = file;
    }
    record(area, target, what) {
        const line = `${new Date().toISOString()}  ${area.padEnd(5)}  ${target}  ${what}`;
        this.entries.push(line);
        if (this.file) {
            try {
                appendFileSync(this.file, line + "\n");
            }
            catch {
                // the log in memory still goes into the report
            }
        }
    }
}
