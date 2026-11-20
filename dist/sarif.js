// SARIF 2.1.0 output, so GitHub code scanning (and other tools) can show findings.
import { shortLabel } from "./report.js";
const LEVEL = {
    secret: "error",
    "weak-now": "error",
    "quantum-vulnerable": "warning",
    exposed: "error",
};
/** One SARIF rule per kind of problem, like "weak-now/md5" or "secret/aws-access-key". */
function ruleId(f) {
    const label = shortLabel(f).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    return `${f.risk}/${label}`;
}
export function buildSarif(findings, toolVersion) {
    const rules = new Map();
    for (const f of findings) {
        const id = ruleId(f);
        if (!rules.has(id))
            rules.set(id, { id, name: shortLabel(f), shortDescription: { text: f.title }, help: { text: f.fix } });
    }
    return {
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "Hard Keel Quantum Scan",
                        version: toolVersion,
                        informationUri: "https://hardkeel.com",
                        rules: [...rules.values()],
                    },
                },
                results: findings.map((f) => ({
                    ruleId: ruleId(f),
                    level: LEVEL[f.risk],
                    message: { text: `${f.title}. ${f.fix}` },
                    locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: f.line } } }],
                })),
            },
        ],
    };
}
