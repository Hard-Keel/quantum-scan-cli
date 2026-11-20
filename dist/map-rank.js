// Ranks every finding by what breaks first, and turns code findings into map findings.
export function tierOf(f) {
    if (f.risk !== "quantum-vulnerable")
        return 1;
    if ((f.primitive === "key-agreement" || f.primitive === "public-key-encryption") && f.internetFacing)
        return 2;
    if (f.primitive === "signature" && f.longLived)
        return 3;
    return 4;
}
const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
export function rank(findings) {
    return findings
        .map((f) => ({ ...f, tier: tierOf(f) }))
        .sort((a, b) => a.tier - b.tier || SEV[a.severity] - SEV[b.severity] || a.area.localeCompare(b.area) || a.target.localeCompare(b.target));
}
export function fromCodeFinding(f) {
    return {
        area: "code",
        target: `${f.file}:${f.line}`,
        ruleId: f.ruleId,
        title: f.title,
        algorithm: f.algorithm,
        primitive: f.primitive,
        risk: f.risk,
        severity: f.severity,
        fix: f.fix,
        internetFacing: false,
        keySize: f.keySize,
    };
}
/** Back to the code scanner's shape, so the CycloneDX inventory builder can be reused. */
export function toFinding(f) {
    return {
        kind: f.risk === "secret" ? "secret" : f.risk === "exposed" || f.primitive === "setting" ? "config" : "crypto",
        ruleId: f.ruleId,
        title: f.title,
        algorithm: f.algorithm,
        primitive: f.primitive,
        risk: f.risk,
        severity: f.severity,
        file: f.target,
        line: 0,
        snippet: "",
        fix: f.fix,
        keySize: f.keySize,
    };
}
