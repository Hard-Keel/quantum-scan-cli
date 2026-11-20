// Hard Keel quantum readiness score, method version 1.
// Turns a full-repository scan into a 0-100 score and a grade from A+ to F.
// The method is public: docs/readiness-score.md and hardkeel.com/learn/quantum-readiness-score/.
// Change a weight, cap or threshold only by bumping METHOD_VERSION and the docs together.
export const METHOD_VERSION = "1";
const GRADES = ["A+", "A", "B", "C", "D", "F"];
/** Points taken off for one kind of problem (one algorithm or setting), before the use multiplier. */
const BASE = {
    secret: () => 25,
    weak: (s) => (s === "critical" || s === "high" ? 10 : 6),
    exposed: (s) => ({ critical: 12, high: 8, medium: 5, low: 2 })[s],
    "quantum-key-exchange": () => 5,
    "quantum-signature": () => 2,
};
/** Most a category can take off in total, so one area can't hide every other. */
const CAP = {
    secret: 50,
    weak: 30,
    exposed: 30,
    "quantum-key-exchange": 20,
    "quantum-signature": 8,
};
/** Best grade a repository can get while it has any problem in this category. */
const GRADE_CAP = {
    secret: "D",
    weak: "C",
    exposed: "C",
    "quantum-key-exchange": "B",
    "quantum-signature": "A",
};
const THRESHOLDS = [
    [90, "A"],
    [75, "B"],
    [60, "C"],
    [40, "D"],
    [0, "F"],
];
export function categoryOf(f) {
    if (f.risk === "secret")
        return "secret";
    if (f.risk === "weak-now")
        return "weak";
    if (f.risk === "exposed")
        return "exposed";
    return f.primitive === "signature" ? "quantum-signature" : "quantum-key-exchange";
}
/** 1 use counts once; more uses count more, up to double (16 or more uses). */
export function useMultiplier(uses) {
    return Math.min(2, 1 + 0.25 * Math.log2(Math.max(1, uses)));
}
function worse(a, b) {
    return GRADES[Math.max(GRADES.indexOf(a), GRADES.indexOf(b))];
}
export function readinessScore(findings, pqc = []) {
    const pqcKex = pqc.some((p) => p.use === "key-establishment");
    const pqcSig = pqc.some((p) => p.use === "signature");
    // One deduction per category and algorithm (or setting), however many files use it.
    const groups = new Map();
    for (const f of findings) {
        const k = `${categoryOf(f)}|${f.algorithm}`;
        groups.set(k, [...(groups.get(k) ?? []), f]);
    }
    const deductions = [];
    for (const g of groups.values()) {
        const category = categoryOf(g[0]);
        // A group is as serious as its most serious use.
        const sev = g.map((f) => f.severity).sort((a, b) => sevRank(a) - sevRank(b))[0];
        let points = BASE[category](sev) * useMultiplier(g.length);
        // Credit for migration under way: half off where post-quantum methods are already in use.
        if ((category === "quantum-key-exchange" && pqcKex) || (category === "quantum-signature" && pqcSig))
            points /= 2;
        deductions.push({ category, algorithm: g[0].algorithm, uses: g.length, points: round1(points) });
    }
    const counts = { secret: 0, weak: 0, exposed: 0, "quantum-key-exchange": 0, "quantum-signature": 0 };
    const byCategory = { ...counts };
    for (const d of deductions) {
        counts[d.category] += d.uses;
        byCategory[d.category] += d.points;
    }
    let total = 0;
    for (const c of Object.keys(CAP))
        total += Math.min(CAP[c], byCategory[c]);
    const score = Math.max(0, Math.round(100 - total));
    let grade = THRESHOLDS.find(([min]) => score >= min)[1];
    for (const c of Object.keys(GRADE_CAP))
        if (counts[c])
            grade = worse(grade, GRADE_CAP[c]);
    // A+ is for repositories with nothing left to fix that already use post-quantum methods.
    if (grade === "A" && !findings.length && (pqcKex || pqcSig))
        grade = "A+";
    const due = counts.secret || counts.weak || counts.exposed ? "now" : counts["quantum-key-exchange"] ? "2030" : counts["quantum-signature"] ? "2035" : null;
    return {
        method: METHOD_VERSION,
        score,
        grade,
        counts,
        pqc: { keyExchange: pqcKex, signatures: pqcSig, algorithms: [...new Set(pqc.map((p) => p.algorithm))] },
        due,
        deductions: deductions.sort((a, b) => b.points - a.points),
    };
}
function sevRank(s) {
    return { critical: 0, high: 1, medium: 2, low: 3 }[s];
}
function round1(n) {
    return Math.round(n * 10) / 10;
}
/** One plain sentence about the grade, for reports and the command line. */
export function gradeSentence(s) {
    const lead = `Quantum readiness: ${s.grade} (${s.score}/100, Hard Keel method v${s.method}).`;
    if (s.grade === "A+")
        return `${lead} Nothing to fix, and post-quantum encryption is already in use.`;
    if (s.due === null)
        return `${lead} Nothing to fix.`;
    if (s.counts.secret)
        return `${lead} A leaked key or password holds the grade at D or lower until it is revoked and removed.`;
    if (s.due === "now")
        return `${lead} Weak encryption or exposed settings hold the grade at C or lower until they are fixed.`;
    if (s.due === "2030")
        return `${lead} Key exchange or RSA keys that quantum computers will break hold the grade at B until they move to post-quantum methods.`;
    return `${lead} Only signatures are left to move to post-quantum methods, before 2035.`;
}
