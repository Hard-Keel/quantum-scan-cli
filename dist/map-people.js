// People and process: a short, optional checklist about the parts of security no scan can see,
// such as phishing, admin habits, separation, backups and what happens on a bad day.
// Answers stay on this machine. They are scored on their own, next to the technical findings,
// and are never part of the anonymized summary.
export const QUESTIONS = [
    { id: "phishing-training", group: "People", text: "Do staff get phishing and social-engineering training at least once a year?", severity: "medium", fix: "Run short phishing training each year, with a practice email or two. Most break-ins start with someone being tricked." },
    { id: "verify-requests", group: "People", text: "Are requests to change bank details, send money or reset a password confirmed by calling back on a known number?", severity: "high", fix: "Require a call back on a number you already have before changing payment details, paying a new account or resetting a password." },
    { id: "report-path", group: "People", text: "Do staff know who to tell, right away, if they clicked something odd?", severity: "medium", fix: "Name one person or address for 'I think I clicked something', and thank people for using it." },
    { id: "mfa", group: "Accounts", text: "Does every email and admin account use multi-factor sign-in?", severity: "high", fix: "Turn on multi-factor sign-in for every email and admin account, ideally with an app or security key, not text messages." },
    { id: "separate-admin", group: "Accounts", text: "Do admins use a separate account for admin work, not their everyday account?", severity: "medium", fix: "Give admins a second account used only for admin work, so a phished everyday account can't change settings." },
    { id: "offboarding", group: "Accounts", text: "Are accounts and access removed the same day someone leaves?", severity: "medium", fix: "Keep a leaving checklist: accounts, shared passwords, door codes, remote tools and devices, done on the last day." },
    { id: "vendor-access", group: "Accounts", text: "Is outside vendors' remote access limited, logged and turned off when not in use?", severity: "high", fix: "Give vendors their own accounts, turn their access on only when needed, and keep a log." },
    { id: "default-passwords", group: "Equipment", text: "Have default passwords been changed on routers, switches, printers, cameras and other equipment?", severity: "high", fix: "Change every default password on network equipment, printers and cameras, and keep the new ones in a password manager." },
    { id: "firmware-updates", group: "Equipment", text: "Do routers, printers, cameras and other equipment get firmware updates at least every quarter?", severity: "medium", fix: "Check equipment firmware every quarter, and replace devices the maker no longer updates." },
    { id: "printer-jobs", group: "Equipment", text: "Do your printers avoid keeping copies of past jobs, or wipe them automatically?", severity: "medium", fix: "Turn off stored jobs on printers, or set them to wipe automatically, and wipe the drive before a printer leaves." },
    { id: "guest-network", group: "Separation", text: "Are guest Wi-Fi, cameras and smart devices on a separate network from staff computers?", severity: "high", fix: "Put guests, cameras and smart devices on their own network, so a hacked camera can't reach staff computers." },
    { id: "payments-separate", group: "Separation", text: "Are card payment systems on their own network, apart from everything else?", severity: "high", fix: "Keep card terminals and payment systems on their own network segment, reachable only from what needs them." },
    { id: "containment", group: "Separation", text: "If one computer were taken over, could it be kept from reaching everything else (staff aren't local admins, file shares are limited)?", severity: "high", fix: "Remove local admin rights from everyday accounts and limit each file share to the people who need it, so one bad click stays small." },
    { id: "sandbox", group: "Separation", text: "Are unknown attachments and new software opened in a sandbox or a separate machine first?", severity: "medium", fix: "Open unknown attachments and try new software in a sandbox (like Windows Sandbox) or a spare machine first." },
    { id: "cloud-keys", group: "Data", text: "Is sensitive data in cloud storage, databases and backups encrypted with keys you hold, so the provider can't read it?", severity: "medium", fix: "Encrypt sensitive data before it goes to the cloud, or keep the keys yourself in an external key store, so no third party holds data it can decrypt." },
    { id: "backups", group: "Data", text: "Are backups kept offline or locked against changes, and was a restore tested in the last six months?", severity: "high", fix: "Keep at least one backup offline or locked against changes, and test a restore twice a year." },
    { id: "incident-plan", group: "Bad day", text: "Is there a written plan for a breach or ransomware attack, including who to call?", severity: "high", fix: "Write a one-page plan: who decides, who to call (IT, insurer, lawyer, bank), how to cut off the network, and where backups are." },
    { id: "logs", group: "Bad day", text: "Are sign-in and admin logs kept long enough to look back at least 90 days?", severity: "low", fix: "Keep sign-in and admin logs for at least 90 days, so you can tell what happened after the fact." },
];
const WEIGHT = { critical: 4, high: 3, medium: 2, low: 1 };
export function parseAnswers(v) {
    const out = {};
    if (!v || typeof v !== "object" || Array.isArray(v))
        return out;
    const ids = new Set(QUESTIONS.map((q) => q.id));
    for (const [k, a] of Object.entries(v))
        if (ids.has(k) && (a === "yes" || a === "no" || a === "unsure"))
            out[k] = a;
    return out;
}
export function scorePeople(answers) {
    const asked = QUESTIONS.filter((q) => answers[q.id]);
    if (!asked.length)
        return null;
    let got = 0;
    let max = 0;
    const gaps = [];
    for (const q of asked) {
        const a = answers[q.id];
        max += WEIGHT[q.severity];
        if (a === "yes")
            got += WEIGHT[q.severity];
        else
            gaps.push({ id: q.id, group: q.group, question: q.text, answer: a, severity: q.severity, fix: q.fix });
    }
    // Most important first; at the same weight a "no" comes before a "not sure", then checklist order.
    gaps.sort((x, y) => WEIGHT[y.severity] - WEIGHT[x.severity] || Number(x.answer !== "no") - Number(y.answer !== "no"));
    return { answered: asked.length, total: QUESTIONS.length, inPlace: asked.length - gaps.length, score: Math.round((100 * got) / max), gaps };
}
export function readAnswer(raw) {
    const t = raw.trim().toLowerCase();
    if (/^y(es)?$/.test(t))
        return "yes";
    if (/^no?$/.test(t))
        return "no";
    if (t === "?" || /^(u|unsure|not sure|dk|don'?t know)$/.test(t))
        return "unsure";
    return null; // Enter skips the question
}
export async function askPeople(ask, write) {
    write(`\nPeople and process: ${QUESTIONS.length} short questions about what no scan can see. Answer y, n or ? (not sure). Press Enter to skip one. Answers stay on this machine.\n`);
    const out = {};
    let group = "";
    for (const q of QUESTIONS) {
        if (q.group !== group)
            write(`\n${(group = q.group)}\n`);
        const a = readAnswer(await ask(`  ${q.text} (y/n/?) `));
        if (a)
            out[q.id] = a;
    }
    return out;
}
