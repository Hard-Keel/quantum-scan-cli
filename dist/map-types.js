// Types for the encryption map: one picture of encryption across code, websites and machines.
export const TIER_TITLES = {
    1: "Broken now",
    2: "Recorded now, read later",
    3: "Long-lived signatures",
    4: "Everything else",
};
export const TIER_NOTES = {
    1: "Weak today, without any quantum computer. Fix these first.",
    2: "Internet-facing key exchange with no quantum-safe option. Traffic recorded today can be decrypted once quantum computers arrive.",
    3: "Signatures that must stay trusted for years. NIST deprecates these methods after 2030.",
    4: "Uses RSA or elliptic-curve encryption. NIST disallows these after 2035.",
};
export function emptyResult(area) {
    return { area, findings: [], strengths: [], errors: [], checked: [], skipped: [] };
}
