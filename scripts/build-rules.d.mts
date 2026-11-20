export interface RuleFile {
  id: string;
  extensions: string[];
  examples: { match: string[]; noMatch: string[] };
  [k: string]: unknown;
}
export function checkRule(r: object, file: string, seen: Set<string>): string[];
export function loadRules(): { rules: RuleFile[]; problems: string[] };
export function render(rules: RuleFile[]): string;
