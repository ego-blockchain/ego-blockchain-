export const PASSWORD_RULES: { label: string; ok: (p: string) => boolean }[] = [
  { label: 'At least 10 characters', ok: p => [...p.trim()].length >= 10 },
  { label: 'A capital letter', ok: p => /\p{Lu}/u.test(p) },
  { label: 'A small letter', ok: p => /\p{Ll}/u.test(p) },
  { label: 'A number', ok: p => /[0-9]/.test(p) },
];

export function passwordProblem(pw: string): string | null {
  const missing = PASSWORD_RULES.find(r => !r.ok(pw));
  return missing ? `The password needs: ${missing.label.toLowerCase()}.` : null;
}
