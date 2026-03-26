export function toUEgoc(egoc: number | string): bigint {
  return BigInt(Math.round(Number(egoc) * 1_000_000));
}

export function fromUEgoc(uEgoc: bigint | string): string {
  const n = BigInt(uEgoc);
  const whole = n / 1_000_000n;
  const frac  = n % 1_000_000n;
  return `${whole}.${frac.toString().padStart(6, "0")} EGOC`;
}

export function normalizeAddress(addr: string): string {
  return "0x" + addr.replace(/^0x/, "").toLowerCase().padStart(40, "0");
}

export function isValidAddress(addr: string): boolean {
  return /^(0x)?[0-9a-fA-F]{40}$/.test(addr);
}
