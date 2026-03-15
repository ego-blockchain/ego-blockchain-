/** Convert EGOC (as decimal string or number) to uEGOC bigint */
export function toUEgoc(egoc: number | string): bigint {
  return BigInt(Math.round(Number(egoc) * 1_000_000));
}

/** Convert uEGOC bigint to a human-readable EGOC string */
export function fromUEgoc(uEgoc: bigint | string): string {
  const n = BigInt(uEgoc);
  const whole = n / 1_000_000n;
  const frac  = n % 1_000_000n;
  return `${whole}.${frac.toString().padStart(6, "0")} EGOC`;
}

/** Normalise an address to lowercase hex with 0x prefix */
export function normalizeAddress(addr: string): string {
  return "0x" + addr.replace(/^0x/, "").toLowerCase().padStart(40, "0");
}

/** True if `addr` looks like a valid 20-byte hex address */
export function isValidAddress(addr: string): boolean {
  return /^(0x)?[0-9a-fA-F]{40}$/.test(addr);
}
