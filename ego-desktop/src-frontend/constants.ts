/** Current EGOC market price in USD. Update when the oracle goes live. */
export const EGOC_PRICE_USD = 2.45;
export const EGOC_SUPPLY    = 1_000_000_000;

/** Human-readable amount for a transaction: EGUSD transfers/releases carry their
 *  value in the memo (credits, $0.01 units) with amount=0 EGOC; mints burn EGOC
 *  for EGUSD. Everything else is plain EGOC. */
export function txDisplayAmount(
  tx: { amount: number; memo?: string | null },
  egocDigits: number = 6,
): string {
  const memo = tx.memo || '';
  const creditsFrom = (prefix: string) => {
    const c = parseInt(memo.slice(prefix.length).split(':')[0] || '0', 10);
    return c > 0 ? `${(c / 100).toFixed(2)} EGUSD` : null;
  };
  if (memo.startsWith('credits_pay:')) {
    const v = creditsFrom('credits_pay:');
    if (v) return v;
  }
  if (memo.startsWith('credits_release:')) {
    const v = creditsFrom('credits_release:');
    if (v) return v;
  }
  if (memo.startsWith('credits_mint:')) {
    const price = parseInt(memo.slice('credits_mint:'.length), 10) || 0;
    const credits = Math.floor((tx.amount * price) / 1e10);
    if (credits > 0) {
      return `${(tx.amount / 1_000_000).toFixed(2)} EGOC → ${(credits / 100).toFixed(2)} EGUSD`;
    }
  }
  return `${(tx.amount / 1_000_000).toFixed(egocDigits)} EGOC`;
}
