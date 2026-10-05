import { blake2s } from 'blakejs';

export const POOL_ADDRESS = 'egot1shieldedpool000000000000000000000000000';
export const TX_SHIELD = 'shield';
export const TX_UNSHIELD = 'unshield';
export const DENOMINATIONS_UEGOC = [1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000];
export const MAX_SPENDS = 16;
export const WITHDRAWAL_GRACE_SECS = 300;
export const WITHDRAWAL_DEAD_SECS = 1_800;
export const SYNC_LAG_TOLERANCE = 3;
export const RECOVERY_GAP = 20;
export const PROOF_SYSTEM = 'winterfell-stark/rescue-goldilocks, no trusted setup';

const NOTE_LABEL_PREFIX = 'ego/shielded-note/v1/';
const NOTES_KEY_LABEL = 'ego/shielded-notes/v1:';
const NOTES_EXPORT_LABEL = 'ego/shielded-notes-export/v1:';

export type NoteDomain = 'ext' | 'desktop';
export const NOTE_DOMAINS: NoteDomain[] = ['ext', 'desktop'];
const UNSHIELD_HASH_PREFIX = 'ego/unshield/v1:';

const enc = new TextEncoder();

export type NoteStatus = 'pending' | 'ready' | 'spending' | 'settling' | 'spent' | 'cancelled' | 'returned';

export interface NoteSecrets {
  owner_secret: string;
  rho: string;
}

export interface StoredNote {
  index: number;
  domain?: NoteDomain;
  secret?: NoteSecrets;
  source?: 'extension' | 'desktop';
  value_uegoc: number;
  commitment: string;
  nullifier: string;
  leaf: string;
  leaf_index: number | null;
  created_at: number;
  deposit_tx: string;
  spent_tx: string | null;
  spent_at: number | null;
  cancelled_at: number | null;
}

export interface NoteView {
  commitment: string;
  value_uegoc: number;
  leaf_index: number | null;
  status: NoteStatus;
  deposit_tx: string;
  spent_tx: string | null;
  created_at: number;
  source: 'extension' | 'desktop';
}

export interface DesktopStoredNote {
  note: { inner: { value_uegoc: number; owner_secret: number[]; rho: number[] } };
  commitment: string;
  created_at: number;
  deposit_tx: string;
  spent_tx?: string | null;
  spent_at?: number | null;
  cancelled_at?: number | null;
}

export interface TxCheck {
  block_height: number | null;
  finalized: boolean;
  in_mempool: boolean;
}

export interface ChainView {
  now: number;
  behind: boolean;
  nullifierSpent: (nullifier: string) => boolean;
  tx: (hash: string) => TxCheck | undefined;
}

export interface UnshieldSpend {
  root: string;
  nullifier: string;
  amount_uegoc: number;
  fee_uegoc: number;
  proof: string;
}

export function toHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error('not hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export function denominate(amountUegoc: number): { notes: number[]; remainder: number } {
  const notes: number[] = [];
  let left = Math.max(0, Math.floor(amountUegoc));
  for (const d of [...DENOMINATIONS_UEGOC].reverse()) {
    while (left >= d) { notes.push(d); left -= d; }
  }
  return { notes, remainder: left };
}

export function shieldMemo(commitmentHex: string): string {
  return `shield:${commitmentHex}`;
}

export function recipientDigest(address: string): string {
  return toHex(blake2s(enc.encode(address), undefined, 32));
}

export function noteSecrets(seed: Uint8Array, index: number, domain: NoteDomain = 'ext'): NoteSecrets {
  if (!Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new Error('note index out of range');
  const idx = u32le(index);
  const part = (role: string) =>
    toHex(blake2s(concat(enc.encode(`${NOTE_LABEL_PREFIX}${domain}/${role}:`), seed, idx), undefined, 32));
  return { owner_secret: part('secret'), rho: part('rho') };
}

export function secretsOf(seed: Uint8Array, n: StoredNote): NoteSecrets {
  return n.secret ?? noteSecrets(seed, n.index, n.domain ?? 'ext');
}

export function notesExportMessage(address: string, timestamp: number): string {
  return `${NOTES_EXPORT_LABEL}${address}:${timestamp}`;
}

export function notesKeyBytes(seed: Uint8Array): Uint8Array {
  return blake2s(concat(enc.encode(NOTES_KEY_LABEL), seed), undefined, 32);
}

export function feeShares(totalFee: number, spends: number): number[] {
  const base = Math.floor(totalFee / spends);
  const remainder = totalFee % spends;
  return Array.from({ length: spends }, (_, i) => base + (i < remainder ? 1 : 0));
}

export function unshieldBodyJson(
  spends: UnshieldSpend[],
  recipient: string,
  amountUegoc: number,
  feeUegoc: number,
): string {
  return JSON.stringify({
    spends: spends.map(s => ({
      root: s.root,
      nullifier: s.nullifier,
      amount_uegoc: s.amount_uegoc,
      fee_uegoc: s.fee_uegoc,
      proof: s.proof,
    })),
    recipient,
    amount_uegoc: amountUegoc,
    fee_uegoc: feeUegoc,
  });
}

export function unshieldHash(bodyJson: string): string {
  return '0x' + toHex(blake2s(enc.encode(UNSHIELD_HASH_PREFIX + bodyJson), undefined, 32));
}

export function pickNotesFor(
  amountUegoc: number,
  ready: { commitment: string; value_uegoc: number }[],
  limit = MAX_SPENDS,
): string[] | null {
  const sorted = [...ready].sort((a, b) => b.value_uegoc - a.value_uegoc);
  const chosen: string[] = [];
  let left = amountUegoc;
  for (const n of sorted) {
    if (n.value_uegoc <= left) {
      chosen.push(n.commitment);
      left -= n.value_uegoc;
      if (left === 0) break;
    }
  }
  return left === 0 && chosen.length > 0 && chosen.length <= limit ? chosen : null;
}

export function withdrawalAbandoned(n: StoredNote, view: ChainView): boolean {
  if (view.behind || !n.spent_tx) return false;
  const waited = n.spent_at == null ? Number.MAX_SAFE_INTEGER : view.now - n.spent_at;
  if (waited >= WITHDRAWAL_DEAD_SECS) return true;
  if (waited < WITHDRAWAL_GRACE_SECS) return false;
  return !(view.tx(n.spent_tx)?.in_mempool ?? false);
}

export function depositAbandoned(n: StoredNote, view: ChainView): boolean {
  if (view.behind) return false;
  if (view.tx(n.deposit_tx)?.block_height != null) return false;
  const waited = view.now - n.created_at;
  if (waited >= WITHDRAWAL_DEAD_SECS) return true;
  if (waited < WITHDRAWAL_GRACE_SECS) return false;
  return !(view.tx(n.deposit_tx)?.in_mempool ?? false);
}

export function noteStatus(n: StoredNote, view: ChainView): NoteStatus {
  const nullifierSpent = view.nullifierSpent(n.nullifier);
  if (n.spent_tx) {
    const t = view.tx(n.spent_tx);
    if (t?.finalized) return 'spent';
    if (t?.block_height != null) return 'settling';
    if (nullifierSpent) {
      const waited = n.spent_at == null ? Number.MAX_SAFE_INTEGER : view.now - n.spent_at;
      return !view.behind && !(t?.in_mempool ?? false) && waited >= WITHDRAWAL_GRACE_SECS ? 'spent' : 'settling';
    }
    if (withdrawalAbandoned(n, view)) return 'ready';
    return 'spending';
  }
  if (nullifierSpent) return 'spent';
  if (n.leaf_index != null) return 'ready';
  if (n.cancelled_at != null) return 'cancelled';
  if (depositAbandoned(n, view)) return 'returned';
  return 'pending';
}
